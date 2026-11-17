package memberships

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (c *Service) AddGroupMembers(
	ctx context.Context,
	request AddGroupMembersRequest,
) (GroupMembershipMutationResult, error) {
	return internalServiceChangeGroupMembers(c, ctx, request, false)
}

func (c *Service) RemoveGroupMembers(
	ctx context.Context,
	request RemoveGroupMembersRequest,
) (GroupMembershipMutationResult, error) {
	return internalServiceChangeGroupMembers(c,
		ctx,
		admodel.AddGroupMembersRequest{
			Identity:        request.Identity,
			Members:         request.Members,
			Mode:            request.Mode,
			MemberPartition: request.MemberPartition,
			Options:         request.Options,
		},
		true,
	)
}

func internalServiceChangeGroupMembers(c *Service,
	ctx context.Context,
	request admodel.AddGroupMembersRequest,
	remove bool,
) (result admodel.GroupMembershipMutationResult, err error) {
	if err = admodel.InternalValidateGroupMembers(request); err != nil {
		return result, err
	}
	for _, identity := range request.Members {
		result.Members = append(result.Members, admodel.GroupMemberInput{Identity: identity})
	}
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalGroupIdentityOptions(request.Identity, request.Options.Partition, nil),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalGroupClass(*observed.Object); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
				*mutation.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			if request.Mode == admodel.GroupMembershipPermissive {
				if !slices.Contains(root.SupportedControls, admodel.InternalGroupPermissiveModify) {
					return admodel.ErrObjectControlUnsupported
				}
				controls = append(
					controls,
					admodel.InternalLdapWriteControl{
						InternalOid:      admodel.InternalGroupPermissiveModify,
						InternalCritical: true,
					},
				)
			}
			if request.TimeToLive != nil &&
				!slices.Contains(root.SupportedControls, admodel.InternalGroupLinkTTL) {
				return admodel.ErrGroupMembershipTTLUnsupported
			}
			values := make([][]byte, 0, len(request.Members))
			bytes := 0
			for index, member := range request.Members {
				if err := context.Cause(ctx); err != nil {
					return err
				}
				var reference string
				switch admodel.InternalIdentityForm(member) {
				case admodel.IdentityFormDN:
					reference = admodel.InternalIdentityValue(member)
				case admodel.IdentityFormGUID:
					reference = "<GUID=" + hex.EncodeToString(
						admodel.InternalIdentityBinary(member),
					) + ">"
				case admodel.IdentityFormSID:
					reference = "<SID=" + hex.EncodeToString(
						admodel.InternalIdentityBinary(member),
					) + ">"
				case admodel.IdentityFormAccountName:
					resolved, resolveErr := admodel.InternalResolveIdentitySession(
						ctx,
						session,
						adengine.InternalClientConfig(c.engine()),
						root,
						member,
						admodel.ResolveIdentityOptions{
							Target:     admodel.IdentityTargetAccount,
							Partition:  request.MemberPartition,
							Properties: []string{"objectGUID"},
						},
					)
					result.Members[index].Resolution = &resolved
					if resolveErr != nil {
						return fmt.Errorf("member %d: %w", index, resolveErr)
					}
					value, valueErr := resolved.Object.Values("objectGUID").Single()
					if valueErr != nil {
						return valueErr
					}
					guid, valueErr := value.GUID()
					if valueErr != nil {
						return valueErr
					}
					reference = admodel.InternalObjectGUIDTarget(guid)
				}
				if request.TimeToLive != nil {
					reference = "<TTL=" + strconv.FormatInt(
						int64(*request.TimeToLive/time.Second),
						10,
					) + "," + reference + ">"
				}
				bytes += len(reference)
				if bytes > admodel.InternalMaxGroupWriteBytes {
					return admodel.ErrGroupMembershipLimit
				}
				result.Members[index].Reference = reference
				values = append(values, []byte(reference))
			}
			operation := uint32(0)
			if remove {
				operation = 1
			}
			write := admodel.InternalLdapWriteRequest{
				InternalOperation: admodel.InternalLdapWriteModify,
				InternalDn:        admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
				InternalControls:  controls,
				InternalModifications: []admodel.InternalLdapAttributeModification{
					{
						InternalOperation: operation,
						InternalAttribute: "member",
						InternalValues:    values,
					},
				},
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				write,
				false,
				mutation,
			); err != nil {
				return err
			}
			return admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				admodel.InternalGroupProperties(request.Options.Properties),
				false,
			)
		},
	)
	return result, err
}
