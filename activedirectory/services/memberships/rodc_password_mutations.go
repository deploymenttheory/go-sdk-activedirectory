package memberships

import (
	"context"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// AddRODCPasswordReplicationPolicy adds principals to an RODC's allowed or denied password-replication
// list. Request selects the controller, list, principals, write mode, and mutation options.
//
// Related cmdlet: Add-ADDomainControllerPasswordReplicationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-addomaincontrollerpasswordreplicationpolicy?view=windowsserver2025-ps
func (c *Service) AddRODCPasswordReplicationPolicy(
	ctx context.Context,
	request RODCPasswordReplicationChange,
) (RODCPasswordReplicationMutationResult, error) {
	return internalServiceChangeRODCPasswordPolicy(c, ctx, request, false)
}

// RemoveRODCPasswordReplicationPolicy removes principals from an RODC's allowed or denied
// password-replication list without deleting their accounts. The result preserves principal
// observations and the linked-value write outcome.
//
// Related cmdlet: Remove-ADDomainControllerPasswordReplicationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-addomaincontrollerpasswordreplicationpolicy?view=windowsserver2025-ps
func (c *Service) RemoveRODCPasswordReplicationPolicy(
	ctx context.Context,
	request RODCPasswordReplicationChange,
) (RODCPasswordReplicationMutationResult, error) {
	return internalServiceChangeRODCPasswordPolicy(c, ctx, request, true)
}

// internalServiceChangeRODCPasswordPolicy resolves the RODC and principals before modifying its
// allowed or denied list.
func internalServiceChangeRODCPasswordPolicy(c *Service,
	ctx context.Context,
	request admodel.RODCPasswordReplicationChange,
	remove bool,
) (result admodel.RODCPasswordReplicationMutationResult, err error) {
	attribute, err := admodel.InternalRODCPasswordReplicationListAttribute(request.List)
	if err != nil {
		return result, err
	}
	if err = admodel.InternalValidateGroupMembers(
		admodel.AddGroupMembersRequest{
			Identity: request.Controller,
			Members:  request.Principals,
			Mode:     request.Mode,
			Options:  request.Options,
		},
	); err != nil {
		return result, err
	}
	for _, identity := range request.Principals {
		result.Principals = append(result.Principals, admodel.GroupMemberInput{Identity: identity})
	}
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Controller,
		request.Options,
		admodel.InternalMembershipResolveOptions(
			request.Controller,
			request.Options.Partition,
			admodel.InternalRodcPasswordProperties(nil),
		),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := adengine.InternalRodcPasswordServer(
				ctx,
				c.engine(),
				session,
				root,
				observed.Partition,
				true,
			); err != nil {
				return err
			}
			if err := admodel.InternalValidateRODCPasswordTarget(*observed.Object); err != nil {
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
			values := make([][]byte, 0, len(request.Principals))
			for i, identity := range request.Principals {
				resolved, resolveErr := admodel.InternalResolveIdentitySession(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					identity,
					admodel.InternalMembershipResolveOptions(
						identity,
						observed.Partition,
						[]string{"groupType"},
					),
				)
				result.Principals[i].Resolution = &resolved
				if resolveErr != nil {
					return resolveErr
				}
				if err := admodel.InternalValidateRODCPasswordPrincipal(
					*resolved.Object,
					true,
				); err != nil {
					return err
				}
				principal, resolveErr := admodel.InternalDecodeMembershipPrincipal(
					*resolved.Object,
					adengine.InternalClientConfig(c.engine()).Endpoint,
				)
				if resolveErr != nil {
					return resolveErr
				}
				reference := admodel.InternalObjectGUIDTarget(principal.GUID)
				result.Principals[i].Reference = reference
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
						InternalAttribute: attribute,
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
			// Identity readback is useful, but does not establish linked-value visibility
			// or the resultant policy. Mutation.Verified deliberately remains false.
			return admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				admodel.InternalRodcPasswordProperties(request.Options.Properties),
				false,
			)
		},
	)
	return result, admodel.InternalRodcPasswordError(err)
}
