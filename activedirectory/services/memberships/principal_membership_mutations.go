package memberships

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (c *Service) AddPrincipalGroupMembership(
	ctx context.Context,
	request PrincipalGroupMembershipRequest,
) (PrincipalGroupMembershipMutationResult, error) {
	return internalServiceChangePrincipalMembership(c, ctx, request, false)
}

func (c *Service) RemovePrincipalGroupMembership(
	ctx context.Context,
	request PrincipalGroupMembershipRequest,
) (PrincipalGroupMembershipMutationResult, error) {
	return internalServiceChangePrincipalMembership(c, ctx, request, true)
}

func internalServiceChangePrincipalMembership(c *Service,
	ctx context.Context,
	request admodel.PrincipalGroupMembershipRequest,
	remove bool,
) (result admodel.PrincipalGroupMembershipMutationResult, err error) {
	if len(request.Groups) == 0 || len(request.Groups) > 1000 {
		return result, admodel.ErrInvalidMembership
	}
	if err := admodel.InternalValidateIdentityOperation(
		request.Principal,
		admodel.InternalMembershipResolveOptions(request.Principal, request.Partition, nil),
	); err != nil {
		return result, err
	}
	for _, target := range request.Groups {
		if err := admodel.InternalValidateGroupMembers(
			admodel.AddGroupMembersRequest{
				Identity: target.Identity,
				Members:  []admodel.Identity{request.Principal},
				Mode:     request.Mode,
				Options:  target.Options,
			},
		); err != nil {
			return result, err
		}
		result.Outcomes = append(
			result.Outcomes,
			admodel.PrincipalMembershipOutcome{Group: target.Identity},
		)
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	result.Principal, err = c.engine().
		ResolveIdentity(bounded, request.Principal, admodel.InternalMembershipResolveOptions(request.Principal, request.Partition, nil))
	if err != nil {
		return result, err
	}
	principal, err := admodel.InternalDecodeMembershipPrincipal(
		*result.Principal.Object,
		adengine.InternalClientConfig(c.engine()).Endpoint,
	)
	if err != nil {
		return result, err
	}
	member := admodel.InternalObjectGUIDIdentity(principal.GUID)
	var failures []error
	for i, target := range request.Groups {
		if err := context.Cause(bounded); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		var outcome admodel.GroupMembershipMutationResult
		var writeErr error
		if remove {
			outcome, writeErr = c.RemoveGroupMembers(
				bounded,
				admodel.RemoveGroupMembersRequest{
					Identity: target.Identity,
					Members:  []admodel.Identity{member},
					Mode:     request.Mode,
					Options:  target.Options,
				},
			)
		} else {
			outcome, writeErr = c.AddGroupMembers(
				bounded,
				admodel.AddGroupMembersRequest{
					Identity: target.Identity,
					Members:  []admodel.Identity{member},
					Mode:     request.Mode,
					Options:  target.Options,
				},
			)
		}
		result.Outcomes[i].Result, result.Outcomes[i].Error = outcome, writeErr
		result.Processed++
		if writeErr != nil {
			failures = append(failures, writeErr)
		}
		if outcome.Mutation.State == admodel.ObjectWriteUncertain {
			break
		}
	}
	err = errors.Join(failures...)
	result.Complete = err == nil && result.Processed == len(request.Groups)
	return result, err
}
