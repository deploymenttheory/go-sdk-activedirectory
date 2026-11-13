package activedirectory

import (
	"context"
	"errors"
)

type PrincipalMembershipTarget struct {
	Identity Identity
	Options  ObjectMutationOptions
}
type PrincipalGroupMembershipRequest struct {
	Principal Identity
	Partition string
	Groups    []PrincipalMembershipTarget
	Mode      GroupMembershipMode
}
type PrincipalMembershipOutcome struct {
	Group  Identity
	Result GroupMembershipMutationResult
	Error  error
}

// Each group is an independent Modify. Known failures retain per-target results;
// uncertainty or cancellation stops all remaining targets without replay.
type PrincipalGroupMembershipMutationResult struct {
	Principal IdentityResult
	Outcomes  []PrincipalMembershipOutcome
	Processed int
	Complete  bool
}

func (c *Client) AddPrincipalGroupMembership(ctx context.Context, request PrincipalGroupMembershipRequest) (PrincipalGroupMembershipMutationResult, error) {
	return c.changePrincipalMembership(ctx, request, false)
}
func (c *Client) RemovePrincipalGroupMembership(ctx context.Context, request PrincipalGroupMembershipRequest) (PrincipalGroupMembershipMutationResult, error) {
	return c.changePrincipalMembership(ctx, request, true)
}
func (c *Client) changePrincipalMembership(ctx context.Context, request PrincipalGroupMembershipRequest, remove bool) (result PrincipalGroupMembershipMutationResult, err error) {
	if len(request.Groups) == 0 || len(request.Groups) > 1000 {
		return result, ErrInvalidMembership
	}
	if err := validateIdentityOperation(request.Principal, membershipResolveOptions(request.Principal, request.Partition, nil)); err != nil {
		return result, err
	}
	for _, target := range request.Groups {
		if err := validateGroupMembers(AddGroupMembersRequest{Identity: target.Identity, Members: []Identity{request.Principal}, Mode: request.Mode, Options: target.Options}); err != nil {
			return result, err
		}
		result.Outcomes = append(result.Outcomes, PrincipalMembershipOutcome{Group: target.Identity})
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	result.Principal, err = c.ResolveIdentity(bounded, request.Principal, membershipResolveOptions(request.Principal, request.Partition, nil))
	if err != nil {
		return result, err
	}
	principal, err := decodeMembershipPrincipal(*result.Principal.Object, c.config.Endpoint)
	if err != nil {
		return result, err
	}
	member := objectGUIDIdentity(principal.GUID)
	var failures []error
	for i, target := range request.Groups {
		if err := context.Cause(bounded); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		var outcome GroupMembershipMutationResult
		var writeErr error
		if remove {
			outcome, writeErr = c.RemoveGroupMembers(bounded, RemoveGroupMembersRequest{Identity: target.Identity, Members: []Identity{member}, Mode: request.Mode, Options: target.Options})
		} else {
			outcome, writeErr = c.AddGroupMembers(bounded, AddGroupMembersRequest{Identity: target.Identity, Members: []Identity{member}, Mode: request.Mode, Options: target.Options})
		}
		result.Outcomes[i].Result, result.Outcomes[i].Error = outcome, writeErr
		result.Processed++
		if writeErr != nil {
			failures = append(failures, writeErr)
		}
		if outcome.Mutation.State == ObjectWriteUncertain {
			break
		}
	}
	err = errors.Join(failures...)
	result.Complete = err == nil && result.Processed == len(request.Groups)
	return result, err
}
