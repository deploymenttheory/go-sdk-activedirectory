package activedirectory

import (
	"context"
	"slices"
)

// One request changes one explicit list in one atomic Modify. Reuse the direct
// membership strict/permissive semantics and common concurrency controls. No
// secret replication, cache eviction, cross-domain lookup or automatic replay.
type RODCPasswordReplicationChange struct {
	Controller Identity
	List       RODCPasswordReplicationList
	Principals []Identity
	Mode       GroupMembershipMode
	Options    ObjectMutationOptions
}
type RODCPasswordReplicationMutationResult struct {
	Mutation   ObjectMutationResult
	Principals []GroupMemberInput
}

func (c *Client) AddRODCPasswordReplicationPolicy(ctx context.Context, request RODCPasswordReplicationChange) (RODCPasswordReplicationMutationResult, error) {
	return c.changeRODCPasswordPolicy(ctx, request, false)
}
func (c *Client) RemoveRODCPasswordReplicationPolicy(ctx context.Context, request RODCPasswordReplicationChange) (RODCPasswordReplicationMutationResult, error) {
	return c.changeRODCPasswordPolicy(ctx, request, true)
}
func (c *Client) changeRODCPasswordPolicy(ctx context.Context, request RODCPasswordReplicationChange, remove bool) (result RODCPasswordReplicationMutationResult, err error) {
	attribute, err := request.List.attribute()
	if err != nil {
		return result, err
	}
	if err = validateGroupMembers(AddGroupMembersRequest{Identity: request.Controller, Members: request.Principals, Mode: request.Mode, Options: request.Options}); err != nil {
		return result, err
	}
	for _, identity := range request.Principals {
		result.Principals = append(result.Principals, GroupMemberInput{Identity: identity})
	}
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Controller, request.Options, membershipResolveOptions(request.Controller, request.Options.Partition, rodcPasswordProperties(nil)), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := rodcPasswordServer(ctx, c, session, root, observed.Partition, true); err != nil {
			return err
		}
		if err := validateRODCPasswordTarget(*observed.Object); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		if request.Mode == GroupMembershipPermissive {
			if !slices.Contains(root.SupportedControls, groupPermissiveModify) {
				return ErrObjectControlUnsupported
			}
			controls = append(controls, ldapWriteControl{oid: groupPermissiveModify, critical: true})
		}
		values := make([][]byte, 0, len(request.Principals))
		for i, identity := range request.Principals {
			resolved, resolveErr := resolveIdentitySession(ctx, session, c.config, root, identity, membershipResolveOptions(identity, observed.Partition, []string{"groupType"}))
			result.Principals[i].Resolution = &resolved
			if resolveErr != nil {
				return resolveErr
			}
			if err := validateRODCPasswordPrincipal(*resolved.Object, true); err != nil {
				return err
			}
			principal, resolveErr := decodeMembershipPrincipal(*resolved.Object, c.config.Endpoint)
			if resolveErr != nil {
				return resolveErr
			}
			reference := objectGUIDTarget(principal.GUID)
			result.Principals[i].Reference = reference
			values = append(values, []byte(reference))
		}
		operation := uint32(0)
		if remove {
			operation = 1
		}
		write := ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), controls: controls, modifications: []ldapAttributeModification{{operation: operation, attribute: attribute, values: values}}}
		if err := submitObjectWrite(ctx, session, write, false, mutation); err != nil {
			return err
		}
		// Identity readback is useful, but does not establish linked-value visibility
		// or the resultant policy. Mutation.Verified deliberately remains false.
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, rodcPasswordProperties(request.Options.Properties), false)
	})
	return result, rodcPasswordError(err)
}
