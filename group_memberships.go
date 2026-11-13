package activedirectory

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
)

var (
	ErrInvalidGroupMembership        = errors.New("invalid direct group membership request")
	ErrGroupMembershipLimit          = errors.New("direct group membership collection or request limit reached")
	ErrGroupMembershipChanged        = errors.New("group changed during member range retrieval")
	ErrGroupMembershipTarget         = errors.New("direct member retrieval requires a full LDAP replica, not a global catalog port")
	ErrGroupMembershipTTLUnsupported = errors.New("server does not advertise expiring link support")
)

const (
	groupPermissiveModify = "1.2.840.113556.1.4.1413"
	groupLinkTTL          = "1.2.840.113556.1.4.2309"
	maxGroupWriteMembers  = 10000
	maxGroupWriteBytes    = 16 << 20
)

// GroupMembershipMode controls repeated additions/removals. The default matches
// Add/Remove-ADGroupMember: existing additions and missing deletions are accepted
// using a critical permissive-modify control. Strict delegates these errors to
// the server. Neither mode retries, splits a batch, or suppresses other errors.
type GroupMembershipMode uint8

const (
	GroupMembershipPermissive GroupMembershipMode = iota
	GroupMembershipStrict
)

type AddGroupMembersRequest struct {
	Identity Identity
	Members  []Identity
	Mode     GroupMembershipMode
	// MemberPartition selects the NC for account-name member resolution. DN,
	// GUID and SID references go directly to the server, including foreign DNs.
	MemberPartition string
	// nil adds permanent links. A non-nil duration must be a nonnegative whole
	// number of seconds. PAM must already be enabled on the target forest;
	// zero explicitly removes expiry under the server's existing-link rules.
	// this operation never enables features. Existing-link TTL changes retain
	// the server's strict/permissive semantics, not a client-side upsert.
	TimeToLive *time.Duration
	Options    ObjectMutationOptions
}

type RemoveGroupMembersRequest struct {
	Identity        Identity
	Members         []Identity
	Mode            GroupMembershipMode
	MemberPartition string
	Options         ObjectMutationOptions
}

// GroupMemberInput records each requested value in order, including duplicates.
// Reference is the exact value submitted (including a TTL wrapper). Resolution
// is populated only for account names; incomplete resolutions prevent all writes.
type GroupMemberInput struct {
	Identity   Identity
	Reference  string
	Resolution *IdentityResult
}

// GroupMembershipMutationResult describes one atomic Modify for the entire
// batch. Rejection is not attributed to an individual input; a permissive
// acknowledgement does not distinguish changed links from existing state.
// Mutation.Verified remains false: group identity readback does not prove
// member visibility, TTL or link state. Use GroupMemberLinks for observation.
type GroupMembershipMutationResult struct {
	Mutation ObjectMutationResult
	Members  []GroupMemberInput
}

func (c *Client) AddGroupMembers(ctx context.Context, request AddGroupMembersRequest) (GroupMembershipMutationResult, error) {
	return c.changeGroupMembers(ctx, request, false)
}

func (c *Client) RemoveGroupMembers(ctx context.Context, request RemoveGroupMembersRequest) (GroupMembershipMutationResult, error) {
	return c.changeGroupMembers(ctx, AddGroupMembersRequest{Identity: request.Identity, Members: request.Members, Mode: request.Mode, MemberPartition: request.MemberPartition, Options: request.Options}, true)
}

func validateGroupMembers(request AddGroupMembersRequest) error {
	if err := validateGroupMutation(request.Identity, request.Options); err != nil {
		return err
	}
	if len(request.Members) == 0 || request.Mode > GroupMembershipStrict {
		return ErrInvalidGroupMembership
	}
	if len(request.Members) > maxGroupWriteMembers {
		return ErrGroupMembershipLimit
	}
	if request.TimeToLive != nil && (*request.TimeToLive < 0 || *request.TimeToLive%time.Second != 0) {
		return ErrInvalidGroupMembership
	}
	if request.MemberPartition != "" {
		if _, err := parseIdentityDN(request.MemberPartition); err != nil {
			return err
		}
	}
	bytes := 0
	for _, member := range request.Members {
		if member.form < IdentityFormDN || member.form > IdentityFormAccountName {
			return ErrInvalidIdentity
		}
		bytes += len(member.value) + 64
		if bytes > maxGroupWriteBytes {
			return ErrGroupMembershipLimit
		}
	}
	return nil
}

func (c *Client) changeGroupMembers(ctx context.Context, request AddGroupMembersRequest, remove bool) (result GroupMembershipMutationResult, err error) {
	if err = validateGroupMembers(request); err != nil {
		return result, err
	}
	for _, identity := range request.Members {
		result.Members = append(result.Members, GroupMemberInput{Identity: identity})
	}
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, request.Options, groupIdentityOptions(request.Identity, request.Options.Partition, nil), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := groupClass(*observed.Object); err != nil {
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
		if request.TimeToLive != nil && !slices.Contains(root.SupportedControls, groupLinkTTL) {
			return ErrGroupMembershipTTLUnsupported
		}
		values := make([][]byte, 0, len(request.Members))
		bytes := 0
		for index, member := range request.Members {
			if err := context.Cause(ctx); err != nil {
				return err
			}
			var reference string
			switch member.form {
			case IdentityFormDN:
				reference = member.value
			case IdentityFormGUID:
				reference = "<GUID=" + hex.EncodeToString(member.binary) + ">"
			case IdentityFormSID:
				reference = "<SID=" + hex.EncodeToString(member.binary) + ">"
			case IdentityFormAccountName:
				resolved, resolveErr := resolveIdentitySession(ctx, session, c.config, root, member, ResolveIdentityOptions{Target: IdentityTargetAccount, Partition: request.MemberPartition, Properties: []string{"objectGUID"}})
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
				reference = objectGUIDTarget(guid)
			}
			if request.TimeToLive != nil {
				reference = "<TTL=" + strconv.FormatInt(int64(*request.TimeToLive/time.Second), 10) + "," + reference + ">"
			}
			bytes += len(reference)
			if bytes > maxGroupWriteBytes {
				return ErrGroupMembershipLimit
			}
			result.Members[index].Reference = reference
			values = append(values, []byte(reference))
		}
		operation := uint32(0)
		if remove {
			operation = 1
		}
		write := ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), controls: controls, modifications: []ldapAttributeModification{{operation: operation, attribute: "member", values: values}}}
		if err := submitObjectWrite(ctx, session, write, false, mutation); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, groupProperties(request.Options.Properties), false)
	})
	return result, err
}
