package model

import (
	"errors"
	"time"
)

var (
	ErrInvalidGroupMembership = errors.New("invalid direct group membership request")
	ErrGroupMembershipLimit   = errors.New(
		"direct group membership collection or request limit reached",
	)
	ErrGroupMembershipChanged = errors.New("group changed during member range retrieval")
	ErrGroupMembershipTarget  = errors.New(
		"direct member retrieval requires a full LDAP replica, not a global catalog port",
	)
	ErrGroupMembershipTTLUnsupported = errors.New("server does not advertise expiring link support")
)

const (
	InternalGroupPermissiveModify = "1.2.840.113556.1.4.1413"
	InternalGroupLinkTTL          = "1.2.840.113556.1.4.2309"
	InternalMaxGroupWriteMembers  = 10000
	InternalMaxGroupWriteBytes    = 16 << 20
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

func InternalValidateGroupMembers(request AddGroupMembersRequest) error {
	if err := InternalValidateGroupMutation(request.Identity, request.Options); err != nil {
		return err
	}
	if len(request.Members) == 0 || request.Mode > GroupMembershipStrict {
		return ErrInvalidGroupMembership
	}
	if len(request.Members) > InternalMaxGroupWriteMembers {
		return ErrGroupMembershipLimit
	}
	if request.TimeToLive != nil &&
		(*request.TimeToLive < 0 || *request.TimeToLive%time.Second != 0) {
		return ErrInvalidGroupMembership
	}
	if request.MemberPartition != "" {
		if _, err := InternalParseIdentityDN(request.MemberPartition); err != nil {
			return err
		}
	}
	bytes := 0
	for _, member := range request.Members {
		if member.form < IdentityFormDN || member.form > IdentityFormAccountName {
			return ErrInvalidIdentity
		}
		bytes += len(member.value) + 64
		if bytes > InternalMaxGroupWriteBytes {
			return ErrGroupMembershipLimit
		}
	}
	return nil
}
