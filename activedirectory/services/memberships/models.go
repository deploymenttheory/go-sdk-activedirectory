// Package memberships provides the memberships SDK interface.
package memberships

import (
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// AccountAuthorizationGroupsOptions is the SDK's AccountAuthorizationGroupsOptions.
type AccountAuthorizationGroupsOptions = adengine.AccountAuthorizationGroupsOptions

// TokensComplete means the server returned every contiguous tokenGroups range.
// Complete additionally requires every SID to resolve to a security group in
// the supplied contexts. Neither is a Windows logon token or access-check result.
type AccountAuthorizationGroupsResult = admodel.AccountAuthorizationGroupsResult

// AddGroupMembersRequest is the SDK's AddGroupMembersRequest.
type AddGroupMembersRequest = admodel.AddGroupMembersRequest

// AuthorizationGroupSIDResult is the SDK's AuthorizationGroupSIDResult.
type AuthorizationGroupSIDResult = admodel.AuthorizationGroupSIDResult

// ErrAuthorizationGroupsUnavailable is the SDK's ErrAuthorizationGroupsUnavailable.
var ErrAuthorizationGroupsUnavailable = admodel.ErrAuthorizationGroupsUnavailable

// ErrGroupMembershipChanged is the SDK's ErrGroupMembershipChanged.
var ErrGroupMembershipChanged = admodel.ErrGroupMembershipChanged

// ErrGroupMembershipLimit is the SDK's ErrGroupMembershipLimit.
var ErrGroupMembershipLimit = admodel.ErrGroupMembershipLimit

// ErrGroupMembershipTTLUnsupported is the SDK's ErrGroupMembershipTTLUnsupported.
var ErrGroupMembershipTTLUnsupported = admodel.ErrGroupMembershipTTLUnsupported

// ErrGroupMembershipTarget is the SDK's ErrGroupMembershipTarget.
var ErrGroupMembershipTarget = admodel.ErrGroupMembershipTarget

// ErrInvalidGroupMembership is the SDK's ErrInvalidGroupMembership.
var ErrInvalidGroupMembership = admodel.ErrInvalidGroupMembership

// ErrInvalidMembership is the SDK's ErrInvalidMembership.
var ErrInvalidMembership = admodel.ErrInvalidMembership

// ErrInvalidRODCPasswordPolicy is the SDK's ErrInvalidRODCPasswordPolicy.
var ErrInvalidRODCPasswordPolicy = admodel.ErrInvalidRODCPasswordPolicy

// ErrMembershipContext is the SDK's ErrMembershipContext.
var ErrMembershipContext = admodel.ErrMembershipContext

// ErrMembershipForeign is the SDK's ErrMembershipForeign.
var ErrMembershipForeign = admodel.ErrMembershipForeign

// ErrMembershipGC is the SDK's ErrMembershipGC.
var ErrMembershipGC = admodel.ErrMembershipGC

// ErrMembershipLimit is the SDK's ErrMembershipLimit.
var ErrMembershipLimit = admodel.ErrMembershipLimit

// ErrRODCPasswordPolicyCapability is the SDK's ErrRODCPasswordPolicyCapability.
var ErrRODCPasswordPolicyCapability = admodel.ErrRODCPasswordPolicyCapability

// ErrRODCPasswordPolicyPermission is the SDK's ErrRODCPasswordPolicyPermission.
var ErrRODCPasswordPolicyPermission = admodel.ErrRODCPasswordPolicyPermission

// ErrRODCPasswordPolicyTarget is the SDK's ErrRODCPasswordPolicyTarget.
var ErrRODCPasswordPolicyTarget = admodel.ErrRODCPasswordPolicyTarget

// GroupMemberInput records each requested value in order, including duplicates.
// Reference is the exact value submitted (including a TTL wrapper). Resolution
// is populated only for account names; incomplete resolutions prevent all writes.
type GroupMemberInput = admodel.GroupMemberInput

// GroupMemberLink is a direct member attribute value, not a resolved principal
// or recursive membership. RemainingTTLSeconds is populated only for returned
// TTL-DNs; nil means no TTL was returned, not necessarily a permanent link when
// IncludeTTL was false. ObservedAt is a client timestamp, not a server expiry.
type GroupMemberLink = admodel.GroupMemberLink

// GroupMemberLinksOptions bounds one read on one authenticated connection. Zero
// limits select defaults: 100,000 values, 1,000 ranges and 64 MiB of attribute
// bytes. A received batch is retained even if it crosses a limit; no next batch
// is requested. Limits bound accumulated work, not the native in-flight reply.
type GroupMemberLinksOptions = admodel.GroupMemberLinksOptions

// Complete means all returned ranges were contiguous, bounded and decoded with
// the same objectGUID/uSNChanged. It does not establish ACL visibility or a
// transactional snapshot: expiring links can vanish without a USN change.
// AttributeReturned distinguishes an omitted member attribute from an explicit
// empty response. Neither omission nor Complete proves an empty group.
type GroupMemberLinksResult = admodel.GroupMemberLinksResult

// GroupMemberRange is the SDK's GroupMemberRange.
type GroupMemberRange = admodel.GroupMemberRange

// GroupMembersOptions is the SDK's GroupMembersOptions.
type GroupMembersOptions = adengine.GroupMembersOptions

// Complete means every requested traversal, range and resolution completed.
// It does not prove ACL visibility or a transactionally consistent graph. Each
// Links.AttributeReturned preserves omission without proving no hidden members.
type GroupMembersResult = admodel.GroupMembersResult

// GroupMembershipMode controls repeated additions/removals. The default matches
// Add/Remove-ADGroupMember: existing additions and missing deletions are accepted
// using a critical permissive-modify control. Strict delegates these errors to
// the server. Neither mode retries, splits a batch, or suppresses other errors.
type GroupMembershipMode = admodel.GroupMembershipMode

// GroupMembershipMutationResult describes one atomic Modify for the entire
// batch. Rejection is not attributed to an individual input; a permissive
// acknowledgement does not distinguish changed links from existing state.
// Mutation.Verified remains false: group identity readback does not prove
// member visibility, TTL or link state. Use GroupMemberLinks for observation.
type GroupMembershipMutationResult = admodel.GroupMembershipMutationResult

// GroupMembershipPermissive is the SDK's GroupMembershipPermissive.
const GroupMembershipPermissive = admodel.GroupMembershipPermissive

// GroupMembershipStrict is the SDK's GroupMembershipStrict.
const GroupMembershipStrict = admodel.GroupMembershipStrict

// GroupMembershipTraversal is the SDK's GroupMembershipTraversal.
type GroupMembershipTraversal = admodel.GroupMembershipTraversal

// MembershipContext explicitly supplies an authenticated connection and NC.
// The SDK does not dial, forward credentials, chase referrals, or close it.
type MembershipContext = adengine.MembershipContext

// Zero limits select 100000 objects, 1000 groups/ranges, depth 32 and 64 MiB.
// A received native batch is retained on overflow, then no next read is made.
type MembershipLimits = admodel.MembershipLimits

// MembershipLookup is the SDK's MembershipLookup.
type MembershipLookup = admodel.MembershipLookup

// MembershipPrincipal is the SDK's MembershipPrincipal.
type MembershipPrincipal = admodel.MembershipPrincipal

// MembershipResolution is the SDK's MembershipResolution.
type MembershipResolution = admodel.MembershipResolution

// MembershipSearch is the SDK's MembershipSearch.
type MembershipSearch = admodel.MembershipSearch

// Each group is an independent Modify. Known failures retain per-target results;
// uncertainty or cancellation stops all remaining targets without replay.
type PrincipalGroupMembershipMutationResult = admodel.PrincipalGroupMembershipMutationResult

// ErrPrincipalMembershipIncomplete indicates that independent group writes
// have accepted or uncertain effects despite a later failure. Reconcile first.
var ErrPrincipalMembershipIncomplete = admodel.ErrPrincipalMembershipIncomplete

// PrincipalGroupMembershipOptions is the SDK's PrincipalGroupMembershipOptions.
type PrincipalGroupMembershipOptions = adengine.PrincipalGroupMembershipOptions

// PrincipalGroupMembershipRequest is the SDK's PrincipalGroupMembershipRequest.
type PrincipalGroupMembershipRequest = admodel.PrincipalGroupMembershipRequest

// Complete covers these direct membership searches, not transitive membership,
// ACL visibility, replication convergence or authorization. ResourceContext
// returns only its specified NC. No automatic cross-forest lookup occurs.
type PrincipalGroupMembershipResult = admodel.PrincipalGroupMembershipResult

// PrincipalMembershipOutcome is the SDK's PrincipalMembershipOutcome.
type PrincipalMembershipOutcome = admodel.PrincipalMembershipOutcome

// PrincipalMembershipTarget is the SDK's PrincipalMembershipTarget.
type PrincipalMembershipTarget = admodel.PrincipalMembershipTarget

// RODCPasswordAllowed is the SDK's RODCPasswordAllowed.
const RODCPasswordAllowed = admodel.RODCPasswordAllowed

// RODCPasswordAuthenticated is the SDK's RODCPasswordAuthenticated.
const RODCPasswordAuthenticated = admodel.RODCPasswordAuthenticated

// RODCPasswordDenied is the SDK's RODCPasswordDenied.
const RODCPasswordDenied = admodel.RODCPasswordDenied

// RODCPasswordPolicyAllow is the SDK's RODCPasswordPolicyAllow.
const RODCPasswordPolicyAllow = admodel.RODCPasswordPolicyAllow

// RODCPasswordPolicyDenyExplicit is the SDK's RODCPasswordPolicyDenyExplicit.
const RODCPasswordPolicyDenyExplicit = admodel.RODCPasswordPolicyDenyExplicit

// RODCPasswordPolicyDenyImplicit is the SDK's RODCPasswordPolicyDenyImplicit.
const RODCPasswordPolicyDenyImplicit = admodel.RODCPasswordPolicyDenyImplicit

// RODCPasswordPolicyUnknown is the SDK's RODCPasswordPolicyUnknown.
const RODCPasswordPolicyUnknown = admodel.RODCPasswordPolicyUnknown

// One request changes one explicit list in one atomic Modify. Reuse the direct
// membership strict/permissive semantics and common concurrency controls. No
// secret replication, cache eviction, cross-domain lookup or automatic replay.
type RODCPasswordReplicationChange = admodel.RODCPasswordReplicationChange

// Revealed entries are per-secret-attribute markers, not secret values. Several
// markers can name one account. Authenticated entries have SecretAttribute empty.
type RODCPasswordReplicationEntry = admodel.RODCPasswordReplicationEntry

// RODCPasswordReplicationList is the SDK's RODCPasswordReplicationList.
type RODCPasswordReplicationList = admodel.RODCPasswordReplicationList

// RODCPasswordReplicationMutationResult is the SDK's RODCPasswordReplicationMutationResult.
type RODCPasswordReplicationMutationResult = admodel.RODCPasswordReplicationMutationResult

// The target is explicitly the RODC computer object, using the shared Identity
// constructors. Server/DSA object identities, DNS names and discovery are not
// guessed. Partition defaults to the connected server's full domain NC.
type RODCPasswordReplicationOptions = admodel.RODCPasswordReplicationOptions

// Complete covers contiguous ranges and resolution of the returned references.
// Omission is retained in AttributeReturned; it does not prove ACL visibility.
// Principals are deduplicated by GUID; Entries preserve every raw linked value.
type RODCPasswordReplicationResult = admodel.RODCPasswordReplicationResult

// RODCPasswordReplicationUsageKind is the SDK's RODCPasswordReplicationUsageKind.
type RODCPasswordReplicationUsageKind = admodel.RODCPasswordReplicationUsageKind

// RODCPasswordRevealed is the SDK's RODCPasswordRevealed.
const RODCPasswordRevealed = admodel.RODCPasswordRevealed

// RODCResultantPasswordReplicationPolicy is the SDK's RODCResultantPasswordReplicationPolicy.
type RODCResultantPasswordReplicationPolicy = admodel.RODCResultantPasswordReplicationPolicy

// Policy is the server's constructed attribute, never a local approximation of
// nested membership. Raw retains absent, malformed and unknown values. Complete
// only describes this read; it does not mean permission to replicate secrets,
// current cache state, or replication convergence.
type RODCResultantPasswordReplicationResult = admodel.RODCResultantPasswordReplicationResult

// RemoveGroupMembersRequest is the SDK's RemoveGroupMembersRequest.
type RemoveGroupMembersRequest = admodel.RemoveGroupMembersRequest
