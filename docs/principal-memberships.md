# Membership traversal, discovery and authorization

These operations have distinct meanings:

| API | Result |
| --- | --- |
| `GroupMemberLinks` | Raw direct `member` links, including ranged retrieval; no principal expansion. |
| `GroupMembers` | Resolved direct members or recursive leaf principals, including primary-group members. |
| `PrincipalGroupMembership` | Direct groups containing one principal, with explicit domain/GC or resource-context scope. |
| `AccountAuthorizationGroups` | Security groups resolved from the server's computed `tokenGroups` SIDs. |
| `AddPrincipalGroupMembership` / `RemovePrincipalGroupMembership` | Independent direct-link changes across explicitly listed groups. |

All use existing native LDAP, identity, filter, value and range machinery. There
is no runtime PowerShell/RSAT dependency, implicit connection, referral chasing,
credential forwarding or automatic retry. A `MembershipContext` supplies an
already authenticated Client and explicit Partition; the caller owns and closes
that client. Each operation has an overall caller/client deadline. It acquires
one connection gate at a time, including across multiple supplied clients.

```go
group, err := ad.IdentityByDN("CN=Engineering,OU=Groups,DC=example,DC=test")
// Check err before using group.
members, err := client.GroupMembers(ctx, group, ad.GroupMembersOptions{
    Recursive: true,
    Limits: ad.MembershipLimits{MaxObjects: 10000, MaxGroups: 500},
})
// Inspect err, Complete, LimitReached, Groups and Unresolved.
```

Group traversal uses ranged direct links and separate `primaryGroupID` searches
for domain-SID groups. Primary members are scoped to the group's domain and
their derived primary-group SID is checked. Recursive results exclude nested
groups themselves, deduplicate principals by SID and stop cycles. Direct results
retain group members. Non-security-principal objects are ignored. Missing data
on an otherwise recognizable principal, unresolved DNs, ambiguous identities or
failed range reads remain errors with retained observations.

Foreign security principals retain their local FSP object. Resolution searches
only explicitly supplied other contexts, by SID, and rejects ambiguity. A foreign
group is expanded only after its original group is resolved. Missing contexts,
unreadable principals and orphan FSPs are not quietly omitted: Unresolved retains
the original reference, lookup attempts, raw candidates and error, and Complete
stays false. Context partitions must be distinct; ambiguous same-name contexts
are rejected rather than guessed. AD DS traversal requires full domain LDAP
connections, rather than partial GC replicas. Applicable AD LDS group traversal
has no AD DS primary-group synthesis.

Empty groups and primary-only groups can omit `member` legitimately. A completed
range read with omission still permits the primary-group search and completed
enumeration. `Groups[i].Links.AttributeReturned` keeps that omission explicit.
Complete means the requested reads/traversal finished; it never proves that ACLs
exposed every possible member, or that the graph was one atomic snapshot. Link
expiry and other group changes can occur between requests without changing the
account's observed USN.

Principal membership discovery does not recurse. Its default AD DS behavior
combines home-domain global/domain-local groups, the principal's primary group,
and forest universal groups. Supply GlobalCatalog as a separately authenticated
client connected to port 3268/3269. The server must advertise a ready GC, and its
configuration-NC objectGUID must match the home forest. Matching DNS names alone
are insufficient. Universal-group discovery searches the entire GC namespace.
The source account remains pinned to a full LDAP replica of its home domain.

```go
principal, err := ad.IdentityByAccountName("jli")
// Check err; gc is an explicitly dialed catalog Client owned by the caller.
membership, err := client.PrincipalGroupMembership(ctx, principal,
    ad.PrincipalGroupMembershipOptions{GlobalCatalog: gc})
```

Alternatively, ResourceContext limits discovery to exactly its specified NC and
client. In another forest the SDK resolves the principal's SID to that NC's FSP
before matching direct member links. Same-forest cross-domain links use the
original principal DN. Primary-group inclusion applies when the resource context
is the home domain. ResourceContext and GlobalCatalog are mutually exclusive.
Explicit resource-context queries also support applicable AD LDS partitions;
automatic AD LDS forest-wide discovery is not implemented and fails explicitly.
Neither mode turns incomplete or permission-limited searches into transitive
membership or authorization claims.

Authorization reads require an account identity, not a group. The SDK issues
BASE searches for `tokenGroups` on the account's GUID, follows contiguous ranges
and preserves binary SIDs. It never substitutes `tokenGroupsNoGCAcceptable` or an
LDAP transitive-chain filter. Missing tokenGroups is unavailable, not an empty
authorization set: on AD DS it can reflect GC unavailability or access policy.
The attribute is also supported on AD LDS under its server-defined semantics.

```go
authorization, err := client.AccountAuthorizationGroups(ctx, principal,
    ad.AccountAuthorizationGroupsOptions{GlobalCatalog: gc})
// TokensComplete records range completion. Complete additionally requires every
// returned SID to resolve to a security group in the supplied contexts.
```

SID resolution searches the home context, explicit additional contexts and an
optional same-forest GC. Unresolved/deleted/hidden group SIDs and raw lookup
results remain in SIDs and Resolutions; they are not discarded or manufactured
into group objects. The result reflects the selected server's tokenGroups
calculation and domain/resource context. It is not a Windows logon token, an
access check, or a claim about every resource forest. Native group expansion,
including primary groups and SID semantics, is left to the directory. Account
GUID/USN checks detect replacement or account changes across ranges, but cannot
make a changing group graph transactional.

MembershipLimits bounds collected objects, traversed groups, attribute ranges,
depth and attribute bytes. Zero selects 100000 objects, 1000 groups/ranges, depth
32 and 64 MiB. Limits apply to collected work, not allocation of a native reply
already in flight. That received batch is retained on failure. Search limits,
native errors, cancellation, range gaps and malformed values leave partial data
visible and completion false. Normal property visibility remains distinguishable
through Object.Values and original requested properties.

Principal-to-group mutations resolve the principal once to its GUID, validate
the target list, and reuse the direct group member writer. Each target has its
own ObjectMutationOptions and native outcome. Known failures are reported per
target while subsequent targets continue; uncertain writes or cancellation stop
the remainder as not attempted. The entire list is not a transaction. No accepted
change is rolled back, no failed/uncertain change is replayed, and an accepted
permissive Modify does not prove that a link changed. PrimaryGroupID is never
modified by these APIs. TTL changes remain in AddGroupMembers.

```go
changed, err := client.AddPrincipalGroupMembership(ctx,
    ad.PrincipalGroupMembershipRequest{
        Principal: principal,
        Groups: []ad.PrincipalMembershipTarget{{Identity: group}},
        Mode: ad.GroupMembershipStrict,
    })
// Inspect every Outcomes entry, Processed and err; do not retry the list blindly.
```

`examples/memberships` performs reads only and defaults to direct group members.
Portable tests cover primary-only/empty groups, nested cycles, foreign principals,
deduplication, explicit resource contexts, missing/wrong GCs, bounded collection,
token-group range failures and per-target accepted/rejected/uncertain writes.
Actual WinLDAP loopback tests verify BASE ranged tokenGroups with binary SIDs,
partial permission failures, GUID-addressed principal membership writes and
native ownership cleanup. No live directory operation is performed by these tests.

This is a draft slice of issue #21. Live PowerShell comparisons on supported
server/module versions, realistic large/permission-limited groups, cross-forest
trust cases and AD LDS qualification remain open. Automatic forest discovery,
UPN identity guessing and cross-forest credential forwarding are not implemented.
The local tests do not close the issue or claim full cmdlet parity.

References: [group-member protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adcap/3501d61e-43c7-499b-a596-6c261124e008),
[principal membership protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adcap/3528e43c-5174-412a-82df-5c137007db28),
[tokenGroups protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/01002598-92db-4c59-822e-b22f53168c90),
[tokenGroups BASE retrieval](https://learn.microsoft.com/en-us/windows/win32/adschema/a-tokengroups),
[authorization cmdlet](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adaccountauthorizationgroup?view=windowsserver2025-ps).
