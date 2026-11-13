# Direct group membership

`AddGroupMembers` and `RemoveGroupMembers` modify the `member` attribute of one
resolved group. `GroupMemberLinks` retrieves its direct link values through all
returned ranges. These APIs extend issue #20's group lifecycle. They do not
resolve member objects, expand nested groups, include primary-group membership,
or discover groups for a principal; those are issue #21's separate operations.
No PowerShell or RSAT is used at runtime.

```go
group, err := ad.IdentityByDN("CN=Application Readers,OU=Groups,DC=example,DC=test")
// Check each constructor error.
member, err := ad.IdentityByDN("CN=User,OU=People,DC=example,DC=test")
result, err := client.AddGroupMembers(ctx, ad.AddGroupMembersRequest{
    Identity: group, Members: []ad.Identity{member},
    Mode: ad.GroupMembershipPermissive,
})
// Always inspect err and result.Mutation.State; never automatically replay.
```

The group uses the shared class-checked identity resolver. Members accept explicit
DN, GUID, SID or account-name identities. DN/GUID/SID member references are sent
directly to the selected server; a foreign DN is not incorrectly confined to the
group's naming context. GUID and SID use documented alternative DN forms. Account
names are resolved uniquely on the same authenticated connection and submitted
by GUID. `MemberPartition` overrides their configured/default partition. These
account lookups require AD DS; DN/GUID group identities and direct references can
be used with applicable AD LDS groups. There is no referral chasing, foreign DC
discovery, implicit foreign-security-principal creation by the SDK, or credential
forwarding. The server remains authoritative for reference resolution, nested
group/category/scope rules, permissions and cross-domain constraints.

Each call issues one atomic Modify with every supplied member, preserving input
order and duplicates. Default `GroupMembershipPermissive` requires the advertised
critical permissive-modify control; existing additions and missing deletions can
succeed without a change. `GroupMembershipStrict` omits that control, retaining
the server's duplicate/missing-value errors. The SDK does not split a failed batch
or attribute a batch rejection to a guessed member. `Members` preserves each
input, the submitted reference and any account-name resolution candidates.
Requests are limited to 10,000 members and 16 MiB of encoded reference values.

`Options.ExpectedVersion` reuses the shared endpoint/GUID/USN assertion guard.
An unsupported critical control fails before mutation. Native LDAP codes and
diagnostics are retained. Accepted means the server acknowledged the whole
request, including possible permissive no-ops. An accepted write followed by a
failed readback or cleanup remains accepted with an error. Uncertain means the
request may have committed: reconcile before another write. There are no retries.
The post-write observation reads group identity and requested properties;
`Mutation.Verified` deliberately remains false because it does not prove links,
their visibility, their TTL or which values changed.

For an expiring addition, set `TimeToLive` to a positive whole-second
`time.Duration`. It emits `<TTL=seconds,DN>` (including alternate GUID/SID DNs).
Nil requests an ordinary permanent reference. A non-nil zero explicitly submits
`<TTL=0,DN>`, removing expiry under the server's existing-link rules. Negative or
fractional-second durations are rejected. The SDK requires advertised link
TTL support; the target must additionally have the PAM optional feature already
enabled at forest functional level Windows Server 2016 or later. The server
enforces this prerequisite and any existing-link TTL semantics. The SDK neither
enables PAM nor replaces existing links to force a TTL update. The TTL search
control is **not** sent with Modify. Removal deletes the link regardless of TTL.

```go
links, err := client.GroupMemberLinks(ctx, group, ad.GroupMemberLinksOptions{
    IncludeTTL: true, MaxValues: 200000, MaxRanges: 1000, MaxBytes: 64 << 20,
})
// Preserve links even on error; require links.Complete for complete traversal.
for _, link := range links.Members {
    fmt.Println(link.DistinguishedName, link.RemainingTTLSeconds)
}
```

The reader pins the resolved group GUID and observed `uSNChanged`, requests at
most 1,500 values per range, validates contiguous indices and declared counts,
and stops only on a terminal range/plain attribute or an explicit error. An
AD DS global catalog port is rejected because it can expose partial membership.
Each range must return the same GUID/USN. It returns a partial result if the group
changes, a range is missing/malformed, a request fails, or a bound/deadline is
reached. It does not retry a changing group or claim a transactional snapshot:
TTL expiry can remove links without a USN change. `Members` holds decoded values
observed even in an incomplete response; `Ranges` retains original attribute
names and bytes, including a failed/malformed batch.

Zero limits default to 100,000 values, 1,000 ranges and 64 MiB of returned attribute
bytes. The final received batch is preserved even when it crosses a limit, so
these are accumulation/work bounds, not a cap on a native in-flight response.
An omitted attribute gives `AttributeReturned=false`; neither omission nor
successful traversal proves an empty group under attribute ACLs. With
`IncludeTTL`, a critical valueless TTL search control requests remaining seconds
for expiring links. `ObservedAt` is a client timestamp. Without that option, nil
TTL means it was not requested, not that a link is permanent.

`examples/groupmemberships` defaults to read-only enumeration and requires
`-apply` for an explicit add/remove. Unit tests cover 3,003 values, limits,
malformed/gapped/changed ranges, partial errors, identity/capability guards,
strict/permissive batches and uncertain writes. Host-only actual WinLDAP
loopback tests verify UTF-8 member values, escaped-comma DNs, TTL values,
critical controls, continuation and seven native ownership counters. Live
Server 2016/2019/2022/2025 and applicable AD LDS differential qualification,
including enabled-PAM expiry, cross-domain/FSP/nesting and ACL cases, remains
open. This implementation does not claim that qualification has happened.

Protocol sources: [alternative DN and TTL-DN forms](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/92a54869-38d7-4e71-a3be-5f67a0dcdd7e),
[permissive modify](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/49cdb1e3-3baa-4c7c-8cde-7c26b13d3ba7),
[TTL search control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f4f523a8-abc0-4b3a-a471-6b2fef135481),
[PAM prerequisites](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d079eee8-1bac-4b03-86e4-506a21450905),
[range retrieval](https://learn.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval),
[Add-ADGroupMember](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember?view=windowsserver2025-ps).
