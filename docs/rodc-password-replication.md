# RODC password replication policy

The SDK implements separate operations for configured lists, observed usage and
the server's resultant policy. They execute through native WinLDAP and do not
replicate a password, authenticate an account, evict a cache, or invoke PowerShell.

| API | Meaning |
| --- | --- |
| `RODCPasswordReplicationPolicy` | Read the configured allowed or denied principals. |
| `AddRODCPasswordReplicationPolicy` / `RemoveRODCPasswordReplicationPolicy` | Change one selected list with one atomic Modify. |
| `RODCPasswordReplicationPolicyUsage` | Read authenticated accounts or revealed secret-attribute markers. |
| `AccountResultantPasswordReplicationPolicy` | Read the directory's policy for an account at the selected RODC. |

Supply an explicit RODC **computer** `Identity`, using DN, GUID, SID or SAM name.
This slice does not infer identities from DNS names, IP addresses, server objects
or NTDS Settings objects. The connection must be a synchronized AD DS full replica
of that computer's domain. GC endpoints, another domain/application NC, AD LDS,
missing capability observations and writable-DC targets are rejected. The target
must have constructed `msDS-isRODC=TRUE` and `PARTIAL_SECRETS_ACCOUNT` in its stored
account flags. These are preflight observations, not an atomic guarantee against
concurrent topology changes.

List changes require the **connected** DC to be writable. It modifies the RODC's
computer object in its writable replica. Read operations may use a writable DC or
an RODC with a full domain replica. No referral chasing, implicit connections,
credential forwarding or automatic retry occurs. Normal replication delay and
property visibility affect observations from different servers.

```go
rodc, err := ad.IdentityByDN("CN=Branch-RODC,OU=Domain Controllers,DC=example,DC=test")
// Check err. client is explicitly connected and authenticated to this domain.
allowed, err := client.RODCPasswordReplicationPolicy(ctx, rodc,
    ad.RODCPasswordAllowed, ad.RODCPasswordReplicationOptions{})
// Inspect err, allowed.Complete, Entries, Ranges and AttributeReturned.
```

Allowed and denied lists map to `msDS-RevealOnDemandGroup` and
`msDS-NeverRevealGroup`. Reads resolve their direct user/computer/service-account
or security-enabled group references; they do not expand nested groups into an
effective policy. Distribution groups and unavailable groupType observations
are rejected before list mutations, following the protocol's allowed object sets.
Resolution is confined to the specified domain NC. Unsupported foreign or
cross-domain references, hidden/deleted principals and partial native replies
retain raw entries and lookup candidates, with completion false.

Authenticated usage reads `msDS-AuthenticatedToAccountlist`, the backlink to
authentication records maintained on accounts. Revealed usage reads constructed
`msDS-RevealedList`. Each revealed DN-String identifies one secret attribute and
one account; its payload is metadata, never the secret's value. Multiple markers
can name the same account. `Entries` preserves every marker and
`Principals` deduplicates resolved accounts by GUID. A revealed attribute marker
does not establish equality of all secrets or a usable logon, and an
authentication record does not prove the account's password is cached.

All three collections follow contiguous native attribute ranges, retain original
responses and validate the controller GUID/USN across requests. An omitted
attribute can legitimately represent an empty list, but ACL visibility cannot be
proved from omission. `AttributeReturned` preserves that distinction. `Complete`
means requested reads and returned-reference resolutions finished; it is not a
transactional snapshot or proof that all properties were visible.

Collection limits use `MembershipLimits.MaxObjects`, `MaxRanges` and `MaxBytes`.
Zero chooses 100000 collected values/rows, 1000 ranges and 64 MiB of attribute
bytes. Values and principal lookup rows both consume MaxObjects. MaxGroups and
MaxDepth must be zero because these APIs do not traverse a group graph. A received
batch remains available after a limit/error; the SDK does not request another
batch to compensate. Limits do not cap allocation of a native response already
in flight. Resultant-policy reads require zero collection limits.

```go
account, err := ad.IdentityByAccountName("jli")
// Check err before querying.
policy, err := client.AccountResultantPasswordReplicationPolicy(ctx, rodc,
    account, ad.RODCPasswordReplicationOptions{})
if err == nil && policy.Policy != nil && *policy.Policy == ad.RODCPasswordPolicyAllow {
    // The selected server returned an allow policy observation.
}
```

Resultant policy uses `msDS-IsUserCachableAtRodc` with the critical native
`LDAP_SERVER_DN_INPUT_OID` control and GUID-addressed controller/account inputs.
The directory handles nested membership, deny precedence, primary-group and
special-account rules. The SDK does not emulate these rules using direct lists
or an LDAP transitive-chain filter. Known results are explicit deny (0), allow
(1), and implicit deny (2). Unknown (-1) and future numeric values remain visible;
`Known()` is false for them. Missing/malformed results return an error. The raw
attribute and any successfully decoded value remain available on native errors.
Allow is a policy observation, not a secret-replication permission check or cache
observation.

```go
changed, err := client.AddRODCPasswordReplicationPolicy(ctx,
    ad.RODCPasswordReplicationChange{
        Controller: rodc,
        List: ad.RODCPasswordAllowed,
        Principals: []ad.Identity{account},
        Mode: ad.GroupMembershipStrict,
    })
// Inspect changed.Mutation.State even when err != nil.
```

Every principal is resolved and class-checked before one GUID-addressed Modify.
All requested values are submitted together; no partial batching is performed.
The default permissive mode uses an advertised critical permissive-modify control
for already-present additions/missing removals. Strict mode retains those server
errors. Common `ObjectMutationOptions` supply supported concurrency controls;
unavailable controls fail explicitly. The SDK never reads/merges/replaces an
entire policy list to add or remove values.

Accepted writes retain accepted state if later identity readback fails. Rejected
and uncertain states preserve native diagnostics; uncertain requests are never
replayed. `Mutation.Verified` remains false: identity readback does not prove list
visibility or the account's resultant policy. List changes do not trigger password
replication or remove already-cached secrets. Reconcile the selected list and
resultant policy explicitly before deciding on further actions.

Run the read-only example with `go run ./examples/rodcpasswordpolicy -server
dc.example.test -rodc-dn 'CN=Branch-RODC,OU=Domain Controllers,DC=example,DC=test'`.
Its default operation reads the allowed list. `-operation denied`, `authenticated`
or `revealed` selects another collection; `resultant` also requires `-account-dn`.
The example has no mutation command.

Portable tests cover targeting, authoritative return values, distinct usage,
malformed DN-Strings, range/permission/limit failures and uncertain writes. Real
WinLDAP loopback tests cover critical DN-input BER, GUID targeting, multiple
revealed ranges, all list add/remove combinations, LDAP access errors and native
ownership cleanup. They perform no live directory operations.

This remains a draft implementation of #38. Live PowerShell comparisons on
Server 2016/2019/2022/2025, nested-group/deny precedence and special-account cases,
actual authenticated-versus-revealed state, permissions and large lists remain
unqualified. The portable/native tests do not claim live cmdlet parity or close
the issue. No additional native binding gap was needed for this slice.

References: [RODC object and lists](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/73d11ea7-e634-453e-944d-559654cc91c5),
[isRODC semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/314967d0-e0c6-4c1f-bca1-b3265f781d78),
[authentication backlink](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/092d1e38-6b1f-4a75-beaf-5e2a2a11dd81),
[revealed markers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4ffbc8e2-4701-492b-a63b-29f76ec62b15),
[constructed policy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5abb497-8397-4afa-92ce-001ba3696697),
[server policy algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/1df2d582-38b8-4812-bc4d-c26eb39f99e2).
