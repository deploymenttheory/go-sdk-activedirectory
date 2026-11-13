# Central access rules and policies

`CentralAccessRule`, `CentralAccessRules`, `CentralAccessPolicy` and
`CentralAccessPolicies` read the AD DS configuration naming context. Their
create, update and delete counterparts use native asynchronous LDAP writes;
`AddCentralAccessPolicyMembers` and `RemoveCentralAccessPolicyMembers` edit
rule memberships in one LDAP modify. Runtime PowerShell, AD Web Services and
an installed agent are not required. Native execution supports Windows amd64
and arm64; portable input validation and models build on other platforms.

These APIs require AD DS with the Windows Server 2012 central-access schema
and containers installed by forest preparation. They neither install that
schema nor impose an invented forest functional-level requirement. AD LDS and
Global Catalog endpoints are rejected. Explicit partitions must match the
configuration naming context. DN/GUID identities use the shared identity API;
rules and policies must have the expected class and direct container parent.
Search uses the existing typed or raw LDAP filter and restricts the result to
that container and class. Configure an explicit writable LDAP endpoint and
credentials with the necessary read/create/write/delete or DACL permissions.

## Permissions, expressions and IDs

The rule fields are independent. Current, proposed and previous permissions
map to `msAuthz-EffectiveSecurityPolicy`, `msAuthz-ProposedSecurityPolicy` and
`msAuthz-LastEffectiveSecurityPolicy`. Resource conditions map to
`msAuthz-ResourceCondition`. **All four are Unicode directory strings**, not
binary security descriptors. The SDK validates permission SDDL and conditional
expressions through Windows, then sends the original SDDL or rendered condition
text. It preserves owner, group, conditional ACEs and unrelated values in those
strings. Syntax validation does not prove a claim exists or evaluate access.

Replacing or clearing current permissions also records the observed old value
as previous permissions in the same LDAP modify. A strict delete of the old
current value makes a concurrent replacement reject the entire modification;
the SDK cannot manufacture history from an omitted or unreadable current value.
Updating proposed permissions or the resource condition does not change current
or previous permissions. Explicit `Clear*` fields distinguish clearing from
leaving a field unchanged. Raw `Changes` support unrelated schema properties;
they cannot bypass managed permission, membership, ID or object-DACL fields.

Omitted creation CurrentACL uses
`O:SYG:SYD:(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)`. This was observed from the
installed Microsoft reference module's native default descriptor helper; it is
not a claim of live differential qualification. Policy creation generates a
cryptographically random 128-bit scoped policy SID, `S-1-17-a-b-c-d`, and writes
its binary SID representation to `msAuthz-CentralAccessPolicyID`. The generated
ID survives rejected or uncertain Add outcomes in `GeneratedPolicyID`, so callers
can reconcile the exact attempt. IDs cannot be replaced through this API.

## Memberships and incomplete observations

Singular and plural reads include rule backlinks or policy member references.
They retrieve contiguous ranges, pin the source object GUID and observed USN,
reject equivalent duplicate DNs, and retain raw ranges when later reads fail.
Limits default to 100,000 references, 1,000 reads and 64 MiB of returned attribute
bytes per source, with cancellation checks during materialization. Positive
`Max*` values override these defaults; the defaults are not hard caps. `Complete`
means retrieval completed at that observed source version. It does not prove
that ACLs exposed every value or provide a snapshot of referenced objects.
`AttributeReturned=false` remains distinct from an explicitly returned empty set.

Member inputs must resolve to rules in the canonical central-rule container.
Each request uses strict LDAP add/delete values, preserving other members;
duplicates and absent removals retain native errors. The reference module's
127-rule limit is checked against observed membership before adding and after
readback. This is an observed client-side bound, not an assertion that the schema
enforces it. Concurrent changes or hidden values can prevent proof of the total.
`ExpectedVersion` requests the shared critical server assertion control when
advertised; the SDK never substitutes a client read for that control.

## Write outcomes and protection

Inspect results even when an error is returned. `Mutation.State` records whether
a write was submitted, accepted, rejected or uncertain; `Verified` separately
describes observed requested effects. All methods use one timeout across their
multi-stage workflow, and never replay a submitted request. Readback failure
retains accepted status and raw observations. LDAP omission after clearing a
permission or removing the final member is compatible with empty data and with
ACL hiding; the result remains accepted but unverified with
`ErrObjectVerification`, rather than claiming proven absence of the attribute.

Creation with omitted `ProtectedFromAccidentalDeletion` leaves schema/default
ACLs unchanged. The installed module's pure default helper reports false for
both central-access classes. Explicit true/false uses the shared protection
workflow: enabling can change the parent DACL before the object's DACL;
disabling changes the object's DACL only. Each stage and its native outcome is
retained in `Protection`. Unrelated, inherited and unknown ACE bytes are
preserved from the observed descriptor. This default read/modify/write workflow
does not promise atomic preservation against concurrent DACL edits. A version
precondition cannot cover multiple objects; unsupported combinations and no-op
paths that cannot enforce it fail explicitly. See [OU protection](organizational-units.md).

Deletion performs one leaf delete. It does not unprotect objects, separately
remove memberships, cascade to rules/policies, or modify GPO deployment or file
ACLs. Native ACL, non-leaf and linked-reference behavior remains authoritative;
any directory-maintained backlink changes are directory effects. Existing
filesystem references to a policy SID are outside this directory API.

## Example and qualification

```powershell
go run ./examples/central-access -server dc.example.test -kind rule -dn 'CN=Finance,CN=Central Access Rules,CN=Claims Configuration,CN=Services,CN=Configuration,DC=example,DC=test'
go run ./examples/central-access -server dc.example.test -kind rule -operation create -name Finance -apply
go run ./examples/central-access -server dc.example.test -kind policy -operation create -name Finance -apply
```

The example reads by default and emits JSON before returning an operation error.
It also exposes update, explicit protect/unprotect, member add/remove and delete
operations, all requiring `-apply`. For a caller-owned existing object, save its
read output and run `scripts/reference-central-access.ps1` with the same server,
DN, kind and `-SDKResultPath`. The script performs read-only native-module/raw
attribute comparisons, records module/server versions and leaves errors visible.
It does not provision a fixture or establish deployment/effective-access parity.

Portable tests cover lifecycle, history races, reference constraints and ranges,
127-rule limits, ACL-stage failures and uncertain/accepted outcomes. Host-only
WinLDAP tests cover actual SDDL text, atomic history modifications, server
errors, ranged references and native allocation release. Live AD DS comparison
of permissions, membership limits, protected deletion, concurrent writers,
server versions and downstream policy use remains required for issue #42.

Sources: [schema additions](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/schema-updates),
[New-ADCentralAccessRule](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adcentralaccessrule?view=windowsserver2025-ps),
[Set-ADCentralAccessRule](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adcentralaccessrule?view=windowsserver2025-ps),
[New-ADCentralAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adcentralaccesspolicy?view=windowsserver2025-ps),
[membership operation](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adcentralaccesspolicymember?view=windowsserver2025-ps),
[MS-CAPR policy identifiers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-capr/66f308bc-ebc7-4870-8b41-d8da9495b222).
Local reference observations used Microsoft.ActiveDirectory.Management file
10.0.26100.7920, module 1.0.1.0: `GetDefaultCAPESecurityDescriptor`,
`GenerateNewCAPID`, the 127-member constant, history precommit logic and
`ShouldProtectByDefault`. Undocumented reference exports are not SDK dependencies.
