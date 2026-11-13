# Replication connections, site links and bridges

These APIs implement the connection Get/Set and site-link/bridge New/Get/Set/Remove
operations in issue #34 through native asynchronous LDAP. They require Windows
amd64/arm64 at runtime; importing and compiling remains portable. They do not
require PowerShell or RSAT at runtime.

Use explicit DN/GUID `Identity` values. All objects and references must belong to
the connected endpoint's configuration naming context. `Config.Partition` does
not redirect these topology operations into an application/domain partition; an
explicit incompatible operation partition is rejected. AD DS GC endpoints cannot
write. AD LDS supports the IP transport; SMTP is rejected as unsupported.

## Reads

`ReplicationConnection` and `ReplicationConnections` expose source and destination
DSAs, transport DN, enabled state, schedule, option bits, GUID and raw attributes.
Connection searches default to the Sites subtree; explicit search bases must
remain below it. Existing raw/typed filter composition applies.

`ReplicationSiteLink` / `ReplicationSiteLinkBridge` accept
`ReplicationLinkReadOptions`; their plural search methods accept a transport,
`SearchOptions` and `ReplicationReferenceLimits`. Links expose cost, interval,
schedule and options. Bridges expose their transport and metadata. The result's
`Sites` / `SiteLinks` contains the referenced DNs and original bytes, each raw
range response, `AttributeReturned`, `Complete` and `Error`.

References continue through contiguous LDAP ranges. Every batch must carry the
same objectGUID/uSNChanged as the first observation. Defaults bound a read to
100000 references, 1000 ranges and 64 MiB of returned attribute names/value bytes.
Limits can be lowered or raised explicitly. Duplicates, gaps, inconsistent counts,
changed source versions, permission errors and cancellation retain the received
raw batches and any decoded prefix. Search results retain each row's failure.
`Complete` does not prove ACL visibility: an omitted attribute remains distinct
from a returned empty attribute. Raw attributes are never synthesized from typed
values. Reference reads do not assert the referenced objects are still live.

## Mutations

```go
siteA, _ := ad.IdentityByDN("CN=A,CN=Sites,CN=Configuration,DC=example,DC=com")
siteB, _ := ad.IdentityByDN("CN=B,CN=Sites,CN=Configuration,DC=example,DC=com")
created, err := client.CreateReplicationSiteLink(ctx, ad.CreateReplicationSiteLinkRequest{
    Name: "A-B", Transport: ad.ReplicationTransportIP,
    Sites: []ad.Identity{siteA, siteB},
})
// Inspect created.Mutation.State even when err != nil. Never automatically retry.
```

New links default to cost 100 and interval 180 minutes. Cost must be nonnegative;
intervals are multiples of 15 between 15 and 10080 minutes. An omitted schedule
is left absent (the directory's default availability); an explicitly supplied
all-zero schedule permits no time slots. `ReplicationSchedule` uses the existing
188-byte Windows format and UTC quarter-hour slots; see [sites](replication-sites.md).

Create/update links accept site identities. Create/update bridges accept link
identities from the same transport container. Each supplied reference is resolved
and checked for class, configuration and placement before a write. References are
not followed to another endpoint. These are observations, not a transaction across
the referenced objects. Membership lists may be empty while a topology is being
assembled; successful LDAP writes do not prove a usable replication path or a
connected bridge graph. The server remains authoritative for schema constraints.

`ReplicationReferenceChanges` uses a non-nil `Replace` slice for explicit
replacement, including clearing the complete attribute with an empty slice.
Otherwise disjoint `Remove`/`Add` lists become one remove-first atomic LDAP Modify,
preserving every other member. No permissive-modify control suppresses missing or
duplicate-value errors. `SetOptions`/`ClearOptions` preserve unmentioned/unknown
bits by strict delete-old/add-new in the same Modify; a stale observed value causes
server rejection instead of overwriting another editor's flags. Missing options
cannot be treated as zero for such a patch.

Connections can change `ReplicateFromDirectoryServer`, `Transport`, `Enabled`,
description, schedule and documented option bits. A source must resolve to a
configuration server or its nTDSDSA child; self-replication is rejected. Schedule
bytes and `ReplicationConnectionUserOwnedSchedule` are separate explicit inputs,
matching the native directory properties. Setting a schedule does not silently
change KCC ownership, generated-connection flags or other options. KCC can later
change its managed objects. Link/bridge transport is selected at creation, not
changed by moving the object to another transport.

Raw `Changes` / creation `Attributes` support additional schema attributes. Managed
topology fields must use their typed inputs; raw writes cannot bypass their
validation. The existing generic object API remains available for other operations.
Deletes are native leaf deletes; neither bridges nor links cause their referenced
objects to be deleted. No replication synchronization or KCC execution is implied.

Each result retains `ObjectMutationResult` (not-attempted, accepted, rejected or
uncertain), resolved reference inputs and typed/raw readback. Accepted is preserved
if readback fails. Membership verification uses complete bounded ranges and DN
structural equality. A successful final-member removal commonly makes LDAP omit
the attribute; this is **accepted but unverified**, with `ErrObjectVerification`,
because omission cannot distinguish empty from unreadable. Clearing a schedule
has the same conservative generic verification rule.

`ExpectedVersion` requires a supported critical assertion control on the connected
endpoint. No-op updates reject a requested version because no guarded write would
be submitted. Without an assertion, ordinary scalar replacements and explicit
membership replacements do not guard against concurrent edits. There are no
automatic retries, rollbacks, reconnects or credential forwarding. The complete
workflow shares one cancellation/deadline budget. Creation uses the generic schema
naming and native write engine with bounded reference verification under its gate.

## Running and qualification

`go run ./examples/replication-links -server dc.example.com` lists IP site links.
Use `-operation connections`, `bridges`, `link`, `bridge` or `connection` for reads.
Mutations require explicit `-apply`; `-reference-dn` can be repeated for membership.
The example prints the result before returning an error so partial evidence survives.

`scripts/reference-replication-links.ps1` is an opt-in read-only PowerShell
collector/comparator for an explicitly selected object/server. It records OS/module
versions, typed cmdlet output, original raw property values and normalized comparisons
against the example's SDK JSON. It performs no provisioning or writes.

Portable tests cover DS/LDS lifecycles, class/transport/NC rejection, strict atomic
deltas, unknown flags, readback failures, no-op properties, 100000-reference bounds,
structural DN equivalence and cancellation. Host-only WinLDAP loopback tests cover
actual atomic Modify/control encoding, terminal/partial ranged reads, native error
details and allocation cleanup. They do not establish directory parity. Live
multi-site AD DS/AD LDS writes, PowerShell differential outcomes, permissions and
supported Server 2016/2019/2022/2025 versions remain qualification work for #34.

## Primary references

- [MS-ADTS connection objects](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d6cca73b-9696-4700-9dab-7c4e54502960)
- [MS-ADTS site-link objects](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f148e965-e4d7-413a-acfc-0e9a9e591708)
- [MS-ADTS site-link bridges](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fd3ad099-c18c-46f2-b638-526657133577)
- [Replication interval constraints](https://learn.microsoft.com/en-us/windows/win32/adschema/a-replinterval)
- [Microsoft .NET site-link defaults and constraints](https://github.com/dotnet/runtime/blob/main/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/ActiveDirectorySiteLink.cs)
- [Microsoft .NET separate connection schedule/ownership properties](https://github.com/dotnet/runtime/blob/main/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/ReplicationConnection.cs)
- [Set-ADReplicationSiteLink](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adreplicationsitelink?view=windowsserver2025-ps)
- [Set-ADReplicationConnection](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adreplicationconnection?view=windowsserver2025-ps)
