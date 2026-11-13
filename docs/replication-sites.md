# Replication sites, subnets and server placement

The `Client` exposes typed site/subnet lifecycle operations and a directory-server
site move. They use the authenticated endpoint's configuration naming context,
existing identity/filter/value APIs and native WinLDAP writes. AD DS and AD LDS
are supported where the schema applies. GC endpoints are rejected for AD DS;
an AD LDS instance using the same custom port remains distinct. No PowerShell,
RSAT or remote agent is required by the SDK.

`ReplicationSite` accepts a site DN/GUID and reads the site, its NTDS Site
Settings, server children and associated subnets. `ReplicationSites` lists site
object projections; it does not silently fetch the topology for every row.
`ReplicationSubnet` and `ReplicationSubnets` return typed prefix, location,
description and site-link values. Search methods intersect raw or typed filters
with their class and fix scope to the corresponding configuration container's
direct children. Paging, result limits and errors retain the `SearchResult`
contract. Missing fields stay nil; raw data and partial observations survive
failures. Site reads reuse `ForestSite`; move observations reuse `ControllerReplica`.

Create subnets with an explicit `netip.Prefix`. Both IPv4 and IPv6 are accepted;
host bits, IPv4-mapped IPv6, invalid prefixes and zones are rejected instead of
silently masking them. Canonical `Prefix.String()` becomes the subnet's CN.
Duplicate definitions and stricter server constraints retain native LDAP errors.
Overlapping networks are not duplicates and are not rejected locally. An optional
site identity is resolved explicitly in the same configuration; omitted means an
unassigned subnet. Update changes the association with `Site` or removes it with
`ClearSite`. The native Modify is atomic across the selected attributes. Clearing
an attribute can return Accepted but unverified when it disappears from readback,
because omission also occurs under restricted visibility. Deletion is a leaf
delete, with no site or server deletion side effect. Microsoft documents this
surface in [New-ADReplicationSubnet](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adreplicationsubnet?view=windowsserver2025-ps).

`CreateReplicationSite` creates the site, NTDS Site Settings, Servers container,
and an AD DS-only Licensing Site Settings child. Each Add has its own retained
`ReplicationTopologyStep`. A later failure leaves accepted earlier stages in
place; the SDK performs no automatic rollback or replay. This follows the object
construction used by [Microsoft's ActiveDirectorySite implementation](https://github.com/dotnet/runtime/blob/main/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/ActiveDirectorySite.cs).
The complete workflow shares one `Config.Timeout` budget. An existing name is not
treated as permission to repair or overwrite a partially created site.

`UpdateReplicationSite` has separate site-property and NTDS Site Settings stages.
The settings patch supports a schedule, explicit schedule removal, an ISTG DSA
identity in that site, an AD DS group-caching refresh site, and typed option masks.
`SetOptions`/`ClearOptions` preserve unselected and unknown flags. A strict
delete-old/add-new pair changes `options` atomically and rejects conflicting
concurrent changes. The flags map to [NTDS Site Settings options](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d300c652-8873-41a4-a50c-90cc89d5bdd8),
including topology generation, cleanup, minimum hops, stale detection, caching,
bridgehead selection, hashing, redundant topology and legacy KCC behavior. AD LDS
rejects requests to enable universal-group caching or set its refresh site.
Creation cannot select an ISTG in a not-yet-existing site; move a server first,
then set its NTDS Settings identity. No KCC task is triggered by the client.

`ReplicationSchedule` is a UTC `[7][24][4]bool` week starting Sunday. It encodes
one 188-byte interval schedule; zero enables no slots. Nil omits a setting and
does not imply an all-open default. Malformed or unsupported raw schedules remain
available alongside decoding errors. The [SCHEDULE layout](https://learn.microsoft.com/en-us/windows/win32/api/schedule/ns-schedule-schedule)
and [header](https://learn.microsoft.com/en-us/windows/win32/api/schedule/ns-schedule-schedule_header)
define the wire container. The header page has contradictory bit-order prose;
the SDK uses quarter bits 1, 2, 4, 8, matching [Microsoft's schedule serializer](https://github.com/dotnet/runtime/blob/main/src/libraries/System.DirectoryServices/src/System/DirectoryServices/ActiveDirectory/ActiveDirectorySchedule.cs)
and 672 offline checks against the installed Windows implementation. No automatic
local-time or daylight-saving conversion is applied. The reference module exposes
local-time schedules, so compare normalized wire bytes, not displayed clock times.

`DeleteReplicationSite` refuses configured servers, linked subnets and unknown
descendants. It deletes the Servers container first, then other recognized
administrative children by GUID with leaf deletes, followed by the site. A hidden
or new server therefore rejects cleanup before site settings are removed.
New children cause server rejection rather than
being recursively removed. Preflight visibility and concurrent changes cannot be
made atomic across these objects; inspect retained child/link observations and
each stage. A protected site returns the native access error; protection is never
removed. Site ACL/protection editing is outside this API, and no PowerShell
protection default is imported. Site/subnet deletion does not rewrite site links.

`MoveDirectoryServer` accepts a configuration server or NTDS Settings DN/GUID
and an explicit destination site. Computer-account identities are rejected. It
resolves both sites and the destination Servers container, then uses
[`ldap_rename_extW` with NewParent](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_rename_extw)
to move the server subtree within that configuration. It verifies the original
server and NTDS Settings GUIDs, destination-site GUID/class/placement, and AD DS
computer reference after acceptance. AD LDS does not require a computer link.
The domain computer account, replication connections and services are not
separately moved or restarted. AD maintains linked-DN relationships; KCC/DNS
convergence is asynchronous and is not proved by this readback. This is the
topology operation described by [Move-ADDirectoryServer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/move-addirectoryserver?view=windowsserver2025-ps).

Inspect `State`, `Verified`, raw preflight/readback candidates and every returned
error. An accepted write survives failed verification. Unknown outcomes retire
the session without retry. Same-site moves return `NoChange` with
`ObjectWriteNotAttempted`. `ExpectedVersion` guards the server object for a move,
even when the supplied identity is its NTDS Settings child. Site updates use
`Options.ExpectedVersion` for the site and `SettingsExpectedVersion` for its
different settings object. Creation, multistep site deletion and paths submitting
no guarded request reject version assertions. A supported critical assertion
control is required. Cross-object link and parent checks remain preflight/readback
observations rather than transactions.

The example reads by default:

```powershell
go run ./examples/replication-sites -server dc.example.test -operation sites
go run ./examples/replication-sites -server dc.example.test -operation subnets
go run ./examples/replication-sites -server dc.example.test -operation site -dn 'CN=Branch,CN=Sites,CN=Configuration,DC=example,DC=test'
```

Writes require `-apply`. It supports `create-site -name Branch`,
`create-subnet -prefix 192.0.2.0/24 -site-dn ...`, `set-subnet-site -dn ...
-site-dn ...`, `set-site-description -dn ... -description ...`, `delete-site`,
`delete-subnet`, and `move-server -dn <server-or-DSA-DN> -site-dn ...`.
The example prints observations even when an error follows an accepted write.

Portable tests cover IPv4/IPv6, duplicate definitions, staged failures, nonempty
sites, unknown option bits, cancellation budgets, no-op preconditions and malformed
related readbacks. Host-only Windows tests drive actual WinLDAP Unicode NewParent,
assertion controls, schedule binary values, native errors and allocation cleanup.
`scripts/reference-replication-schedule-local.ps1` performs only local conversion.
`scripts/reference-replication-sites.ps1` is a read-only collector for independently
owned multi-site fixtures. Live DS/LDS lifecycle, permissions, protected/nonempty
deletion, linked topology changes, multi-site placement and version-specific
PowerShell comparison remain pending. This implementation does not close #33.
