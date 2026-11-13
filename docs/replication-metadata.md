# Replication attribute metadata and update vectors

`ReadReplicationAttributeMetadata` reads current attribute and linked-value
replication stamps. `ReadReplicationUpToDatenessVectors` reads each source
invocation's watermark for selected naming contexts. These read-only operations
use WinLDAP through the generated `go-bindings-win32` dependency, with the same
authentication and TLS configuration as `Dial`. They do not invoke PowerShell,
RSAT, ADWS, or an RPC credential adapter.

```powershell
go run ./examples/replicationmetadata -server dc1.example.test `
  -object 'CN=LabGroup,OU=Lab,DC=example,DC=test' -properties description,member -links
go run ./examples/replicationmetadata -server dc1.example.test `
  -partition 'DC=example,DC=test' -scope domain
```

The example uses the current Windows identity and signed/sealed Negotiate.
Runtime targets are Windows amd64 and arm64; requests, decoders, and tests are
portable. AD DS and AD LDS are accepted when the endpoint advertises their
capability. Domain/forest/site expansion requires AD DS topology. Use server
scope with an explicit port for AD LDS. Deployment support still requires the
live qualification matrix below.

## Targeting and result meaning

`ReplicationSelection` shares the resolver used by replication diagnostics.
Explicit server selections preserve failed servers. Topology discovery errors
and per-server failures are joined into the returned error. Inspect `Complete`,
each server's `Observation.Error`, and each requested collection's state before
using a result. Cancellation retains discovered but unvisited targets as failed.

`ObjectDN` is an exact distinguished name, including the current tombstone DN
for a deleted object. There is no GUID/SID/name resolution or PowerShell filter
language. `Properties` selects exact, case-insensitive LDAP attribute names;
empty or a single `*` selects all stamps. Filtering is applied after reading
the complete metadata collection. Nonlinked multivalued attributes have one
attribute stamp. `IncludeLinkedValues` adds a separate `LinkedValues` collection
with creation/deletion times, value DN, and unmodified binary value data.

`IncludeDeletedObjects` sends the critical show-deleted LDAP control.
`IncludeDeactivatedLinks` independently sends the critical show-deactivated-link
control and requires `IncludeLinkedValues`. Set both for the visibility requested
by PowerShell's `-IncludeDeletedObjects`; the example's `-deleted -links` does so.
The server must advertise the controls. Recycled objects, garbage-collected
links, and prior history already discarded by AD cannot be reconstructed.

Vector `PartitionDNs` selects explicit NC roots. An empty slice requests every
NC in each server's `namingContexts`; `Config.Partition` does not override this
explicit API contract. Missing partitions retain their LDAP error and do not
discard successful partitions. A non-root DN may return no constructed cursor
attribute; this is incomplete, not a confirmed empty vector.

USNs remain signed native 64-bit integers, invocation IDs preserve GUID identity,
and timestamps retain original 100 ns FILETIME ticks plus UTC. A zero timestamp
has nil UTC. Source/originating server fields contain reported nTDSDSA DNs;
nil denotes unreported data. The SDK does not invent DNS names. These are last
replication stamps and watermarks, not a chronological audit log.

Raw LDAP responses and returned range names remain in `Objects`. Ranges are read
on one connection under the client gate, with checked contiguous indexes and
stable `uSNChanged`; changes, malformed values, missing consistency tokens, or
the explicit 1,048,576 range bound return partial results and an error. Sequential
attribute/link/partition reads are not an atomic snapshot. Omitted or empty LDAP
metadata cannot distinguish no values from access filtering or unavailability;
it is reported as incomplete. All supported authentication and transport paths
retain native LDAP diagnostics and cleanup errors.

## Native contract

The [constructed metadata contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/21ea8133-4947-4409-bca8-4239723d3e6a)
maps `msDS-ReplAttributeMetaData`, `msDS-ReplValueMetaData`, and `msDS-NCReplCursors`
to the documented replication-info results. The SDK requests `;binary` and
decodes the protocol's little-endian packets, including bounds-checked offsets
and strict UTF-16. Wire layouts are independent of Go/C ABI padding:

- [DS_REPL_ATTR_META_DATA_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/63fabec7-cb4b-47ed-ab45-9a20e4397d55)
- [DS_REPL_VALUE_META_DATA_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5d421689-808b-466d-8d9f-106cda2dbcce)
- [DS_REPL_CURSOR_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/42f0e26e-7627-4e68-814c-afc35a2b5f62)
- [Show deactivated links](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/059e33fc-c7af-451e-92a9-fcb33d828f0f)

## Verification and remaining qualification

Portable tests cover exact counters, GUID byte order, zero/missing timestamps,
link distinctions, malformed offsets/UTF-16, range gaps/reset/change, filtering,
missing partitions, permission denials, cleanup errors, cancellation, and
partial results. Windows loopback tests exercise actual WinLDAP binary/range
reads, critical controls, native errors, and allocation cleanup. They do not
establish behavior against real AD or authentication policy.

Live qualification remains required on isolated multi-DC Server
2016/2019/2022/2025 and applicable AD LDS fixtures, with the server and AD module
versions recorded. Compare after externally controlled attribute writes, member
add/remove/re-add, replication convergence, tombstone reads, nonexistent NCs,
and restricted identities. Compare originating USNs across DCs, but compare
local USNs only with the reference from the same DC. Run arm64 native tests on
an arm64 Windows host; cross-compilation alone is not runtime qualification.
No live matrix or full PowerShell parity is claimed by this implementation.
