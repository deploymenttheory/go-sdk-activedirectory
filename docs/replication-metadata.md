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

The consistency USN detects changes to the object. Operational vector updates
can occur without changing the NC root object's USN, so it does not establish
an atomic vector snapshot; qualify vector reads on a quiescent fixture.

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

The remaining live qualification matrix covers isolated multi-DC Server
2016/2019/2022/2025 and applicable AD LDS fixtures, with the server and AD module
versions recorded. Compare after externally controlled attribute writes, member
add/remove/re-add, replication convergence, tombstone reads, nonexistent NCs,
and restricted identities. Compare originating USNs across DCs, but compare
local USNs only with the reference from the same DC. Run arm64 native tests on
an arm64 Windows host; cross-compilation alone is not runtime qualification.
No live matrix or full PowerShell parity is claimed by this implementation.

### Recorded Server 2025 read-only smoke

Run `metadata-smoke-20261113T005856Z-6a68e6cf` passed on 2026-11-13 at
00:59 UTC. DC2 ran the collector and Windows amd64 SDK test against
`ADSDK25DC1.ad.sdk.test:389`, reading the existing `DC=ad,DC=sdk,DC=test`
root. One `objectClass` replication stamp and two NC vector entries matched
PowerShell exactly, including counters, invocation IDs, source DNs and timestamps.
Both DCs reported Server 2025 Standard Evaluation `10.0.26100`, UBR `32230`,
ActiveDirectory module `1.0.1.0`, Windows PowerShell `5.1.26100.7462`, and UTC.
The collector and SDK used the same current domain administrator identity.

All seven native allocation counters were zero for both reads. The host receipt
records five completed and removed jobs, terminal success, and no guest
uncertainty. No fixture writes or replication triggers were performed. The
tested source is **`e2c7d396c41b6dde62fd946312e91e1bf39f810d`**, built with Go
`1.26.5 windows/amd64`; this record does not qualify later revisions or additional
cases. Native records retain `FullTicketComplete: false` and
`ProvenanceVerified: false`; the separate host receipt records the build and
capture hashes.

The committed proof subset preserves original bytes:

- [Qualification receipt](../coverage/lab/server2025/replication/metadata-smoke/qualification.json) and [build manifest](../coverage/lab/server2025/replication/metadata-smoke/build.json).
- [DC1 inventory](../coverage/lab/server2025/replication/metadata-smoke/source_environment.json) and [DC2 inventory](../coverage/lab/server2025/replication/metadata-smoke/runner_environment.json).
- [Attribute reference](../coverage/lab/server2025/replication/metadata-smoke/attributes-reference.json) and [native result](../coverage/lab/server2025/replication/metadata-smoke/attributes-native.json).
- [Vector reference](../coverage/lab/server2025/replication/metadata-smoke/vectors-reference.json) and [native result](../coverage/lab/server2025/replication/metadata-smoke/vectors-native.json).

Controlled writes and convergence, linked-value add/remove/re-add, deleted
objects, missing partitions, restricted identities, scoped enumeration,
AD LDS, other server versions, and Windows arm64 runtime remain unqualified
by this smoke. No binaries or source archive are included in this proof subset.

### Opt-in differential read

On an existing isolated Windows fixture, run the reference collector and test
as the same Windows identity. Supply the actual server version from the fixture
inventory; it is recorded as caller-supplied, not automatically attested. Freeze
fixture changes between reference collection and the SDK read. Background
replication can legitimately advance a watermark, so a mismatch requires
inspection and a fresh stable observation; the harness never retries writes.

```powershell
./scripts/lab/collect-replication-metadata.ps1 -Server dc1.ad.sdk.test `
  -ServerVersion 'Windows Server 2022 10.0.20348' -RunID run-001 `
  -FixtureID owned-metadata-fixture -Phase after-member-remove `
  -ObjectDN 'CN=MetadataGroup,OU=Lab,DC=ad,DC=sdk,DC=test' `
  -Properties description,member -IncludeLinkedValues -IncludeDeletedObjects `
  -OutputPath C:\Lab\metadata-reference.json
$env:ADSDK_METADATA_REFERENCE = 'C:\Lab\metadata-reference.json'
$env:ADSDK_METADATA_REFERENCE_SHA256 = (Get-FileHash $env:ADSDK_METADATA_REFERENCE -Algorithm SHA256).Hash
$env:ADSDK_METADATA_RUN_ID = 'run-001'
$env:ADSDK_METADATA_RESULT = 'C:\Lab\metadata-native.json'
go test . -run '^TestReplicationMetadataReferenceLab$' -count=1 -v
```

Use `-PartitionDN` in place of `-ObjectDN` for a vector reference. Each invocation
targets one explicit server, object or NC, and phase; repeat against each DC
before/after the fixture owner performs controlled writes and waits for
replication. Attribute comparisons include exact decimal USNs, invocation ID,
version, change time, source DN, and per-link value/create/delete distinctions.
Vector comparisons include invocation ID, watermark, last-success timestamp,
and source DN. The collector fails if required reference properties are absent.
The SDK's raw linked value bytes are retained but not compared to PowerShell's
schema-converted `AttributeValue`; the DN component is compared.

For a missing partition/object, use `-ExpectedOutcome failure
-ExpectedLDAPCodes 32`; for an explicitly denied fixture use the appropriate
native code, commonly `50`. The reference must also fail. Use
`-ExpectedOutcome unavailable` only for a prepared fixture that returns an empty
reference collection; the SDK must retain its incomplete/uncertain outcome.
Restricted-identity collection and testing run under that same identity;
credentials are not included in artifacts. Both output paths must be fresh.

The test records native allocation counts, versions, phase, reference hash,
runtime architecture, results and failure status. Hash equality binds the input
bytes; it does not establish provenance or qualify the full ticket. The harness
does not provision fixtures, authenticate inventory provenance, trigger
replication, or launch PowerShell from Go. AD LDS cases require an AD module
environment that supports the reference operation, otherwise record the
reference limitation separately. The recorded smoke above covers only its two
successful reads; the other live scenarios remain pending.
