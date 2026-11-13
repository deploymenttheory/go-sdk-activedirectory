# Replication diagnostics

The draft implementation for issue #36 adds `ResolveReplicationTargets`,
`ReadReplicationPartners`, `ReadReplicationFailures`, and
`ReadReplicationQueue`. Each call accepts `Config` and a typed query. Windows
amd64/arm64 use WinLDAP and NTDSAPI through go-bindings-win32; there is no
PowerShell, RSAT, or remote-agent runtime dependency.

```go
config := ad.Config{Endpoint: ad.Endpoint{Host: "dc1.example.test"}}
result, err := ad.ReadReplicationFailures(ctx, config, ad.ReplicationFailureQuery{
    Selection: ad.ReplicationSelection{Scope: ad.ReplicationScopeForest},
})
// Inspect err and result.Complete. Successful server/category observations
// remain in result.Servers even when another server or category failed.
```

Run `go run ./examples/replication -server dc1.example.test -kind failures
-scope domain` on Windows using the current Windows identity.

## Selection and result contracts

Server scope uses the supplied endpoint list, or `Config.Endpoint` by default.
Domain, forest and site scopes resolve DCs through the anchor's authenticated
AD DS configuration topology, then query each target independently. Explicit
domain/forest names must belong to that topology. Site selection spans the
forest, not just the anchor's domain. Resolution never follows trusts or LDAP
referrals. Discovered DCs use standard LDAP/LDAPS ports; the anchor's custom
port is not propagated to unrelated hosts. AD LDS supports server scope and
uses its `dsServiceName` object's GUID to select the RPC instance.

Inbound neighbors, connection failures, link failures and queued operations
use documented `DsReplicaGetInfo2W` information types. Successful native
zero-count arrays are confirmed empty results. Outbound partners use the
documented RootDSE `msDS-ReplAllOutboundNeighbors`, or the selected NC's
`msDS-NCReplOutboundNeighbors`. Ranges continue on one connection, validating
their indices and counts. Gaps, resets, omitted values and failures preserve
partial rows and raw responses with an incomplete error. Sequential ranges,
LDAP and RPC calls do not form an atomic snapshot.

An omitted outbound value cannot distinguish empty, denied or unavailable
information. It remains incomplete even if the server advertises support.
`Requested`, `Available`, and `Complete` distinguish unrequested categories,
observed partial data, and finished reads. Errors retain native Win32/RPC or
LDAP codes and are reachable through `errors.Is`/`errors.As`; they are excluded
from automatic JSON serialization. The runnable example prints the aggregate
error separately while still emitting partial result JSON.

GUIDs, signed USNs, unknown flags and operation numbers are preserved.
Timestamp values retain original FILETIME ticks; nil ticks mean unreported,
while reported zero ticks have no UTC event. A connection failure's time is
its first failure; a link failure's time is its last successful replication.
A failure row with result code zero means the specific code is unavailable.
Outbound metadata describes notification delivery and does not invent
inbound-only invocation, transport or USN fields. Missing XML fields remain
nil. The native queue retains array order and the current-operation timestamp.

## Authentication, lifetime and pending work

Current-identity and explicit-password Negotiate use the documented native
credential owner. Explicit credentials are converted directly from mutable
UTF-8 bytes into pinned UTF-16 buffers, then those temporary buffers are erased
after native credential creation. The caller's password bytes are unchanged.
Unbind precedes native credential release on success and query failure. An
explicit username requires either `Credentials.Domain` or a fully qualified
name such as a UPN; the SDK never substitutes the current identity when an
explicit credential fails. Outbound-only LDAP uses the existing `Config`
authentication support.

This draft pins the reviewed, published upstream companion commit
`ca210d257ae4872da3179563da9c0b211934a6b1` through normal `go.mod`/`go.sum`
resolution (`v0.6.1-0.20261113002110-ca210d257ae4`).
[Upstream PR #74](https://github.com/deploymenttheory/go-bindings-win32/pull/74)
is pending merge; refresh this immutable pin to the merged commit or release
before marking the SDK PR ready. There is no local replace or syscall shim.

RPC reads require Negotiate; Simple-over-TLS is rejected for RPC operations.
`Config.Transport` protects LDAP and does not select an RPC TLS transport.
Native buffers are copied before the matching free; unbind precedes releasing
an explicit native credential owner. Cancellation is checked between native
calls, and `DsBindingSetTimeout` bounds calls on an established binding. The
initial synchronous native bind has no documented context-cancellation or
timeout parameter and must return before cleanup/cancellation completes.

Portable unit tests and Windows host tests cover scope selection, malformed
and missing data, range continuation, partial multi-server/category failures,
native allocation ownership, cancellation and failed cleanup. They are not
live AD DS/AD LDS qualification. The native integration and PowerShell
differential harness below are prepared; actual healthy/unavailable/queued/
permission fixtures and Server 2016/2019/2022/2025 plus applicable LDS evidence
remain open acceptance work. Issue #36 is not complete or qualified by this draft.

See [the primary-source contract research](research/replication-diagnostics-contract.md)
for API, permission, timestamp and platform details.

## Read-only Server 2025 pair check

`TestReplicationDiagnosticsLab` and `scripts/lab/reference-replication.ps1`
collect the existing `ADSDK25DC1.ad.sdk.test` / `ADSDK25DC2.ad.sdk.test` pair.
They perform reads only, using the current Windows identity. The native test
uses the public SDK; only the independent reference requires RSAT. There are
no VM actions, fixture changes, child-process launch helpers or credentials in
the artifacts. Ordinary `go test ./...` skips the live test.

On the already authorized fixture computer, use its existing directory fixture
manifest (the schema consumed by `Read-DirectoryFixture`), an existing artifact
directory, and a native test binary built with `go test -c` from the reviewed
clean commit. The caller must retain the committed source/build hash proof;
the observations label `source_provenance_verified=false` because a supplied
commit string alone does not prove a binary's source. Replace the variables
below with those pinned paths and the reviewed 40-hex commit:

```powershell
$ErrorActionPreference='Stop'
$FixtureManifest = 'C:\owned-lab\fixture.json'
$ArtifactRoot = 'C:\owned-lab\results'
$NativeBinary = 'C:\owned-lab\replication.test.exe'
$SDKRevision = '<reviewed 40-hex commit>'
. .\scripts\lab\replication-reference.ps1
$fixture = Read-DirectoryFixture $FixtureManifest
$fixtureHash = (Get-FileHash -LiteralPath $FixtureManifest -Algorithm SHA256).Hash
$run = New-DirectoryRun $ArtifactRoot $fixture.fixture_id $fixtureHash
$peer = 'adsdk25dc2.ad.sdk.test' # fixture.server is adsdk25dc1.ad.sdk.test
$arguments = @{FixtureManifest=$FixtureManifest; RunDirectory=$run.Path; RunID=$run.ID;
    SDKRevision=$SDKRevision; BinarySHA256=(Get-FileHash $NativeBinary -Algorithm SHA256).Hash; Peer=$peer}
& .\scripts\lab\reference-replication.ps1 @arguments -Phase Before
$saved = @{}
foreach ($name in @('ADSDK_REPLICATION_REFERENCE','ADSDK_REPLICATION_REFERENCE_SHA256','ADSDK_REPLICATION_RUN_ID')) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $env:ADSDK_REPLICATION_REFERENCE = Join-Path $run.Path 'replication-before.json'
    $env:ADSDK_REPLICATION_REFERENCE_SHA256 = (Get-FileHash $env:ADSDK_REPLICATION_REFERENCE -Algorithm SHA256).Hash
    $env:ADSDK_REPLICATION_RUN_ID = $run.ID
    & $NativeBinary '-test.run=^TestReplicationDiagnosticsLab$' '-test.v' '-test.timeout=8m'
    if ($LASTEXITCODE -ne 0) {throw 'Native collection failed; retain its artifact and stop this run.'}
} finally {
    foreach ($name in $saved.Keys) {[Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')}
}
& .\scripts\lab\reference-replication.ps1 @arguments -Phase After
& .\scripts\lab\reference-replication.ps1 @arguments -Phase Compare
```

Run the phases serially and only after confirmed native process completion.
Native bind cancellation remains subject to the API limitation above. Each
phase creates a fresh file; reruns use a new owned run directory. The native
test verifies the before-file and binary hashes, collector identity, and both
DC/domain GUIDs before reading diagnostics. Reference reads explicitly name
their endpoints and suppress implicit AD-drive creation.

Comparison requires positive inbound and outbound partners on both DCs;
matches partition/partner IDs, DNs, addresses and inbound invocation IDs;
brackets native FILETIME/USN values between reference observations; and requires
healthy zero status/counters and successful empty failure lists. Queue rows,
when stable across all three reads, compare IDs, priority, operation, option
bits, identities and enqueue times. A changing queue fails comparison and needs
a separate controlled observation. The reference queue cmdlet's default scope
is retained; empty healthy queues do not establish nonempty all-partition parity.
Query-dependent partition GUIDs, raw flags, the native current-operation header
and inbound-only outbound fields are recorded or explicitly excluded from parity.

Offline validation is `go test ./...` plus
`powershell.exe -NoProfile -File scripts/lab/test-replication-reference.ps1`
and the equivalent `pwsh` command. Tests reject missing/duplicate rows, changed
IDs/status/USNs/times/queue bits, failed categories, foreign pins and misordered
observations. The pair check does not complete #36: unavailable partners,
controlled nonempty queues, partial multi-server failures, ordinary-identity
permission behavior, explicit-password live authentication, domain/forest/site
live scope resolution, AD LDS and the other supported versions remain pending.
