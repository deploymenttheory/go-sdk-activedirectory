# Directory projection reference harness

This opt-in harness compares the implemented #27 projection slice with the
ActiveDirectory module on an isolated fixture. It does not qualify the complete
ticket. No live reference run has been performed for this implementation.
Ordinary `go test ./...` skips `TestDirectoryProjectionLab`.

The entry points are [test-directory.ps1](../scripts/lab/test-directory.ps1),
[reference-directory.ps1](../scripts/lab/reference-directory.ps1), and the
[native test](../integration_directory_windows_test.go). They do not provision,
start, stop, join, or otherwise operate VMs. They do not create, repair, reset,
remove or reconfigure directory objects or trusts.

## Live-run prerequisites

1. Review and integrate the required connection/search development changes.
   This branch currently incorporates #11 at `5799c70` and #12 at `2255df4`.
   Search `89d0adb` has an unchanged public Search seam and is awaiting integration
   review; it was inspected, not merged here. A clean committed checkout is
   required for preparation, with Go 1.25+, Git, and the pinned bindings available
   to the Go module cache or download mechanism.
2. Use an existing, isolated AD DS fixture with a recorded provisioning identity.
   Supply its domain GUID, explicit DC FQDN, selected execution computer, and
   fixture identifier. The target must expose LDAP 389 and ADWS for the
   PowerShell reference cmdlets. Current Negotiate authentication is used by both
   processes. This harness does not qualify explicit credentials, TLS/Basic, or
   LDS behavior.
3. Run the prepared bundle on the named Windows amd64/arm64 fixture computer
   with Windows PowerShell 5.1 and the ActiveDirectory module installed. The
   current identity must be able to read the selected domain, configuration and
   schema objects. Go/Git are unnecessary on this execution computer when using
   the prepare/run split.
4. Select a profile whose fixtures are actually present:

   | Profile | Positive requirements |
   | --- | --- |
   | `core` | A readable domain/forest and at least one DC. Empty trust results qualify only an empty collection. |
   | `topology` | Core plus an RODC, a GC and a non-GC in the selected domain, and at least two forest domains. |
   | `trust` | Core plus a named external AD trust, an allowlisted partner endpoint/domain GUID, and successful secure-channel verification for each configured trust direction. |
   | `extended` | Both topology and trust requirements. |

5. For trust profiles, install `netdom.exe` from the AD DS/RSAT tools, use an
   elevated execution session, and provide an identity with sufficient rights on
   both domains. The harness runs `netdom trust <trusting> /Domain:<trusted>
   /Verify` for each configured direction, with a 60-second bound per process.
   It never supplies passwords on the command line or invokes repair options.
   Netdom can select its own DC: this verifies the domain relationship and is
   recorded separately from the explicitly pinned LDAP observations. Microsoft
   documents `/verify` as verification of the trust's secure-channel secrets.
   [Netdom trust](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netdom-trust).
6. Keep the fixture stable while the reference and SDK reads run. Reads are
   sequential and can observe replication/topology changes. Repeat and diagnose
   a mismatch rather than treating the two outputs as an atomic snapshot.

## Fixture manifest and ownership

The fixture manifest must come from the approved provisioning record. Its JSON
schema is deliberately restricted; arbitrary extra fields and credentials are
rejected. `trust_partners` is an array even when empty. Replace the example GUIDs
with the actual provisioned identities:

```json
{
  "schema_version": 1,
  "purpose": "go-sdk-activedirectory-isolated-lab",
  "fixture_id": "server2025-controlled-fixture-id",
  "domain_dns": "ad.sdk.test",
  "domain_guid": "11111111-1111-1111-1111-111111111111",
  "server": "dc1.ad.sdk.test",
  "client_computer": "ADSDK-MEMBER",
  "server_version": "2025",
  "trust_partners": [
    {
      "dns_name": "partner.sdk.test",
      "server": "dc1.partner.sdk.test",
      "domain_guid": "22222222-2222-2222-2222-222222222222"
    }
  ]
}
```

The collector matches the local CIM computer name, source RootDSE hostname,
source domain GUID/DNS name, and any selected partner's endpoint/domain identity
before verification. It records actual local OS/module information. The
`server_version` value is a label; the DC's directory-reported OS is retained
separately and is not independent proof of its running OS. The parent lab run
must retain ownership-checked, actual source-DC OS/build/architecture evidence.

These checks prevent accidental scope changes. A supplied manifest or receipt
does not prove ownership or provenance. Retain the approved provisioning record,
transfer record and source-DC environment evidence alongside the resulting
hashes. Hashes establish which bytes were used, not who authorized or created
them. The native test explicitly reports `reference_provenance_verified=false`.

Use an existing artifact directory writable only by the test operator. Each run
gets a new random name and `owner.json`. Paths cannot traverse reparse points;
reference/native artifacts use exclusive creation, and prepared runs are single
use. The harness never deletes prior artifacts. If a run fails, retain it and
prepare a new bundle. A process timeout fails the run. The harness bounds and
waits for its own child processes; it does not verify descendant-process cleanup
and always records `process_tree_cleanup_verified=false`.

## Prepare on the build host

Place the artifact root outside the checkout or in its ignored `tmp` directory.
Preparation requires a clean checkout and copies the root package's Go files,
module pins and exact harness scripts into the owned run. It compiles a native
test executable with `-mod=readonly`, records hashes and the toolchain, and makes
no AD connection:

```powershell
.\scripts\lab\test-directory.ps1 `
  -FixtureManifest C:\ad-sdk-validation\fixture.json `
  -ArtifactRoot C:\ad-sdk-validation\results `
  -Profile core -Architecture amd64 -PrepareOnly
```

For the other profiles, change `-Profile`; trust/extended also require
`-TrustPartner partner.sdk.test`. Omitting `-PrepareOnly` builds and executes on
the same computer, which must then meet both build and live-run prerequisites.

Use the lab owner's established transfer mechanism to copy the entire prepared
run directory to the named execution computer. Preserve its directory name,
source snapshot, scripts, binary, fixture and preparation/owner files. No
transfer or VM operation is performed by this harness.

## Execute the prepared bundle

On the named execution computer, invoke the script retained inside that bundle:

```powershell
& C:\ad-sdk-validation\directory-<run-id>\harness\test-directory.ps1 `
  -PreparedRun C:\ad-sdk-validation\directory-<run-id>
```

The runner verifies the owner, fixture, source, harness and binary hashes before
collecting reference data. Trust profiles execute actual verification in this
run; they do not accept an externally supplied "verified" receipt as a substitute.
It then launches only `TestDirectoryProjectionLab`, supplying the reference hash
and run identity. The native test uses shared public APIs, checks paged and
identity reads, GC/RODC criteria, post-filter limits, trust property selections,
configured GC versus connected GC readiness, and native cleanup balances.

The final `manifest.json` records pass/fail, phase, input/artifact hashes and
process exit statuses. `reference.json` retains the allowlisted reference facts,
actual trust verification statuses and collector environment. `native.json`
retains allowlisted observed facts, named checks, mismatch keys, numeric LDAP
statuses and cleanup counts. Raw LDAP maps, trust authentication fields and
Netdom output are not serialized. Logs and source snapshots remain in the owned
run for review. PowerShell reference facts tagged `.schema` use supplementary
attribute reads; they do not establish derived cmdlet-property parity.

Every profile reports `full_ticket_complete=false`. The collector and comparison
must both pass, and the lab owner must assess fixture/OS/provenance evidence
before importing any scenario-specific results.

## Local validation and remaining work

Run the offline harness checks with Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\scripts\lab\test-directory-harness.ps1
go test -mod=readonly ./...
go vet ./...
```

Offline tests mock all AD reads and trust execution. They exercise manifest and
artifact ownership rejection, hash tampering, fresh-file behavior, quoting and
bounded local child processes, allowlist conversion, reference selection, and
failure-artifact retention. They do not constitute live evidence.

The [full #27 acceptance boundary](discovery.md#remaining-acceptance-boundary)
still applies: complete identities, semantic filter languages, property/range
handling, Current verification, trust InputObject/scope/LDS probes, locator
behavior, permissions, transport variants, and version/native architecture
matrices remain. #13 is currently blocked by open #12. #13/#14/#15 remain shared
implementation seams; #27's recorded native dependency is still closed #9.
