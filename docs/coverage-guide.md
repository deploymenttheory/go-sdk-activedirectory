# Maintaining the operation contract

The SDK is under development. An operation appearing in the inventory is a plan,
not a claim that the SDK implements it.

Run from the repository root:

```sh
go test ./...
go run ./cmd/adcoverage
go run ./cmd/adcoverage -write
```

The first two commands are offline checks. The last regenerates the report after
validating the inventory. CI rejects a stale report.

## Source and ownership

`coverage/reference.json` pins Microsoft's documentation repository commit and
the SHA-256 of each source Markdown file. It records all 151 approved command
names, 253 parameter sets, and 1,756 distinct per-command parameter names. This is
a reference surface, not a verified description of every server version.

`coverage/inventory.json` maps each command to its GitHub delivery issue(s), a
planned Go service, proposed native mechanism, prerequisites, directory
applicability, parameter sets, behavioral scenarios, and acceptance-test IDs. Multiple owning
issues are intentional for shared operations such as managed account creation
and account policy/silo assignments. Test IDs are stable scenario identifiers;
they are not fabricated Go test functions or passing results.

All parameters are retained, including shell conventions such as Confirm,
WhatIf, and PassThru. Their acceptance cases must verify the documented Go
equivalent or intentional difference. Parameter names appearing only in source
documentation outside syntax remain tracked; discrepancies must be resolved
against the installed module rather than silently discarded.

Applicability is independent of implementation status. `unsupported` means the
reference explicitly excludes a directory type. `unverified` means further
investigation is needed, including where the docs mention AD LDS but do not
establish every parameter/schema combination. `documented` records applicability
supported by reviewed sources, not a passing runtime test.

## Advancing coverage

- `unverified`: planned work; no working implementation claim.
- `implemented`: a repository-local implementation file must exist.
- `validated`: the implementation and passing, versioned evidence must exist.

A command's reported status is the least advanced of its parameter sets **and
behavioral scenarios**.
An implementation must not claim full coverage by implementing only Identity
while omitting Filter or LDAPFilter.

Inventory schema version 2 separates syntax coverage from behavioral coverage.
The Microsoft reference schema remains version 1 because its documented surface
is unchanged. Legacy inventory files must be migrated before validation passes.

Each parameter set retains its success/failure IDs, and each parameter has a
distinct test ID. Every operation also has `scenarios`: named behaviors with a
description, relevant parameter names, fixture prerequisites, an expected
outcome, separate test IDs, and independent implementation/evidence state.
Scenario IDs cannot reuse parameter-set or individual-parameter test IDs.

`coverage/scenario-requirements.json` is the separately reviewed list of required
scenario names for every approved command. The validator requires an exact
match, so removing even one behavior (for example TTL membership) fails while
other scenarios remain. New or changed requirements need an explicit review of
this manifest alongside the behavioral definitions; ordinary report generation
does not rewrite it. Do not remove requirements to make partial implementations
pass. The critical workflow tests additionally preserve selected high-impact
transitions independently of the manifest.

The behavioral inventory includes same-partition DS/LDS moves, cross-domain
user/computer password preservation and RID-master checks, ten separate FSMO
role transfer/seizure cases, TTL and recursive memberships, RODC password-only
replication, sMSA/gMSA/dMSA differences, and distinct migration undo/reset states.
Shared scenarios cover authentication, scoped queries, attribute update intent,
permissions, and resource lifetime for each applicable operation.

For example, `Move-ADObject/behavior/cross-domain-user-password/success` requires
a two-domain fixture with both RID masters and post-move authentication proof.
Passing `Move-ADObject/parameter/TargetServer` alone cannot validate that behavior.
The generated report shows scenario counts, but counts and planned IDs are not
passing tests. Review expected outcomes against the owning delivery ticket and
pinned reference when adding or changing scenarios; a parameter-set name alone
cannot establish that behavioral coverage is complete.

For validated variants, evidence must cover all variant tests and each parameter
in that variant. Parameters absent from all syntax sets require evidence too.
Store evidence as repository-local JSON and reference it in `evidence` at the
variant, scenario, or operation level. A validated scenario must have a local
implementation and passing results for all its own IDs. Validating every syntax
set while leaving a behavior unverified leaves the command unverified:

```json
{
  "passed": true,
  "tests": ["Get-ADUser/identity/success", "Get-ADUser/parameter/Identity"],
  "server_version": "actual server build and functional level",
  "module_version": "actual installed ActiveDirectory module version",
  "host_version": "actual Windows build and architecture",
  "run": "durable CI run or retained lab-result reference"
}
```

This abbreviated example does not validate the whole Get-ADUser identity
variant. Supply results for all its required IDs. Local-only syntax tests may
use explicit `not applicable: local Windows syntax validation` environment
fields; they do not establish AD policy semantics or server compatibility.
Never commit credentials or directory secrets as evidence.

## Updating the pinned reference

Review the Microsoft source changes before updating the snapshot. Preserve the
approved names unless the operation scope is deliberately changed. Download the
command Markdown files from the selected commit's
`docset/winserver2025-ps/ActiveDirectory` directory, then run:

```sh
go run ./cmd/adreference -source /path/to/ActiveDirectory -commit FULL_COMMIT_SHA
```

The importer extracts SYNTAX sets and PARAMETERS headings and hashes the original
file bytes. It retains the existing approved command-name list. Reconcile additions,
removals, and parameter changes in the inventory, then regenerate the report.
Ordinary validation never fetches mutable upstream content.

## Comparing an installed module

The reference lab exports the installed command and parameter-set surface.
Compare a capture without changing the pinned contract:

```powershell
.\scripts\lab\compare-reference.ps1 -ModulePath .\coverage\lab\server2025\module.json
```

The [Server 2025 capture](../coverage/lab/server2025/README.md) contains all 151
commands and 253 parameter sets. Its 1,754 per-command parameter names differ
from the pinned documentation only in `New-ADDCCloneConfigFile`:
`PreferredWINSServer` and `AlternateWINSServer` are absent on build 26100.32230.
Keep those planned cases until their version-specific behavior is established.
Parameter-set display-name mappings are reported separately. A surface match
does not prove SDK implementation or semantic parity.

Native feasibility gaps remain open: standalone MSA reset, MSA readiness
equivalence, and dMSA migration recovery require their dedicated evidence gates.

PowerShell remains a provisioning/reference-test tool, never an SDK runtime
dependency. The headless expression API is an intentional replacement for the
interactive editor, not a claim of identical GUI behavior.
