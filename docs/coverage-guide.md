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
applicability, parameter variants, and acceptance-test IDs. Multiple owning
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

A command's reported status is the least advanced of its parameter variants.
An implementation must not claim full coverage by implementing only Identity
while omitting Filter or LDAPFilter.

Each variant has success/failure scenario IDs. Each parameter has a distinct
scenario ID, allowing meaningful parameter-driven behavior to be audited even
when it shares a PowerShell parameter set. Add more IDs for combinations such as
cross-domain moves, gMSA versus dMSA, and policy transition failure recovery.

For validated variants, evidence must cover all variant tests and each parameter
in that variant. Parameters absent from all syntax sets require evidence too.
Store evidence as repository-local JSON and reference it in `evidence` at the
variant or operation level:

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

Native feasibility gaps remain open: standalone MSA reset, MSA readiness
equivalence, and dMSA migration recovery require their dedicated evidence gates.

PowerShell remains a provisioning/reference-test tool, never an SDK runtime
dependency. The headless expression API is an intentional replacement for the
interactive editor, not a claim of identical GUI behavior.
