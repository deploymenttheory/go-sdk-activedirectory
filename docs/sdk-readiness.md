# SDK v1 readiness

The v1.0.0 release gate defines when the SDK is ready to build a Terraform
provider over its entire approved surface: all 151 operation equivalents.
These criteria were agreed on 2026-11-17. **The gate has not been met.** This
document defines the required evidence; it does not qualify new behavior.

The [coverage contract](coverage-guide.md) remains the source of operation,
scenario, variant, and parameter claims. The [glossary](../GLOSSARY.md) defines
these terms. The [qualification decision](adr/0001-qualify-the-full-operation-and-version-matrix.md)
and [compatibility decision](adr/0002-release-v1-with-a-public-compatibility-baseline.md)
record the reasons for this gate.

## Qualification scope

| Dimension | Required for v1 readiness |
| --- | --- |
| Operations | All 151 approved operation equivalents, including read, discovery, host-local, and mutating behavior where applicable |
| AD DS versions | Windows Server 2016, 2019, 2022, and 2025; full applicable evidence on each version |
| Claims | Every applicable behavioral scenario, parameter-set success/failure case, and parameter claim |
| Topology | The domains, roles, functional levels, credentials, and member hosts needed to exercise each claim |
| Architecture | Live Windows amd64 qualification; arm64 compilation and portable logic checks, with runtime qualification explicitly pending |
| AD LDS | Outside the initial v1 readiness guarantee; existing applicability records and implementation remain tracked |

Determine applicability for each claim and version. A version-specific feature
requires success evidence where supported and evidence of a clear refusal where
unsupported. A skipped test, unavailable fixture, or missing permission leaves
a gap; it does not establish unsupported behavior. Record the reason and evidence
for every exclusion. Older-version smoke tests cannot substitute for the full
applicable matrix, and Server 2025 evidence cannot qualify another version.

Retain the current per-parameter evidence bar. A validated variant needs its
success/failure IDs and evidence for every parameter in the set, plus
parameters absent from all syntax sets as required by the validator. Shell
conventions need evidence of the documented Go equivalent or intentional
difference. Shared runs may cover several claims only when each claimed behavior
was actually observed. Local-only cases may use the contract's explicit
not-applicable environment convention, but cannot establish live AD behavior.

## Behavioral acceptance

SDK-level acceptance tests must demonstrate the following for each applicable
operation and supported version. Building a Terraform provider is not part of
this gate.

- **Repeatable lifecycle:** create, read, update, import through stable identity,
  and delete mutable resources. Refresh and reconcile an already-satisfied
  resource repeatedly without unexplained drift or unnecessary writes. Account
  for directory defaults and normalization explicitly; repeating a deliberately
  non-idempotent action is not the definition of reconciliation.
- **Identity and observations:** retain stable object identity through rename
  and other applicable transitions. Read and discovery results distinguish
  complete, partial, absent, unloaded, and inaccessible observations as relevant;
  omissions cannot silently become empty values or proof of deletion.
- **Failures and partial outcomes:** exercise refusals, accepted changes with
  failed readback, and interrupted or uncertain writes. Preserve available
  identity, observations, and outcome information, including partial effects in
  staged or multi-target operations. Error classification alone does not prove
  the recovery path.
- **Reconciliation:** demonstrate how subsequent reads establish what happened
  and what remains before a caller chooses another write. Automate this wherever
  observation permits it. Blind retry or automatic rollback cannot stand in for
  reconciliation. Where an operation has no resource lifecycle, exercise its
  applicable read, transition, or host-local observation contract instead.

An inherently unprovable outcome can meet readiness only with accurate
classification, retained observations, an evidenced limitation, and a documented
read or operator-assisted recovery path. Document what the caller can conclude,
what it cannot conclude, and when it must stop writing. Missing implementation
or missing tests do not qualify as inherent limits.

For example, an accepted attribute clear can remain `ErrObjectUnverifiable`
because omission is also consistent with denied visibility. Qualification must
independently observe the effect where permissions allow it and exercise the
limited-visibility case; the verification limit must remain explicit to the caller.
A contradictory readback remains distinct from an unprovable one, as described
in [error classification](errors.md) and [object mutations](directory-objects.md).

## Evidence register and release checklist

Readiness review requires a separate claim-by-version evidence register in
addition to the inventory's aggregate states. Maintain the register here as
qualification proceeds, with one row per operation, claim ID, and Server version.
For each row record:

- the existing scenario, variant, or parameter test ID, or the named lifecycle
  or recovery acceptance case;
- applicability and its rationale, including evidence of unsupported refusal;
- links to the implementation, passing evidence JSON, raw result, and collector
  run, with actual server build, directory/functional-level configuration,
  module version, host architecture, and tested source or binary provenance;
- the observed outcome, documented limits and recovery steps, and any unresolved
  gap or owning delivery ticket.

Keep this register separate from the inventory JSON schema. Reuse existing test
IDs and versioned artifacts; do not manufacture passing evidence from test names
or promote coverage states through documentation. Apply the current collector
and paired qualification-logic-test requirements, including independent fixture
cleanup verification, described in the [handoff](coverage-handoff.md).

The exhaustive register is outstanding. Until the retained evidence is audited
against individual claims and versions, the readiness gap remains open. A
historical passing reference run cannot fill every cell for its Server version.

Release review must complete every item:

- [ ] Every applicable claim has passing evidence on all four Server versions;
  unsupported cells have evidenced refusals and documented reasons.
- [ ] Every applicable lifecycle, repeated no-change cycle, identity/import,
  read-completeness, failure, and reconciliation case has evidence.
- [ ] Every accepted observation limit has evidence and a caller recovery path;
  no unexplained drift or unresolved behavior contradicts a readiness claim.
- [ ] Windows amd64 live qualification and arm64 compilation/portable logic
  checks pass; arm64 runtime and AD LDS qualification limits are published.
- [ ] The coverage contract validates and its generated report is in sync;
  the separate version matrix has been reviewed in full.
- [ ] The public compatibility baseline and remaining platform/observation
  limits are published with the v1.0.0 release.

`go run ./cmd/adcoverage` checks the inventory, required evidence IDs, provenance
fields, local implementation paths, and generated report. It does **not** enforce
this four-version matrix, repeated reconciliation, or the v1 release checklist.
Even a fully validated aggregate report requires the separate readiness review.

## Current gaps and delivery

As of 2026-11-17, the inventory records **178 of 1,070 behavioral scenarios**
validated and **0 of 253 parameter-set variants** validated. The published
report has **0 of 151 operations validated** because operation status takes the
least advanced scenario or variant. These are aggregate counts, not four-version
readiness results.

| Gate | Remaining evidence or work |
| --- | --- |
| Full claim-by-version matrix | Audit existing artifacts and populate the register; all 253 variants still need qualification |
| Behavioral coverage | Qualify the remaining scenarios and map already-qualified scenarios to their actual Server versions |
| Lifecycle and recovery | Map existing tests to every applicable acceptance case above; fill gaps in repeated no-change and interrupted-write reconciliation |
| API behavior | Resolve or explicitly bound open issues such as DN normalization (#157), uncertainty reporting (#140), and overloaded unsupported errors (#135) before accepting affected claims |
| Platform qualification | Complete all applicable four-version amd64 claims and record arm64 compilation/portable-check evidence and runtime limits |
| Compatibility | Review and publish the complete public baseline when the gate passes; no v1 stability claim is made today |

Continue the scenario burn-down order in the handoff, starting with the 14
remaining account-property states. Variant policy is now settled; variant
qualification remains later in that order. File discovered interface gaps as
remaining readiness work rather than changing public interfaces in this
documentation change. Tickets stay open until their required evidence is
accepted. Raise future lab commands in PowerShell and wait for approval.

Release v1.0.0 only after all readiness gates pass. Its compatibility baseline
covers the public interfaces expressing all 151 operation equivalents, including
request/result types, identity and value semantics, error/outcome contracts, and
documented recovery behavior. Subsequent breaking public interface changes
require a major version. Existing APIs remain provisional until that release.
