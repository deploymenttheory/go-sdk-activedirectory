# Directory projection reference capture

Captured on 2026-11-13 from the isolated two-DC/member Hyper-V profile on H:
(`ad.sdk.test`, lab `60197892-ec9f-4c19-abe8-34dc60d473e5`). These are local
executions, not CI results.

`scripts/lab/reference-directory.ps1` is read-only: every directory call is a
`Get-AD*` and no mutation gate is passed. The owned disposable domain was
unchanged by this capture.

| Property | Observed value |
| --- | --- |
| Source endpoint | `ADSDK25DC1.ad.sdk.test` |
| Client computer | `ADSDK25MEM` |
| Domain / forest | `ad.sdk.test`, single domain, no trusts |
| Domain GUID | `01bfaea4-bebb-4df8-8d90-19f567f08878` |
| Configuration GUID | `1520a013-8129-440d-bd33-58f717c6e6b5` |
| AD module | 1.0.1.0 |
| Topology | Two writable GC/DCs and one member; private switch |

## What passed

`reference-core.json` has `passed: true`. It records the connected server DN and
GC readiness, the domain identity (DN, GUID and SID in binary form, NetBIOS,
forest, allowed suffixes, subrefs, FSMO holders, writability, functional level),
the eight well-known domain containers by GUID, the forest projection (schema
and naming contexts, domains, sites, global catalogs, functional level), and per
controller the server/DSA/computer DNs, host, site, GC and read-only flags, OS
and build, held roles, and the server/DSA/invocation GUIDs with the DSA
behaviour version.

## What the lab cannot satisfy

`reference-topology-unmet.json` has `passed: false` with a
`RuntimeException`. The `topology` profile asserts its own prerequisites before
collecting:

> Topology profile requires an RODC, GC/non-GC controllers and multiple domains.

This profile is **structurally unsatisfiable on this lab**, which runs two
writable global-catalog controllers in a single domain with no read-only
controller. The artifact is kept as the record of an unmet prerequisite rather
than a defect. Satisfying it needs a richer forest: an RODC, at least one
non-GC controller, and a second domain. The `trust` and `extended` profiles are
likewise blocked, as they need a trust partner this lab has none of.

## The SDK differential

`differential-core.json` is the SDK side, produced by
`TestDirectoryProjectionLab` in the same owned run. It pins
`reference-core.json` by SHA-256 before reading it, dials the same endpoint
natively on port 389, and compares the SDK's own projection against the
reference fact by fact.

| Property | Observed value |
| --- | --- |
| Result | `passed: true` |
| Checks | 18, all passed, 0 mismatches |
| Facts compared | 75 |
| Native allocations remaining | all zero (messages, controls, cookies, values, names, cursors) |
| Runtime | windows/amd64 on `ADSDK25MEM` |
| Reference SHA-256 | `ed9713f9aeaf97a22952ff11f50dbebf5be20fcc08a54ff42cc5ca13c26600fd` |

The committed `reference-core.json` is byte-identical to the file that hash was
computed over, and its `run_id` matches the differential's, so the pair is
internally consistent.

`reference_provenance_verified` is `false` by design: the test deliberately
never starts PowerShell or verifies a collection receipt's provenance.

## What this is not

Every artifact here records `full_ticket_complete: false`, and **no coverage
state advances on these files.**

The differential exercises the **success path only** — it reads a healthy
domain, forest and controller set and confirms agreement. The coverage contract
requires each variant and behavioural scenario to carry passing evidence for
*both* its `/success` and its `/failure` test identifier. Nothing here observes
a denied identity, an unreachable endpoint, a bad identity form or a cancelled
request, so no variant or scenario is satisfied yet.

What this does establish is that the SDK's native projection of domain, forest
and controller state is not merely plausible but equal to the module's across
75 facts, with no leaked native allocations.
