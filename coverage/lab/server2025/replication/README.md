# Replication diagnostics reference and differential

Captured on 2026-11-13 from the isolated two-DC/member Hyper-V profile on H:
(`ad.sdk.test`, run `replication-20261113T204033Z`). Local execution, not a CI
result.

Both files are read-only. `scripts/lab/reference-replication.ps1` in its
`Before` phase reads partner metadata, replication failures and queued
operations from each controller and writes nothing to the directory.

| Property | Observed value |
| --- | --- |
| Servers | `adsdk25dc1.ad.sdk.test`, `adsdk25dc2.ad.sdk.test` |
| Client computer | `ADSDK25MEM` |
| Domain | `ad.sdk.test` |

## What passed

`reference-before.json` has `passed: true` and holds one record per controller,
each with that server's partners, failures, queue and read errors.

`native-before.json` is the SDK side, produced by `TestReplicationDiagnosticsLab`
in the same run. It has `passed: true` with the matching records. The
differential refuses to run unless three pins agree: the reference's SHA-256,
the run identity, and the SHA-256 of the **test binary itself**, which the
collector records before it writes. So the comparison cannot be satisfied by a
reference from a different run or a differently built binary.

The SDK record carries one field the reference does not, `queue_started`, which
is the SDK's own observation of when it began reading the queue rather than a
value read from the directory.

## What this is not

Both artifacts record `full_ticket_complete: false`, and **no coverage state
advances on these files.**

This is a success-path projection comparison: two healthy controllers were read
and the SDK agreed with the module. The coverage contract requires passing
evidence for *both* the `/success` and `/failure` identifier of every variant
and scenario, and nothing here observes a denied identity, an unreachable
partner, or a cancelled read. The `After` and `Compare` phases, which would
observe a replication actually converging, were not run.

What it does establish is that the SDK's projection of partner metadata,
failures and queued operations equals the module's on this pair, rather than
merely resembling it.
