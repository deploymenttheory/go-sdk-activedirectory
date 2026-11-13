# Delegated managed service account migration captures

Captured on 2026-11-13 from the isolated two-DC/member Hyper-V profile on H:
(`ad.sdk.test`). Local execution, not a CI result. These are the **first live
observations** of the dMSA migration state machine in this lab: the capture was
blocked until now by the KDS root key's ten-hour creation-age gate.

## The gate

`Add-KdsRootKey -EffectiveTime` backdates only `msKds-UseStartTime`, not
`msKds-CreateTime`, so the ten-hour age cannot be bypassed. Read from the
directory immediately before this run:

| Attribute | Value |
| --- | --- |
| `msKds-CreateTime` | 2026-11-13 12:46:35Z |
| `msKds-UseStartTime` | 2026-11-13 01:46:35Z (backdated) |
| Eligible from | 2026-11-13 22:46:35Z |
| Capture started | 2026-11-13 22:48:17Z |

## Transition outcomes

All seven scenarios ran. Six transitions succeeded and one was refused.

| Scenario | Command | Outcome |
| --- | --- | --- |
| `start-unlinked` | `Start-ADServiceAccountMigration` | success |
| `complete-started` | `Complete-ADServiceAccountMigration` | success |
| `undo-started` | `Undo-ADServiceAccountMigration` | success |
| `undo-completed` | `Undo-ADServiceAccountMigration` | success |
| `reset-started` | `Reset-ADServiceAccountMigration` | success |
| `reset-completed` | `Reset-ADServiceAccountMigration` | success |
| `reset-unlinked` | `Reset-ADServiceAccountMigration` | **refused**, AD code 8224 |

The refusal is the expected reference behaviour, not a capture failure.
Resetting a pair that is not linked has no precondition to satisfy, and the
before/after snapshots confirm it **wrote nothing**: `msDS-DelegatedMSAState`,
`msDS-SupersededServiceAccountState`, all four link attributes,
`userAccountControl` and `servicePrincipalName` are byte-identical on both
accounts. That matches the contract this SDK documents — a transition whose
preconditions do not hold is an error and nothing is written.

## The assessor's verdict: evidence is incomplete

`cmd/addmsareference` assesses a retained bundle offline against
`internal/dmsareference`. It reports `status: incomplete` and
`evidence_complete: false` for **every** scenario, with 53–61 findings each:

| Finding | Count across all seven |
| --- | ---: |
| missing required populated observation | 161 |
| missing required minimal observation | 154 |
| unexplained or mismatched attribute effect | 39 |
| recovered artifact missing | 7 |
| service observations missing | 7 |
| credentials observations missing | 7 |
| service/credential interpretation not implemented | 7 |

The collector says the same of itself, in each run's own `unresolved` field:

> Initial minimal transition capture only; populated, permission,
> partial-failure and independent service/credential scenarios remain missing.

> Recovery has not been inferred or attempted.

> Accelerated lab observation; documented rollout …

So **no coverage state advances on these files**, and issues #51, #52, #53 and
#79 stay open. What this establishes is that the gate is passed and the seven
transitions are observable in this lab; what it does not establish is any of
the populated-account, service, credential, recovery or partial-failure
evidence the contract requires.

## Contents

Each `dmsa-<scenario>/` holds the run manifest (`run.json`, with SHA-256
provenance for the runner, capture script and environment), the `before`,
`after` and `replicated` snapshots, the recovery target, the owned-fixture
list, and the two cleanup snapshots.

Attribute values are recorded structurally, and no secret is present: the
replication metadata lists `unicodepwd` as a changed attribute *name* with its
version and originating USN, and its `value_key` is deliberately empty.
