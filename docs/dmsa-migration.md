# Delegated managed service account migration

`StartServiceAccountMigration`, `CompleteServiceAccountMigration`,
`UndoServiceAccountMigration` and `ResetServiceAccountMigration` link a
delegated managed service account (dMSA) to the account it supersedes and move
that pair through a small state machine. They mirror
`Start`/`Complete`/`Undo`/`Reset-ADServiceAccountMigration` (issues #51, #52,
#53).

These use native asynchronous LDAP writes against the explicit endpoint you
configure. Runtime PowerShell, AD Web Services and an installed agent are not
required. AD DS only; the delegated account must have the
`msDS-DelegatedManagedServiceAccount` class.

Note that `ServiceAccount` and its create/update/delete operations
deliberately **reject** delegated accounts — they cover sMSA and gMSA only.
Migration is this separate surface.

## The state machine

The expected end state of each transition is the contract already encoded in
`internal/dmsareference` (`CheckPhase`), which is what live qualification
asserts.

| Transition | From | dMSA state | Superseded state | Links |
| --- | --- | ---: | ---: | --- |
| Start | clean pair | 1 | 1 | both forward links set |
| Complete | started | 2 | 2 | unchanged |
| Undo | completed | 1 | 1 | unchanged |
| Undo | started | 0 | cleared | **all four absent** |
| Reset | started or completed | 0 | cleared | **all four absent** |

Completing also **disables the superseded account** and **removes its service
principal names**, which is part of the observed end state rather than an
addition by this SDK.

Undo steps back exactly one stage; Reset clears from either live state. There
is a deliberate asymmetry: undoing a *completed* migration returns to started
and keeps the links, while undoing a *started* one unlinks the pair.

### What Undo does not do

Undoing a completed migration does **not** re-enable the superseded account or
restore its service principal names. The reference contract does not require
it, so this SDK does not invent that restoration. If you need the account
usable again, re-enable it explicitly through the account-control API.

## States are read, never assumed

Every transition is decided from what the directory holds, after observing both
accounts. `State` is nil when the attribute was not returned — which is not the
same as state 0 and is never silently treated as it, though both behave as
`MigrationNone` when deciding a transition. An unrecognised stored value is
reported as `unknown(n)` rather than mapped onto a known state.

A transition whose preconditions do not hold is `ErrServiceAccountMigrationState`
and **nothing is written**. Starting in particular requires a genuinely clean
pair: re-starting a live migration could repoint a link away from an account
mid-transfer.

## Both links must agree

`ErrServiceAccountMigrationPaired` means the two accounts do not reference each
other. A one-sided link is not treated as linked, because completing or undoing
it could join two unrelated migrations.

Only the **forward** links are written. `msDS-ManagedAccountPrecededByLinkBL`
and `msDS-SupersededManagedAccountLinkBL` are system-maintained backlinks
(`linkID` 2225 and 2223); clearing a forward link clears its backlink. They are
read for observation and never written.

The `msDS-DelegatedMSAState` attribute is mandatory on the dMSA class, so
clearing it means writing zero rather than removing it. The superseded state is
optional and is removed.

## Partial failure

**Two objects are written and the directory offers no cross-object atomicity
for them.** The delegated account is written first, so a failure there leaves
the superseded account untouched.

If the first write succeeds and the second fails, the pair is inconsistent:
`Partial` is set and the error wraps `ErrServiceAccountMigrationPartial`.
**Nothing is compensated
automatically** — no write is replayed and no reverse write is attempted,
because a compensating write against an unknown state can make things worse.
Reconcile by reading the pair and choosing the transition explicitly; `Reset`
exists for exactly this.

Both accounts are addressed by GUID, so a rename between the read and the write
cannot redirect either modify.

## Limits

Local tests cover each transition's preconditions and rendered changes, the
undo asymmetry, the unlink contract, the paired-link requirement, flag
preservation when disabling, and the absent-versus-zero state distinction.

**No live qualification is implied.** These operations remain `unverified` in
the coverage report. Live evidence is gated behind a KDS root key whose
`msKds-CreateTime` must be at least ten hours old — `Add-KdsRootKey
-EffectiveTime` backdates only `msKds-UseStartTime`, so the gate cannot be
bypassed. `scripts/lab/reference-dmsa.ps1` captures all seven transitions once
the key qualifies; issue #79 owns that evidence.
