# Write capability and resource-lifetime qualification

Run `writecap-20261117T084600Z` passed on 2026-11-17 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result.

Advances **15 scenario states** of `capability-errors-and-resource-lifetime`
on the write surface.

## Resource lifetime, against the real directory

This is the half a long-running caller depends on, and all of it is observable:

| | |
| --- | --- |
| repeated use of one session | each operation completed **three times** |
| a failure after native resources were taken | a parent or target named inside the real domain that no object carries, which submits a genuine search and returns `LDAP status 32` |
| allocations released on both paths | counters back at **0/0**, success and failure |
| close idempotent | `Close` twice returned nil both times — on the owning client as well as every per-operation session |
| no replay of a submitted write | see below |

Three separate objects are used for the repeat, not three identical requests:
repeating an identical create is a duplicate rather than a repeat, so it would
measure nothing.

**No replay** is observed through an add of a single value. A replayed
submission would collide with the value its first submission wrote and be
refused as already present, so the add succeeding *is* the observation that
nothing was submitted twice. That matters because the scenario's stated
expectation is that uncertain mutations are not replayed, and a replayed write
is the one failure mode a caller cannot clean up after.

## The capability half, and why it is credited strictly

Each operation was issued against an in-process loopback LDAP fixture
advertising no `supportedCapabilities`, read by real WinLDAP over a real
socket. Each was refused by a directory-type check **before any write could be
submitted**.

Only an unmistakable refusal is credited — `DirectoryCapabilityError`,
`ErrUnsupportedDirectory` or `ErrUserCapability`. A bare `ErrUnsupported` is
deliberately **not** credited: the fixture cannot answer a write, so a path
with no directory-type prerequisite would proceed to a write and fail there,
and a bare `ErrUnsupported` is equally what that produces. Crediting it would
manufacture a capability observation out of an unrelated failure.

The harness therefore determines the prerequisite by observation rather than
assumption, and records any operation it cannot credit as having none — which
is how the read-side sweep recorded and excluded `Get-ADObject`.

In the event every operation was credited. Reading the source beforehand
suggested only the user and computer paths carried a prerequisite; the
measurement found that **every mutating path checks the directory type**, with
`DirectoryCapabilityError` from all of them except `New-ADUser`, which produces
`ErrUserCapability`. The stricter rule cost nothing and would have caught the
opposite result.

## What this is not

`full_ticket_complete` is `false` in both artifacts, and **no variant state
advances.**

**`Rename-ADObject` is not covered by this harness.** It sweeps create,
update and delete per class and does not exercise the rename role, so 15 of
the 16 mutating operations are claimed here. The rename role is measured
separately in `../rename/`.

The unsupported directory is a loopback fixture, not a real AD LDS instance.
A refusal from it establishes that the prerequisite is checked and actionable;
it does not establish how each operation behaves against a real directory of
another type, which remains part of #56.

## Correction to the first publication of this evidence

As first published, the failure-after-acquisition probe named a parent or
target in a **naming context this server does not hold**. The SDK refuses that
by a client-side scope check before any native call is made, so no allocation
was ever taken and `allocations_remaining_after_failure: 0` was trivially
true — it held because nothing had been allocated, not because what was
allocated had been released. All fifteen operations shared the defect.

The probe now names an object inside the real domain that does not exist,
which submits a genuine search and returns `LDAP status 32`. The fifteen
operations pass as before, and the release claim now rests on an observation
that could have failed. The artifacts in this directory are from that re-run.
