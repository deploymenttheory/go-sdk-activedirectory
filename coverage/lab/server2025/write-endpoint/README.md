# Write endpoint and partition qualification

Run `writeendpoint-20261115T105349Z` passed on 2026-11-15 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result.

`endpoint-and-partition` was already qualified on the read surface. This is the
write half, and the half that matters more: a read sent to the wrong partition
returns nothing, while a write sent to the wrong partition could change the
wrong directory.

All sixteen mutating operations pass, advancing 16 scenario states.

| Role | Operations |
| --- | --- |
| create | the five `New-` operations |
| update | the five `Set-` operations |
| delete | the five `Remove-` operations |
| rename | `Rename-ADObject` |

The harness reuses `lifecycleTargets()` rather than declaring its own table, so
the two mutating harnesses cannot drift apart on which operation does what.

## What passed

**Success.** Each write was submitted with an explicitly named server and an
explicitly named partition, succeeded, and the resulting object — or, for a
delete, the partition the SDK reported acting within — was inside that
partition. Accepting the options and honouring them are asserted separately,
because they are different claims.

**Failure.** The same write against the forest configuration naming context — a
real partition this server holds, which does not hold the target — was refused
in **both identity forms**, and wrote nothing.

| Identity form | Refusal | Why it differs |
| --- | --- | --- |
| distinguished name | `invalid-request` | the DN can be compared against the requested naming context without touching the directory, so the request is rejected outright |
| GUID | `not-found` | a GUID cannot be compared syntactically, so the SDK searches the requested partition alone and reports honestly that the object is not there |

Both forms are recorded and both are required, because the difference is
visible to a caller and the second one is easy to misread.

**`not-found` is the contract being honoured, not a defect.** The object does
exist — in the partition that holds it — and the SDK did not go and find it
there. A caller that treats not-found as "the object is gone" will misread a
misconfigured partition, which is worth knowing; but the alternative, silently
succeeding against another partition, is the failure this scenario exists to
rule out.

The harness rejects any other classification for either form. A denial or an
uncertain outcome would mean the write had been attempted somewhere.

## No write was observed for either refusal

Proved per role rather than assumed:

- **create** — the subsequent create succeeded rather than being refused as a
  duplicate, which it would have been had either refused create written.
- **update, delete, rename** — the target's `uSNChanged` was unchanged and the
  object still present. Any committed modification bumps that counter, so the
  check does not depend on the SDK's own accounting.

## Fixture root

An **organizational unit**, not a container. An `organizationalUnit` cannot be
created inside a `container` at all — the directory refuses it with LDAP 64 —
so a container root leaves the unit's own operations unobservable. The first run
of this harness used a container and `New-ADOrganizationalUnit` was the single
failing row, which is how that was found.

Cleanup is installed from whatever the fixture create reported, before any
decision about whether it succeeded, so a create that writes the object and
then fails cannot leak it.

## What this is not

`full_ticket_complete` is `false` in both artifacts, and **no variant state
advances.**

The scenario's other documented cases are not covered here: a custom port, an
unavailable endpoint, and a missing naming context. This run used one server on
port 389 and two partitions that both exist. The three remaining cross-cutting
scenarios on these sixteen operations — `authentication-and-permissions`,
`capability-errors-and-resource-lifetime` and `explicit-go-invocation` — are
qualified only on the read surface so far.
