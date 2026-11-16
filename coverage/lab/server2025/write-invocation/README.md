# Write explicit-go-invocation qualification

Run `writeinvoke-20261116T060018Z` passed on 2026-11-16 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result.

All sixteen mutating operations pass across **53 refused requests**, advancing
16 scenario states.

## What the scenario means for a write

`explicit-go-invocation` asks what replaces the shell's preview, confirmation
and pass-through conventions. For a read the answer is that the read itself
mutates nothing. For a write there is no preview at all, and the guarantee that
stands in for one is stronger and easier to check:

> A request is validated and its target resolved before anything is submitted,
> so an invalid call writes nothing.

That is the property a caller applying a bad configuration depends on. A
half-applied change is worse than a refused one.

The artifact records that mechanism explicitly rather than implying a `-WhatIf`
this SDK does not have.

## The refused shapes

| Shape | Roles |
| --- | --- |
| an empty name | create |
| a name carrying a NUL | create |
| a malformed partition | create, update, delete, rename |
| an expected version, which no create can guard | create |
| no changes at all | update |
| overlapping add and remove of one value | update |
| a zero identity | update, delete, rename |
| an empty relative name | rename |

Each had to be refused **as a request to correct**, or as something this
directory cannot perform. A denial, a conflict or an uncertain outcome is
rejected by the harness, because each of those would mean the call had reached
the directory and tried — the opposite of the claim.

## Nothing was written, observed rather than assumed

- **create** — the subsequent create succeeded rather than being refused as a
  duplicate, which it would have been had any refused create written. This
  needs no per-class knowledge, which matters: constructing the object's
  distinguished name to look for it directly would be wrong, because an
  organizational unit's relative name uses `ou=` rather than `cn=`.
- **update, delete, rename** — the target's `uSNChanged` was unchanged across
  the refused call. Any committed modification bumps that counter.

## The pass-through half

On success the documented typed result carried the object, its distinguished
name and its accepted write state without a pass-through flag being asked for.
That is what replaces `-PassThru`.

No prompt or confirmation hook exists to be invoked, and the artifact records
that as **absent** rather than as not-called: "no hook exists" and "the hook
was not called" are different observations.

## Two shapes that are not here, and why

**A zero `Parent` is not an invalid request.** It is a documented default —
it selects `Config.Partition` or the endpoint's default naming context. An
earlier version of this harness treated it as invalid, and the creates duly
succeeded into the default containers, outside the fixture root and therefore
outside its cleanup. Four objects were left in the lab and the collector
reported clean, because it was searching only for the fixture root.

Both halves of that are fixed: the shape is gone, and every collector now
searches for the objects a harness **names**, wherever they end up, not only
for where it intended to put them.

**A control character in a name is not invalid either.**
`validDirectoryText` rejects invalid UTF-8 and NUL, and nothing else. A `\x01`
name was accepted by four of the five creates — the computer path alone was
refused, server-side, with LDAP 80. The shape is a NUL, which is refused
client-side before anything is submitted.

## What this is not

`full_ticket_complete` is `false` in both artifacts, and **no variant state
advances.**

The refusal set is not exhaustive. It covers shapes every operation can
express; per-operation parameter validation is the variants' business, not this
scenario's. Two cross-cutting scenarios remain read-surface only on these
sixteen operations: `authentication-and-permissions` and
`capability-errors-and-resource-lifetime`.
