# Create-time attributes and instance qualification

Run `createattr-20261116T062837Z` passed on 2026-11-16 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result.

`attribute-update-intent` and `instance-update-semantics` are attached to the
`New-` operations as well as the `Set-` ones. The lifecycle sweep qualified only
the `Set-` halves, because it creates with naming inputs alone. This is the
create half, and it is the most-used write path there is: a caller declaring a
resource states its attributes and typed properties in the same breath as its
name.

Advances **9 scenario states**.

| Scenario | Operations |
| --- | --- |
| `attribute-update-intent` | all five `New-` operations |
| `instance-update-semantics` | `New-ADUser`, `New-ADGroup`, `New-ADComputer`, `New-ADOrganizationalUnit` |

## What passed

**`attribute-update-intent`.** A create carrying two explicit values of a
multi-valued extension attribute — one of them non-ASCII with a
supplementary-plane character — read back byte-exactly and verified. A create
carrying an attribute the schema does not define was refused as
`invalid-request` and created nothing, including not writing the valid
attribute submitted beside it.

**`instance-update-semantics`.** A create carrying a typed property set that
property and **only** that property, with the attribute the raw half uses left
absent. A typed property value carrying a NUL was refused as `invalid-request`
and created nothing.

"Created nothing" is observed, not assumed: the subsequent create of the same
name succeeded rather than being refused as a duplicate, which it would have
been had the refused create written.

## `instance-update-semantics` is not claimed for `New-ADObject`

The generic path exposes no typed property layer, so there is no typed instance
to exercise and no typed validation to refuse.

An earlier version of this harness built a shim that placed the value in the
raw attribute map and then demanded typed validation of it. The NUL passed
straight through — **correctly**, because `RawValue` is raw bytes by contract
and the generic path does not interpret values. That is the asymmetry worth
knowing: a caller on the generic path validates its own values; a caller using
typed properties gets `validDirectoryText` applied for it.

The scenario is left unclaimed for that operation rather than claimed on an
invented observation.

## What the create half cannot cover

A create has nothing to add to, remove from or clear, so the create half of
`attribute-update-intent` is necessarily narrower than the update half: it
covers an explicit multi-valued set, non-ASCII and supplementary-plane
preservation, and an invalid schema value.

Binary values at create time are **not** covered, because no writable binary
attribute is available on all five classes.

`full_ticket_complete` is `false` in both artifacts, and **no variant state
advances.**
