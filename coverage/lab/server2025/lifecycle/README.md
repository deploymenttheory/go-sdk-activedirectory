# Mutation lifecycle qualification

Run `lifecycle-20261115T071749Z` passed on 2026-11-15 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result.

This is the first evidence on the **write** surface. It takes the five object
classes a caller would model as resources through create, update and delete,
and advances 22 scenario states:

| Scenario | Operations |
| --- | --- |
| `creation-defaults-and-readback` | `New-ADUser`, `New-ADGroup`, `New-ADComputer`, `New-ADOrganizationalUnit`, `New-ADObject` |
| `attribute-update-intent` | the five `Set-` operations |
| `instance-update-semantics` | the five `Set-` operations |
| `object-deletion-and-reference-constraints` | the five `Remove-` operations |
| `recursive-delete-boundary` | `Remove-ADOrganizationalUnit`, `Remove-ADObject` |

The scenario is claimed only where the behaviour was actually exercised. The
update scenarios are **not** claimed for the `New-` operations: the harness
creates with naming inputs alone, so it never observed creating with attributes
or from an instance template.

## What passed

Both halves of every scenario, for all five classes, each on its own fixtures
and each leaving its native allocation counters at zero.

| | Success | Failure |
| --- | --- | --- |
| create | verified, in the requested container, with the requested class and a stable identity | the same name again → `already-exists`, leaving exactly one object |
| update (raw) | set, add, remove and clear on a multi-valued extension attribute, with an unrelated value still present afterwards | an attribute the schema does not define → `invalid-request`, writing neither it **nor the valid change submitted beside it** |
| update (typed) | changed only its own attribute; an omitted one stayed absent; a concurrent unrelated change survived | a stale `uSNChanged` precondition → `unsupported`, writing nothing |
| delete | leaf deleted, absence proved by a read | a second delete reporting `not-found`; a protected organizational unit's first delete refused |
| recursive | container and child both removed | non-leaf delete refused with the child intact |

The stale precondition reports `unsupported` rather than `conflict` because
this server does not advertise RFC 4528. Both are accepted: what the scenario
requires is that the write does not land, and it did not.

## It found three defects before it passed

The first three runs failed. That is the point of the harness, and each failure
was a real defect rather than a harness artifact:

1. **An organizational unit could not be unprotected** (#146, fixed in #147).
   `ouACLProtection` refused to read past object ACEs, and a real DACL — in
   storage order rather than canonical order — begins with them. A protected OU
   therefore could not be deleted at all.
2. **A duplicate name reported as `uncertain` through the user and computer
   creation paths**, because those joined their stage-incomplete sentinel even
   when the first write was cleanly rejected with nothing written. The
   group, organizational-unit and generic-object paths reported
   `already-exists` for the identical condition, which is how it was spotted.
3. **LDAP status 16 classified as `unclassified`.** The classification table
   named no attribute-level codes, so an undefined attribute fell through to
   generic handling.

## What this is not

`full_ticket_complete` is `false` in both artifacts, and **no variant state
advances.** 253 variant states remain at `unverified` across the whole
contract, and the per-parameter evidence those require is untouched here.

The remaining scenarios on these sixteen operations are untouched too:
`authentication-and-permissions`, `capability-errors-and-resource-lifetime`,
`endpoint-and-partition` and `explicit-go-invocation` are cross-cutting and
qualified only on the read surface so far; the property-specific ones
(`protection-acl-preservation`, `group-scope-category-transitions`,
`spn-multivalue-constraints`, `password-enable-creation-order`,
`computer-name-and-domain-join-boundary`, `rdn-rename-and-collision`,
`schema-class-and-container`) were not exercised.

## Cleanup is witnessed independently

Every fixture lives under one container the harness also removes, and absence is
proved by a read rather than inferred from a delete returning no error.

`collector-run.json` is a second witness, because a harness that wrongly
believed it had cleaned up would say so unchallenged: after the harness exits,
`scripts/lab/reference-lifecycle.ps1` searches the domain subtree through the
ActiveDirectory module for anything under the harness's fixture naming. The run
passes only if that search finds nothing live. It also refuses to start when a
root from the same run identity already exists, so an earlier failed attempt's
leavings cannot be read as this run's.

`live_leftovers` is empty. `deleted_object_remnants` lists the deleted-object
entries of this and earlier runs, which are recorded rather than treated as
cleanup failures — a delete leaves one by design.

## Attribute choice

The raw update scenarios use `extensionName`: multi-valued, Unicode string
syntax, available on all five classes, and part of no typed projection — the
"raw extension attribute" the scenario asks for.

`description` was the obvious first choice and is wrong. Its schema says
`isSingleValued=False`, but AD DS enforces a single value on `user`, `group`
and `computer` regardless. The reference module reports *"Multiple values were
specified for an attribute that can have only one value"* and the server
returns LDAP 20, so add and multi-value replace cannot be observed there at
all. It is also a typed property on four of the five classes, so a two-value
write additionally breaks the typed readback with `attribute description has
invalid syntax or cardinality`. Measured across all five classes before
switching.
