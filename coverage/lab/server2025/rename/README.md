# Rename qualification

Run `rename-20261117T084557Z` passed on 2026-11-17 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result.

Advances **3 scenario states** of `Rename-ADObject`:
`rdn-rename-and-collision`, `identity-forms-and-scope` and
`capability-errors-and-resource-lifetime`.

Rename is the one mutating role the other sweeps cannot reach. The lifecycle
and capability harnesses drive create, update and delete per object class, and
a rename is none of those — so `Rename-ADObject` sat at zero while the other
fifteen mutating operations advanced.

## The GUID claim is the load-bearing one

| | observed |
| --- | --- |
| `objectGUID` across a rename | **unchanged** |
| relative name | moved |
| parent | kept |
| old distinguished name | no longer resolves |
| new distinguished name | resolves |
| an unrelated attribute | survived |

A provider tracks a renamed resource by GUID. Had a rename produced a new one,
the old entry would look deleted and the renamed object would look new — a
destroy-and-recreate of a resource nobody asked to replace. This is the single
observation a rename resource is built on, so it is measured rather than
assumed.

## Names that need escaping

Two relative names were requested as literal values and read back as the same
literal value: `sdkrn\,esc+plus`, whose comma and plus are DN metacharacters
and must survive escaping intact, and one carrying non-ASCII text with a
supplementary-plane character. A rename is the operation where a name becomes
part of a distinguished name, so an escaping bug here corrupts the address of
the object rather than one of its attributes.

## Collision

A rename onto a relative name already taken in the same container was refused
as `already-exists` with **LDAP status 68**, and the object's distinguished
name and `uSNChanged` were both unchanged afterwards. `uSNChanged` is the
witness: it advances on any write the directory accepts, so an unchanged value
is the directory's own statement that nothing was written.

## Identity forms

Renamed successfully addressed by distinguished name and by GUID — the two
forms the generic object path documents. The security-identifier and
account-name forms were refused as `unsupported` rather than resolved by
guesswork, and a documented form naming a partition that does not hold the
object was refused as `invalid-request` having written nothing.

## Resource lifetime

Three renames completed on one session, each to a fresh name: renaming an
object to the name it already carries is not a repeat and would measure
nothing. A failure was then raised **after native resources had been taken**,
by resolving a name inside the real domain that no object carries — which
submits a genuine search and returns `LDAP status 32`. The allocation counters
returned to zero on both that path and the success path, and `Close` returned
nil both times it was called.

That probe is deliberately not an out-of-partition name. See the note in
`../write-capability/README.md` — a name in a partition the server does not
hold is refused by a client-side scope check before any native call, so the
balance after it proves nothing.

## What this is not

`full_ticket_complete` is `false`. **No variant state advances.**

`authentication-and-permissions` is **not** claimed: it needs the restricted
credential fixture, which the write-authentication harness owns.

The unsupported directory is the same in-process loopback fixture used by the
write-capability sweep, not a real AD LDS instance.
