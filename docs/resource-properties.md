# Resource properties, property lists and value types

`ResourceProperty`, `ResourceProperties`, `ResourcePropertyList`,
`ResourcePropertyLists`, `ResourceValueType` and `ResourceValueTypes` read the
AD DS configuration naming context. `CreateResourceProperty`,
`UpdateResourceProperty`, `DeleteResourceProperty`,
`CreateResourcePropertyList`, `UpdateResourcePropertyList`,
`DeleteResourcePropertyList`, `AddResourcePropertyListMembers` and
`RemoveResourcePropertyListMembers` use native asynchronous LDAP writes.
Runtime PowerShell, AD Web Services and an installed agent are not required.
Native execution supports Windows amd64 and arm64; portable input validation
and models build elsewhere.

These APIs require AD DS with the Windows Server 2012 claims schema and the
Claims Configuration containers installed by forest preparation. AD LDS and
Global Catalog endpoints are rejected. Explicit partitions must match the
configuration naming context.

## Three classes, three containers

| Class | Container | Writable |
| --- | --- | --- |
| `msDS-ResourceProperty` | `CN=Resource Properties` | yes |
| `msDS-ResourcePropertyList` | `CN=Resource Property Lists` | yes |
| `msDS-ValueType` | `CN=Value Types` | **read-only** |

Each object must have the expected class **and** that container as its direct
parent. The right class in the wrong container is out of scope, not a near
match, and a different class inside the right container is rejected.

Value types are read-only because the reference exposes only
`Get-ADResourcePropertyValueType` — no create, update or delete. This SDK does
not invent one.

## The value type is settled, not stated

`CreateResourcePropertyRequest.ValueType` is a `SchemaReference` naming an
`msDS-ValueType` object by identity or by explicit name — exactly one, never
both and never neither. That object's `msDS-ClaimValueType` settles the
property's value type, and it is written to `msDS-ValueTypeReference`.

**An update cannot change it.** The reference exposes no parameter for the
value type on `Set-ADResourceProperty`, so a property keeps the value type it
was created with, and suggested values on update are encoded for the type the
property already stores.

Reading one property with `IncludeValueType` resolves the referenced object and
reports it in `ValueTypeObservation`. If the property's own stored
`msDS-ClaimValueType` disagrees with the object it references, that is reported
as an error rather than reconciled — the directory is authoritative for both,
and a disagreement is a fact worth surfacing.

## Shared values and claim types

`SharesValuesWith` references a claim type whose possible values the property
shares, stored in `msDS-ClaimSharesPossibleValuesWith`. The reference is
resolved and verified to be a claim type in the Claim Types container, so a
property can never share values with an arbitrary object.

This is the forward edge of the backlink that
[claim types](claim-types.md) reads when refusing to delete a referenced claim
type: a resource property pointing here is exactly what makes
`ErrClaimTypeReferenced` fire.

## Suggested values

`SuggestedValues` is encoded into `msDS-ClaimPossibleValues` for the settled
value type, using the same encoder as claim types: integer sources use
`IntegerList`, unsigned `UnsignedIntegerList`, and string, FQBN, SID and
octet-string sources `StringList`. A suggestion must carry exactly one typed
value; a mistyped suggestion is rejected rather than coerced.

`RestrictValues` maps to `msDS-ClaimIsValueSpaceRestricted` and `IsSecured` to
`msDS-IsUsedAsResourceSecurityAttribute`. Both are written only from their
typed fields; neither is inferred from the presence of suggested values.

## Applies-to resource types

`AppliesToResourceTypes` maps to `msDS-AppliesToResourceTypes`. Entries are
validated before any write: an empty entry, directory-hostile text, or a
duplicate — including one differing only by case — is rejected, because the
directory would otherwise be asked to store the same value twice.

On update the list **adds** by default and replaces only when
`ReplaceAppliesToResourceTypes` is set, so a caller chooses between extending
and rewriting rather than relying on a default.

## List membership

`AddResourcePropertyListMembers` and `RemoveResourcePropertyListMembers` edit
`msDS-MembersOfResourcePropertyList` in one LDAP modify. Every member is
resolved and verified to be a resource property in its own container, so a list
cannot reference an arbitrary object. Duplicates within one request are
rejected. Membership is bounded by `ResourcePropertyListMemberLimit`; exceeding
it is an error rather than a truncated write, and the existing count is read
first so an add cannot cross the bound unnoticed.

The membership before and after the write are both reported. Reading a list
retrieves members through the shared bounded reference reader, so a large list
is either complete or reported incomplete — never silently truncated.

Removing members never deletes the properties themselves, and deleting a list
never deletes the properties it referenced.

## Updates and deletion

Nil and zero fields are left alone; each `Clear` flag conflicts with a stated
value for the same field. `Changes` carries additional raw attribute changes,
but changes naming the name, the value-type reference, the shared-values link,
the applies-to list, the member list, the possible values, the restricted flag,
the secured flag or the security descriptor are rejected, because a raw write
to those would bypass value-type settlement and container verification.

Deletes submit one native leaf delete. A property still referenced by a list is
the directory's own referential concern and its refusal is surfaced unchanged.

## Limits

Local tests cover managed-attribute rejection, applies-to validation including
case duplicates, update contradictions, add-versus-replace semantics, container
and class scoping for all three classes, membership bounds and typed decoding.
**No live qualification is implied**: these operations remain `unverified` in
the coverage report until evidence from a recorded server and module build
exists.
