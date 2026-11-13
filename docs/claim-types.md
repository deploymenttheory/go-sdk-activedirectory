# Claim types

`ClaimType` and `ClaimTypes` read the AD DS configuration naming context.
`CreateClaimType`, `UpdateClaimType` and `DeleteClaimType` use native
asynchronous LDAP writes. Runtime PowerShell, AD Web Services and an installed
agent are not required. Native execution supports Windows amd64 and arm64;
portable input validation and models build on other platforms.

These APIs require AD DS with the Windows Server 2012 claims schema and the
`CN=Claim Types,CN=Claims Configuration,CN=Services` container installed by
forest preparation. They neither install that schema nor impose an invented
functional-level requirement. AD LDS and Global Catalog endpoints are rejected.
Explicit partitions must match the configuration naming context. DN/GUID
identities use the shared identity API; a claim type must have the
`msDS-ClaimType` class and that container as its direct parent. Search uses the
existing typed or raw LDAP filter and restricts the result to that container and
class. Configure an explicit writable LDAP endpoint and credentials with the
necessary read/create/write/delete or DACL permissions.

## Identifiers

A claim type's directory `name` is its claim identifier and must be an
`ad://ext/` value. `CreateClaimTypeRequest.ID` sets it explicitly; when nil the
SDK generates a conforming identifier from the display name plus random
entropy. The generated value is returned in `ClaimTypeMutationResult.GeneratedID`
**even when the write is rejected or uncertain**, so a retry can find an object
it must not duplicate rather than creating a second claim.

`DisplayName` is required. Identifiers are validated for length in UTF-16 code
units and for the characters the reference excludes; a malformed identifier is
rejected before anything is submitted.

## Sources and value types

A claim has exactly one source, and the source settles the stored value type.

| `ClaimSourceType` | Stored as | Requires | Value type |
| --- | --- | --- | --- |
| `ClaimSourceAttribute` (`AD`) | `msDS-ClaimAttributeSource` | one `attributeSchema` reference | derived from `attributeSyntax` |
| `ClaimSourceCertificate` (`Certificate`) | `msDS-ClaimSource` | a dotted-decimal OID | `ClaimString` |
| `ClaimSourceTransform` (`TransformPolicy`) | neither | explicit `ValueType` | as stated |

`ValueType` is accepted directly only for a transform-policy source, matching
the reference parameter sets. For the other sources a zero value requests
derivation and a non-zero value must agree with what the source settles. **No
update can change the value type a claim already stores**; a disagreement is
`ErrClaimTypeSchema`, not a write. The derivation table and the live checks it
still needs are recorded in
[claim value types](research/claim-value-types.md).

`SchemaReference` names a schema object by either the shared DN/GUID `Identity`
or an explicit `LDAPDisplayName` — exactly one, never both and never neither. A
display name is not inferred from a DN and a DN is not parsed out of a name.
Defunct schema objects and objects of the wrong class are rejected. Every
schema object read while settling a source or an applies-to class is retained
in `Schema`, including objects that were then rejected, so a refusal is
inspectable rather than opaque.

An attribute syntax with no mapped claim value type is rejected rather than
defaulted to a string.

## Suggested values

`SuggestedValues` is encoded into `msDS-ClaimPossibleValues` for the settled
value type: integer sources use `IntegerList`, unsigned sources
`UnsignedIntegerList`, and string, FQBN, SID and octet-string sources
`StringList`. Boolean claims have no suggested value list. A suggestion must
carry exactly one typed value; a mistyped suggestion is rejected rather than
coerced.

Reading retains the stored document verbatim in `RawXML` alongside the parsed
values, and `Extensions` reports valid foreign XML retained only in `RawXML`.
Existing XML is never reserialized for an unrelated update.

`RestrictValues` maps to `msDS-ClaimIsValueSpaceRestricted` and is written only
from the typed field. The SDK does not infer it from the presence of suggested
values; the directory remains authoritative for whether the value space is
closed.

## Updates

`UpdateClaimType` renders one LDAP modify. Nil fields are left alone; the
explicit `Clear` flags request removal and conflict with a stated value for the
same field. `AppliesToClasses` adds by default and replaces when
`ReplaceAppliesToClasses` is set, so a caller chooses between extending and
rewriting the class list rather than relying on a default.

Re-pointing a source also retires the attributes the previous form owned, so a
stale source DN or OID never outlives the change.

`Changes` carries additional raw attribute changes. Changes naming a managed
claim attribute — the name, either source attribute, the source kind, the value
type, the possible values, the applies-to or backlink classes, or the security
descriptor — are rejected, because a raw write to those would bypass source and
value-type validation.

## Deletion

`DeleteClaimType` submits one native leaf delete. It never unprotects an object
or removes references on the caller's behalf. Without `Force` it first reads
`msDS-ClaimSharesPossibleValuesWithBL`; an observed reference is reported as
`ErrClaimTypeReferenced` and nothing is submitted. A failed or incomplete
reference read is never read as "no references" — it is reported as incomplete,
so a hidden reference cannot be mistaken for an absent one.

## Protection

`ProtectedFromAccidentalDeletion` uses the shared OU-protection machinery and
requires the SD-flags control. Setting it can change the object's DACL. It is
reported in `Protection` and reflected on the returned claim.

## Limits

Reads and writes stay within the requested configuration partition. Reference
retrieval honours `CentralAccessReferenceLimits`; exceeding a budget is an
error rather than a truncated list presented as complete. The applies-to list
is bounded before any schema read.

Local tests cover identifier rules, source and value-type settlement, the
derivation table's exclusions, suggested-value encoding round trips, managed
attribute rejection and the referenced-delete guard. **No live qualification is
implied**: these operations remain `unverified` in the coverage report until
evidence from a recorded server and module build exists.
