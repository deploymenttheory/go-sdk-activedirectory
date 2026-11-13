# Claim value types and attribute syntax derivation

This records why claim value types are derived rather than accepted, and the
exact table the SDK uses. It is a documented contract **awaiting live
qualification**; nothing here is evidence of reference equivalence.

Source: [`New-ADClaimType`](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adclaimtype?view=windowsserver2025-ps)
and [`Set-ADClaimType`](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adclaimtype?view=windowsserver2025-ps),
pinned at `coverage/reference.json` commit
`b064f9a3ed2e53dd7856ea7daa5ca533560e7866`.

## Why the value type is derived

The pinned reference parameter sets settle this, not inference:

| Cmdlet | Parameter set | `ValueType` present | `SuggestedValues` present |
| --- | --- | --- | --- |
| `New-ADClaimType` | `SourceAttribute` (default) | no | yes |
| `New-ADClaimType` | `SourceOID` | no | no |
| `New-ADClaimType` | `SourceTransformPolicy` | **yes** | yes |
| `Set-ADClaimType` | every set | no | yes except `SourceOID` |

`ValueType` is accepted only alongside `SourceTransformPolicy`. For an attribute
or certificate-OID source the reference module therefore settles the value type
itself, and no set of `Set-ADClaimType` can change it afterwards.

The SDK mirrors that: `ClaimTypeSource.ValueType` is required for
`TransformPolicy`, and for the other sources a zero value requests derivation
while a non-zero value must agree with what the source settles. On update, the
value type already stored on the claim is compared and never replaced, so a
disagreement is `ErrClaimTypeSchema` rather than a write.

## Derivation table

`validateClaimSchema` reads the source attribute's `attributeSyntax` and maps it
to `msDS-ClaimValueType`:

| `attributeSyntax` | Syntax | Claim value type | Stored value |
| --- | --- | --- | ---: |
| `2.5.5.8` | Boolean | `ClaimBoolean` | 6 |
| `2.5.5.9` | Integer and Enumeration | `ClaimInt64` | 1 |
| `2.5.5.16` | LargeInteger | `ClaimInt64` | 1 |
| `2.5.5.12` | Unicode string | `ClaimString` | 3 |
| `2.5.5.10` | Octet string | `ClaimOctetString` | 16 |
| `2.5.5.17` | SID | `ClaimSID` | 5 |

Keyed on `attributeSyntax`, not `oMSyntax`: `oMSyntax` 4 covers both octet
strings and SIDs, which settle on different claim value types, so `oMSyntax`
alone cannot decide between them.

### Deliberate exclusions

- Syntaxes absent from the table are **rejected** with `ErrClaimTypeSchema`
  rather than defaulted to a string. Failing closed keeps an unverified mapping
  from silently creating a claim whose stored value type is wrong.
- `ClaimUInt64` (2) and `ClaimFQBN` (4) have no attribute syntax that derives
  them, so they are reachable only from a transform-policy source that states
  `ValueType` explicitly. `claim_schema_test.go` asserts no table entry derives
  either one.
- A certificate-OID source settles on `ClaimString`; the claim carries the
  issued OID as its value and the reference records no other value type for
  this source. **This is the weakest entry in this document and the first thing
  live qualification should confirm.**

## What live qualification must establish

Issue [#43](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/43)
owns this. Against a recorded server build and module version:

1. For each syntax above, create a claim type from an attribute of that syntax
   with the reference module, and compare the resulting `msDS-ClaimValueType`
   with this table.
2. Confirm a certificate-OID claim stores `3`.
3. Confirm the reference rejects, rather than defaults, an attribute whose
   syntax is outside the table — and record which syntaxes those are.
4. Confirm no `Set-ADClaimType` parameter set can change a stored value type.

Until those pass, the claim-type operations stay `unverified` in
`coverage/inventory.json` regardless of this table's presence.
