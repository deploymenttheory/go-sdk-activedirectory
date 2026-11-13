# Claims transformation policy rule text

What the reference module actually writes to `msDS-TransformationRules` for each
`New`/`Set-ADClaimTransformPolicy` form. **Observed, not inferred.**

Evidence: [`claims-transformation-evidence/server2025-shorthand-forms.json`](claims-transformation-evidence/server2025-shorthand-forms.json),
captured by `scripts/lab/reference-claims-transformation.ps1` against the
isolated `ad.sdk.test` lab. Every rule string is retained verbatim with its
UTF-8 byte length and SHA-256, so whitespace is provable rather than assumed.

| Field | Value |
| --- | --- |
| Module version | 1.0.1.0 |
| OS build | 26100.32230 |
| Schema version | 91 |
| Domain / forest level | Windows2016Domain / Windows2016Forest |

## The stored value is XML, not bare rule text

This is the finding that matters most, and it is not what the parameter names
suggest. The module wraps every rule in a fixed XML envelope with a CDATA
section:

```text
 <ClaimsTransformationPolicy>     <Rules version="1">         <![CDATA[<rule>]]>    </Rules></ClaimsTransformationPolicy>
```

The whitespace is part of the stored value: one leading space before
`<ClaimsTransformationPolicy>`, five spaces before `<Rules`, nine before
`<![CDATA[`, four before `</Rules>`, and none before the closing element. The
`version="1"` attribute is fixed.

`-Rule` supplies only the **inner** rule text; the caller never writes the
envelope. Caller text is wrapped verbatim, including its own spacing — the
explicit `C1:[] => Issue(claim = C1);` case kept its spaces around `=>` and `=`
and so hashes differently from the `AllowAll` expansion of the same intent.

## Shorthand expansions

Each shorthand expands to this inner rule. `New-` and `Set-` produced
**byte-identical** values for every form (equal SHA-256), so one renderer serves
both.

| Form | Inner rule |
| --- | --- |
| `-AllowAll` | `C1:[]=>Issue(claim=C1);` |
| `-DenyAll` | `C1:[Type !~ "*"]=>Issue(claim=C1);` |
| `-AllowAllExcept <id>` | `C1:[Type !="<id>"]=>Issue(claim=C1);` |
| `-DenyAllExcept <id>` | `C1:[Type=="<id>"]=>Issue(claim=C1);` |

Note the module's own inconsistent spacing, reproduced exactly because
correctness here is byte equality, not readability:

- `AllowAllExcept` emits `Type !="…"` — a space **before** `!=`, none after.
- `DenyAllExcept` emits `Type=="…"` — no spaces around `==`.
- `DenyAll` emits `Type !~ "*"` — spaces both sides of `!~`.

`DenyAll` is expressed as "issue claims whose type matches nothing" rather than
as an empty rule set.

## Compiled rules

`msDS-TransformationRulesCompiled` was **absent** on every policy this run
created. The collector records that attribute as length and digest only and
never interprets it; nothing here claims the DC populates it, or when.

## Confirmed incidentally: claim type derivation

The fixture claim type created with `New-ADClaimType -SourceAttribute department`
stored:

| Attribute | Value |
| --- | --- |
| `msDS-ClaimValueType` | `3` (`ClaimString`) |
| `msDS-ClaimSourceType` | `AD` |
| `msDS-ClaimAttributeSource` | `CN=Department,CN=Schema,CN=Configuration,DC=ad,DC=sdk,DC=test` |

`department` has `attributeSyntax` `2.5.5.12` (Unicode string). This confirms
the `2.5.5.12 → ClaimString` row of
[claim value types](claim-value-types.md), that `ClaimSourceAttribute` stores as
the literal `AD`, and that the attribute source is stored as a DN. One row of
six is now evidence-backed; the rest remain a documented contract.

## Still unobserved

- **`Set-ADClaimTransformLink` and `Clear-ADClaimTransformLink`.** These act on
  a `trustedDomain` object and need a second forest with a trust. The current
  lab is a single forest, so the link attributes and the `TrustRole` mapping are
  **not** established. Extending the lab with a second forest is the only way to
  close this.
- **Multi-value `AllowAllExcept`/`DenyAllExcept`.** The captured run named one
  claim type per form, so how the module chains several types into one rule is
  unknown. The collector now creates a second claim type and exercises both
  multi-value forms; that capture has not yet been run.
- **Rule evaluation.** This records what is stored, never how the server
  evaluates it. Byte equality with the reference is not proof of equivalent
  access outcomes.
