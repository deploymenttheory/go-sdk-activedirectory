# Claim transformation policies

`ClaimTransformPolicy` and `ClaimTransformPolicies` read the AD DS
configuration naming context. `CreateClaimTransformPolicy`,
`UpdateClaimTransformPolicy` and `DeleteClaimTransformPolicy` use native
asynchronous LDAP writes, and `SetClaimTransformLink` /
`ClearClaimTransformLink` edit the link on a trust. Runtime PowerShell, AD Web
Services and an installed agent are not required. Native execution supports
Windows amd64 and arm64; portable input validation and models build elsewhere.

These APIs require AD DS with the Windows Server 2012 claims schema and the
`CN=Claims Transformation Policies,CN=Claims Configuration,CN=Services`
container installed by forest preparation. AD LDS and Global Catalog endpoints
are rejected. Explicit partitions must match the configuration naming context.
A policy must have the `msDS-ClaimsTransformationPolicyType` class and that
container as its direct parent.

## The stored value is XML, not bare rule text

This is observed behaviour, not an interpretation. The reference module stores
rules inside a fixed XML envelope containing a CDATA section:

```text
 <ClaimsTransformationPolicy>     <Rules version="1">         <![CDATA[<rule>]]>    </Rules></ClaimsTransformationPolicy>
```

The irregular whitespace is part of the stored value and is reproduced exactly.
`ClaimTransformPolicy.StoredRules` is the whole attribute; `Rule` is the inner
text. When a stored value does not match this envelope, `Rule` is nil and
`StoredRules` still reports what was read, so an unexpected shape is visible
rather than reinterpreted.

The expansions and their captured digests are recorded in
[claims transformation](research/claims-transformation.md), and the unit tests
assert those digests so any drift fails the build.

## Rule forms

`ClaimTransformRuleSet` selects exactly one form. The zero value writes no
rules — it is **not** read as deny-all.

| Field | Stored inner rule |
| --- | --- |
| `AllowAll` | `C1:[]=>Issue(claim=C1);` |
| `DenyAll` | `C1:[Type !~ "*"]=>Issue(claim=C1);` |
| `AllowAllExcept` | `C1:[Type !="<id>"]=>Issue(claim=C1);` |
| `DenyAllExcept` | `C1:[Type=="<id>"]=>Issue(claim=C1);` |
| `Rule` | the caller's text, wrapped verbatim |

`DenyAll` is expressed as a claim type matching nothing rather than as an empty
rule set. The spacing differs between forms — a space precedes `!=` but none
surrounds `==` — because that is what the reference wrote.

`AllowAllExcept` and `DenyAllExcept` accept **one** claim type identifier.
Supplying more is rejected: how the reference chains several into one rule has
not been observed, and this SDK will not invent a separator for it.

`Rule` text is wrapped without normalisation, so caller spacing survives. Text
that could close the CDATA section or nest another envelope is rejected before
any write.

## Trust links

`SetClaimTransformLink` and `ClearClaimTransformLink` take an explicit
`ClaimTransformDirection`:

| Direction | Attribute |
| --- | --- |
| `ClaimTransformEgress` | `msDS-EgressClaimsTransformationPolicy` |
| `ClaimTransformIngress` | `msDS-IngressClaimsTransformationPolicy` |

**The reference exposes `TrustRole` instead, and which role maps to which
direction has not been qualified.** It needs a second forest with a trust,
which the reference lab does not have. Applying a policy to the wrong direction
of claims flow would be a security-relevant error, so the direction is stated
by the caller rather than derived from a role. A `TrustRole` convenience can be
added once the mapping is observed.

The target is verified to be a `trustedDomain` object and the policy is
resolved and verified to live in the Claims Transformation Policies container,
so a link can never be pointed at an arbitrary object. Clearing removes the
link only; it never deletes the policy. A clear of an already-absent value is
not an error and is therefore not verified as a change.

## Compiled rules

`msDS-TransformationRulesCompiled` is server-generated. It is never written, and
`CompiledPresent` only reports whether it was returned. It was absent on every
policy the reference run created; nothing here claims when a DC populates it.

## Updates and deletion

`UpdateClaimTransformPolicy` renders one LDAP modify. Nil and zero fields are
left alone; `ClearRules` and `ClearDescription` conflict with a stated value for
the same field. `Changes` carries additional raw attribute changes, but changes
naming the name, the rules, the compiled rules or the security descriptor are
rejected because they would bypass rule validation.

`DeleteClaimTransformPolicy` submits one native leaf delete. It never
unprotects an object or clears trust links on the caller's behalf; a policy
still linked from a trust is the directory's own referential concern and its
refusal is surfaced unchanged.

## Limits

Local tests cover the rule renderer against captured digests, the observed
spacing, form exclusivity, the multi-identifier refusal, envelope breakout
rejection, managed-attribute rejection and direction mapping. **The four
policy operations are grounded in captured evidence; the two link operations
are not.** All six remain `unverified` in the coverage report until evidence
from a recorded server and module build exists for each.
