# Account value-property qualification

Run `account-values-20261117T092239Z` passed on 2026-11-17 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result.

Advances **20 scenario states** across four families on the three account
classes, each measured at create time and on an update:

| family | operations | states |
| --- | --- | --- |
| `account-expiration-values` | New/Set-AD{User,Computer,ServiceAccount} | 6 |
| `binary-certificate-values` | New/Set-AD{User,Computer,ServiceAccount} | 6 |
| `spn-multivalue-constraints` | New/Set-AD{User,Computer,ServiceAccount} | 6 |
| `user-derived-property-roundtrips` | New/Set-ADUser | 2 |

The generic write sweeps establish that a write lands and that a bad request is
refused. They say nothing about what a **value** means after a round-trip, and
these four families are where a provider's state and the directory come apart.

## Expiry: four things that are not each other

`accountExpires` carries two never-expire sentinels, a finite instant, and the
possibility of not having been read. A provider that conflates any two of them
silently changes a caller's expiry.

| | observed |
| --- | --- |
| a finite instant | round-tripped exactly, at 100ns precision |
| the same instant in a non-UTC zone | same stamp, not one shifted by the offset |
| `0` and `MaxInt64` | both read as never, neither presented as an instant |
| clearing | wrote `MaxInt64`, attribute still **present** |
| an update naming no expiry | stamp untouched |
| a create naming no expiry | the directory's own default |
| **an attribute that was not read** | **reported as not read, never as never-expire** |
| an instant mapping onto a sentinel | refused, `invalid-request` |
| sub-100ns precision | refused, not truncated |

The bolded row is the one a provider gets wrong first. The API documents that a
nil reading means "not read" and does not mean never; a partial read taken as
never-expire would clear a caller's expiry out of state. Sub-100ns precision is
refused rather than truncated for a related reason: a provider that wrote a
truncated stamp would re-plan the difference for ever.

## Certificates are bytes, not text

Two values whose bytes include NUL and `0xFF` round-tripped **byte for byte**
through `userCertificate`, compared by SHA-256 digest. The same bytes offered to
a text-typed property were refused as `invalid-request` — which is what makes
the byte-exact result a property of the binary path rather than of the directory
accepting anything.

A cleared set and a field that was never requested read as **distinguishable**
retrieval states (`absent` against `unloaded`). Reading the second as the first
is how a provider deletes certificates nobody mentioned.

Clearing is reported **unverifiable by design**: an absent attribute is equally
what a denied read looks like, so the SDK will not claim to have confirmed it.
The harness accepts that reading and proves the effect with a read of its own,
which is the only thing that can settle it. The aggregation never lets the
unverifiable report stand in for that read.

## Service principal names, and two different doors

Add kept the others — including any the class already owned before the harness
touched it. Replace set exactly the request, remove kept the rest, clear emptied
the attribute, and a non-ASCII value round-tripped.

**The three classes do not offer the same surface.** Only the service account has
a typed `ServicePrincipalNames` field, and it *replaces the whole set* rather
than adding and removing values. User and computer have no typed field at all;
their SPNs go through explicit attribute changes, which add and remove
individual values. Each observation records the door it used and what that door
can express, and the aggregation rejects an observation whose recorded semantics
disagree with its path — a reader who assumed the stronger guarantee would write
a provider that drops values.

Two refusals, both from the directory:

| | |
| --- | --- |
| a value another object owns | **LDAP 19**, `uSNChanged` unchanged |
| a value already on this object | **LDAP 20** (explicit path) |
| the same, typed path | refused locally as a duplicate raw value |

Forest-wide SPN uniqueness is the constraint a caller cannot discover from the
schema and the one that makes an SPN write fail in production. Note it arrives
as **LDAP 19 constraint violation**, not as a conflict or an already-exists —
the same shape as the permission finding in `../../../docs/errors.md`.

## User properties, and a defect this family found

All six properties reached the attribute recorded against them, carrying
non-ASCII values; an update naming none of them left every one unchanged; and no
property disturbed another. A manager that is not a distinguished name was
refused as `invalid-request` with `uSNChanged` unchanged.

`Country` and `LogonWorkstations` have **no typed field** on `UserProperties`
and were driven through explicit attribute changes (`co`, `userWorkstations`).
The gap is recorded in the artifact rather than papered over.

### The defect

A creation composed its reported `TargetDN` from the schema's naming attribute —
which spells it `cn` — while the directory answers `CN`. A caller that stored
that name and wrote it back into a DN-valued attribute such as `manager` met the
byte-exact readback comparison and was told the effect **could not be verified**,
for a write that had landed correctly. For a provider that is a resource which
never reports a confirmed apply.

Fixed by reporting the directory's own `distinguishedName` attribute, and
measured here against the directory rather than against the SDK's own
composition of the name, so the fix cannot regress unnoticed.

The measurement also established why the *first* attempt at that fix changed
nothing, and it is a directory fact worth having written down:

| | |
| --- | --- |
| readback search entry name | `cn=sdkav-mgrc,OU=…` |
| `distinguishedName` attribute | `CN=sdkav-mgrc,OU=…` |

**A base-scoped search echoes the distinguished name the request supplied as the
entry name.** Only the attribute is authoritative. Code that compares an entry
name against a composed name is comparing the request with itself; the
restoration path is immune because it compares parsed DNs through
`sameIdentityDN` rather than bytes.

### The limitation this does not fix

A DN a caller spells with a non-canonical attribute type (`cn=` where the
directory holds `CN=`) addresses the same object and **lands correctly** — the
harness confirms the value is there — but the byte-exact comparison cannot prove
it, and the caller is told `uncertain` rather than `unverified`. Those two mean
different things to a provider: one says the write may not have happened, the
other that it did and could not be proved. Tracked separately; it needs the
attribute's schema syntax to fix properly, which is more than this family.

## What this is not

`full_ticket_complete` is `false`. **No variant state advances.**

The remaining property families on these classes are not claimed here:
`account-flags-and-security-values`, `computer-name-and-domain-join-boundary`,
`group-scope-category-transitions` and `password-enable-creation-order`.

The service account fixtures are standalone accounts. A group-managed account
needs a KDS root key past its creation-age gate, and its own value semantics
(`msDS-ManagedPassword`) are not part of these four families.
