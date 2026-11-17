# Explicit identities and directory values

`Client.ResolveIdentity` uses the authenticated client's endpoint. It never
discovers another server, follows referrals, forwards credentials, or substitutes
another partition after a failed lookup. All discovery and search reads share
the configured timeout and caller cancellation.

```powershell
go run ./examples/identity -server dc1.example.test -dn 'CN=Jörg\, 李,OU=People,DC=example,DC=test'
```

The example performs only reads with the current Windows identity. Native
execution requires Windows amd64/arm64. Constructors, values and configuration
are portable Go.

| Operation target | Allowed constructors | Directory |
| --- | --- | --- |
| `IdentityTargetObject` (default) | `IdentityByDN`, `IdentityByGUID` | AD DS or AD LDS |
| `IdentityTargetAccount` | All four, including `IdentityBySID`, `IdentityByAccountName` | AD DS |

Constructors take strings and return `(Identity, error)`. Account names are
literal, unqualified `sAMAccountName` values; UPN and `DOMAIN\name` inputs are
rejected. Filters are not identities. GUID and SID filters use their binary LDAP
representations. An account lookup also requires `objectSid` on the result.

## Persisting an identity

`Identity.String()` returns the value without its form, because that is what a
diagnostic wants to show. It is deliberately not round-trippable — the four
forms are not distinguishable by inspection, and guessing which one a string is
is precisely what this type exists to prevent.

To write an identity down and read it back, use the form-prefixed text
encoding:

```go
id, _ := identity.MarshalText()        // "guid:6a2ba0f0-4a2e-4f6d-9f1b-0c3d5e7a9b11"
back, err := activedirectory.ParseIdentity(string(id))
```

`ParseIdentity` dispatches to the four constructors, so every validation they
apply applies to parsed text too, and a GUID or SID reconstructs the same bytes
it was built from. Only the first colon separates the prefix from the value, so
a distinguished name holding one is unaffected.

| Prefix | Form | Constructor |
| --- | --- | --- |
| `dn:` | distinguished name | `IdentityByDN` |
| `guid:` | `objectGUID` | `IdentityByGUID` |
| `sid:` | `objectSid` | `IdentityBySID` |
| `sam:` | `sAMAccountName` | `IdentityByAccountName` |

The prefixes are API. A persisted identity must still parse after an upgrade,
so a prefix may be added but never changed or reused, and a test pins the four.

`Identity` also implements `encoding.TextMarshaler` and `TextUnmarshaler`, so
it encodes as that string inside JSON rather than as an empty object, and a
stored identity that has gone malformed fails the decode instead of arriving as
a zero identity that later reads as not-found. The zero `Identity` is refused
rather than encoded.

Because the GUID and SID forms carry bytes alongside their text, `Identity`
contains a slice and so cannot be compared with `==` or used as a map key.
Compare the form and value, or key on the marshalled text.


`ResolveIdentityOptions.Partition` overrides `Config.Partition`. Otherwise, a DN
selects the longest matching advertised naming context, and other forms select
`defaultNamingContext`. The selected partition must be advertised by this server.

Because a GUID, SID or account name is searched for across that partition, the
server answers with continuation references to any subordinate naming context
it holds — in a domain, always `cn=configuration`, `dc=domaindnszones` and
`dc=forestdnszones`. A reference names a partition the search never asked
about, so it cannot make a unique in-scope match wrong, and resolution
succeeds. Any other incompleteness still fails, including a reference arriving
beside a real failure. `Search` reports the same reference as
`ErrSearchReferences`, because a caller enumerating a subtree does need to
know a partition went unsearched.
AD LDS without a default requires an explicit partition for non-DN identities.
Schema is separate from Configuration; a text suffix alone does not grant scope.

DN input uses RFC4514 syntax, including Unicode, hex escapes, escaped separators
and multivalued RDNs. Quoted legacy DNs, provider URLs and extended GUID/SID DNs
are excluded. Scope comparison is conservative: it understands escapes and
case-insensitive textual AVAs, but does not infer attribute OID aliases or apply
schema-specific Unicode normalization. Use the server's naming-context spelling
where those distinctions matter.

A unique completed search sets `IdentityResult.Object` and `Complete`. The
resolver stops at two candidates and returns `ErrAmbiguousIdentity`; it never
selects the first match. A complete empty search returns
`ErrDirectoryObjectNotFound`. Native errors, permission diagnostics, cancellation
and cleanup failures remain in the error chain; incomplete candidates remain in
`Candidates` without being treated as a resolved identity. These reads are not an
atomic transaction or authorization for a later write.

## Values

`Object.Values(name)` wraps copied bytes in `RawValue` and retains the existing
`AttributeState`: unloaded, absent, present or partial. Absent may mean hidden by
permissions. Unknown attributes remain raw; the SDK does not guess their schema.
Multiple values retain ordering and duplicates. Ranged descriptions and values
remain in `Ranges`, and `Single` refuses incomplete or non-scalar input. Empty
strings/byte values, zero and false remain distinct from absence.

```go
values := result.Object.Values("objectGUID")
raw, err := values.Single()
if err != nil { return err }
guid, err := raw.GUID()
if err != nil { return err }
fmt.Println(guid.String())
```

`RawValue` offers explicit text, boolean, integer, GUID, SID, FILETIME,
generalized-time, interval and flag conversions. `Bytes` returns a copy. GUID
fields use Windows byte order; SID authorities use six big-endian bytes and
subauthorities use little-endian DWORDs.

`FileTime` retains all 64 bits and 100ns precision. Its `Time` method rejects
common sentinel bit patterns (0, MaxInt64, all ones); callers interpret these
according to the attribute. For example, both 0 and MaxInt64 mean never for
`accountExpires`. Other negative signed LDAP values retain their bits and cannot
be converted to an ordinary timestamp. `LDAPString` emits signed LargeInteger
decimal. `FileTimeFromTime` rejects sub-100ns precision and out-of-range input.

`Interval100ns` retains signed wire ticks, including MinInt64. `Duration` rejects
that sentinel and values exceeding Go's duration range. Conversion from a Go
duration rejects sub-100ns precision. This signed wire type is separate from
the password-policy API's nonnegative `PolicyInterval`.

`GeneralizedTime` retains the exact timestamp string, fractional precision and
zone. `Time` supports exact fractions of hours/minutes/seconds; it rejects leap
seconds and sub-nanosecond fractions rather than rounding them. Parse input is
bounded to 4096 bytes. `Flags32` preserves unknown bits and signed LDAP integers;
`With` changes only the caller's mask.

## Qualification boundary

Portable tests cover scope, escaping, ambiguity, incomplete outcomes and value
round trips; fuzz targets exercise DNs, binary identities and times. Windows
loopback tests use real WinLDAP paging, copying, error propagation and allocation
cleanup with fixed discovery data. No live AD operation is part of these tests.
The opt-in reference test compares local Windows/.NET conversions using the
PowerShell collector described below; PowerShell is never a runtime SDK dependency.

```powershell
powershell.exe -NoProfile -File scripts/lab/reference-object-values.ps1 -OutputPath H:\ad-sdk-lab\object-values-reference.json
$env:ADSDK_OBJECT_VALUES_REFERENCE='H:\ad-sdk-lab\object-values-reference.json'
go test ./activedirectory/acceptance -run '^TestObjectValuesPowerShellReference$' -count=1
```

Live AD DS/AD LDS identity differential checks, ordinary-user denial cases and
the Server 2016/2019/2022/2025 matrix remain unqualified. Issue #12's remaining
search qualification is still open. This implementation does not close #13 or
claim full PowerShell parity.

Sources: [Get-ADObject identity/partition rules](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adobject),
[AD LDAP representations](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa),
[GUID layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40),
[accountExpires sentinels](https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires),
[RFC4514 DNs](https://www.rfc-editor.org/rfc/rfc4514), and
[RFC4517 generalized time](https://www.rfc-editor.org/rfc/rfc4517).
