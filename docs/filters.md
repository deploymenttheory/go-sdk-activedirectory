# Typed LDAP filters

`SearchOptions.TypedFilter` composes literal values safely. The existing
`SearchOptions.Filter` string remains the explicit raw LDAP alternative.
Supplying both returns `ErrConflictingFilters` before native I/O. With neither,
Search keeps its existing `(objectClass=*)` default. Raw filter grammar is still
validated by WinLDAP/the server; the SDK does not reinterpret it.

```go
query := activedirectory.SearchOptions{
    Base: "DC=example,DC=test",
    Scope: activedirectory.ScopeSubtree,
    TypedFilter: activedirectory.FilterAnd(
        activedirectory.FilterEqual("objectClass", activedirectory.FilterText("user")),
        activedirectory.FilterEqual("cn", activedirectory.FilterText(userSuppliedName)),
        activedirectory.FilterNot(activedirectory.FilterBitAnd("userAccountControl", 2)),
    ),
    Properties: []string{"cn", "objectGUID"},
}
result, err := client.Search(ctx, query)
// Check err and result.Complete; a failure can still return partial objects.
```

Constructors retain validation errors so nested expressions remain readable.
`filter.LDAP()` returns the complete RFC 4515 string or the construction error.
`query.Validate()` also checks that the expression can be safely submitted by the
native backend. A zero `Filter` is unset in `SearchOptions`, but invalid as a
child expression or when encoded directly. Empty And/Or groups are invalid.
The immutable values/expressions snapshot byte slices and composition inputs.
Typed expressions are limited to 1 MiB and depth 64; exceeding either returns
`ErrFilterLimit`, never truncation. These bounds do not alter legacy raw input.

| Operation | Constructor |
| --- | --- |
| Equality / presence | `FilterEqual(attribute, value)`, `FilterPresent(attribute)` |
| LDAP comparisons | `FilterGreaterOrEqual`, `FilterLessOrEqual`, `FilterApprox` |
| Boolean composition | `FilterAnd`, `FilterOr`, `FilterNot` |
| Ordered substrings | `FilterSubstrings(attribute, SubstringFilter{...})` |
| Extensible match | `FilterExtensible(ExtensibleFilter{...})` |
| AD bit masks / ancestry | `FilterBitAnd`, `FilterBitOr`, `FilterInChain` |

Text values use `FilterText`, arbitrary octets use `FilterBytes`, and exact signed
decimal integers use `FilterInteger`. Equality with `FilterText("*")` means a
literal asterisk; it encodes as `\2a`. Only `FilterPresent` and the separators
inserted by `FilterSubstrings` introduce wildcards. Substring Initial/Final zero
values omit anchors; Any values retain their order. Every supplied segment must
be nonempty. Binary GUID values use the 16 LDAP octets in Windows GUID byte order;
SIDs use binary SID layout. Neither should be passed as a printed string to a
binary attribute comparison. The identity API's `GUID.Bytes()`/`SID.Bytes()` can
be supplied to `FilterBytes` when those APIs are integrated; this feature does
not add competing GUID or SID parsers.

Attribute descriptions and rule OIDs are validated independently from values.
Text must be valid UTF-8; NUL, backslash, parentheses and wildcard characters are
escaped. Binary values escape every octet and are never decoded as UTF-8. Inputs
such as `*)(|(objectClass=*))` remain one literal equality assertion. There is no
constructor that treats a value as an executable filter fragment.

## DN values are a separate syntax

`EscapeDNValue` escapes **one RDN attribute value**, not an entire DN. After
forming the DN, use `FilterText` when it is a filter assertion value:

```go
rdn, err := activedirectory.EscapeDNValue("Group, One")
// Check err.
dn := "CN=" + rdn + ",OU=Groups,DC=example,DC=test"
filter := activedirectory.FilterInChain("memberOf", dn)
```

Filter escaping does not protect DN construction. DN escaping does not protect
filter construction. Do not pre-escape values passed to `FilterText`; it accepts
the actual assertion text (including the escapes already belonging to a formed
DN). DN comparison semantics, schema syntax and access rights belong to the
directory, rather than these construction helpers.

## AD matching rules and the native boundary

The named rules are bit-and (`1.2.840.113556.1.4.803`), bit-or (`.804`), in-chain
(`.1941`), and DN-with-data (`.2253`). All four are documented for the targeted
Server 2016–2025 AD DS/applicable AD LDS versions. In-chain requires a link
attribute; DN-with-data requires the appropriate DN-String/DN-Binary syntax.
Bit-mask width and ordinary comparison/approximate matching semantics depend on
the attribute schema. Custom numeric OIDs can be expressed without implying
server support. AD exposes no matching-rule capability list; native errors and
partial results are preserved rather than replaced with guessed capability or
permission results. AD ignores `dnAttributes` and evaluates an extensible clause
without an attribute as Undefined; the generic RFC constructor does not promise
AD matching behavior for those forms.

**WinLDAP extensible assertion limitation:** the tested native parser transmits
extensible assertion text literally instead of decoding RFC 4515 hexadecimal
escapes. The SDK therefore keeps two representations: `Filter.LDAP()` remains
RFC-correct, while typed Search uses a private native serialization that preserves
safe text exactly, including literal wildcards, Unicode and escaped-comma DNs.
Normal equality, comparison and substring filters use standard escaping.

Typed Search rejects extensible assertions containing NUL, non-UTF-8 binary data,
parentheses, or a terminal backslash with `ErrUnsupportedFilterValue` before
native I/O. These inputs
cannot safely round-trip through this native string interface. Composing them
inside And/Or/Not does not bypass rejection. Portable `LDAP()` output can still
represent them; **native parity for these extensible values remains incomplete**.
Legacy raw filters retain their exact existing WinLDAP interpretation. This
behavior is covered by real WinLDAP BER checks, and must be requalified when the
native runtime changes; no replacement transport or undocumented syscall is used.

An empty equality assertion such as `(description=)` is valid RFC output, but
the tested WinLDAP parser rejects it with `LDAP_FILTER_ERROR` (87). Search
preserves that native error and releases its resources; it does not substitute
a presence or absence test. This native input case also remains unqualified.

## Running and qualifying

`go run ./examples/filters -name 'A*(literal)'` prints the RFC filter without
contacting AD. Add an explicit `-server dc1.example.test -base DC=example,DC=test`
to perform a read-only search using the current Windows identity. Server execution
requires Windows amd64/arm64; construction works on Windows, Linux and macOS.

`go test ./...` covers grammar/value validation, raw compatibility, binary copy
ownership, composition limits, DN separation and error propagation. Windows tests
send real WinLDAP searches to a loopback responder and inspect BER assertion
octets/tree structure for injection-shaped text, literal wildcard, Unicode/NUL,
GUID/SID, comparisons, nested booleans, substrings and AD rules. They also check
unsupported-rule/permission errors, retained partial objects and all seven native
allocation counters returning to zero. This tests encoding, not AD schema matches.

```powershell
go test . -run '^$' -fuzz '^FuzzFilterLiteralEscaping$' -fuzztime=30s -parallel=2
go test . -run '^$' -fuzz '^FuzzFilterComposition$' -fuzztime=30s -parallel=2
```

For later differential qualification, reuse the existing search lab's ownership,
fixture and evidence process. Pass the same RFC output to
`Get-ADObject -LDAPFilter $filter -Server $dc -SearchBase $base -SearchScope Subtree
-Properties objectGUID,cn`, and compare complete GUID/DN result sets with the typed
SDK search. Use controlled existing fixtures with literal wildcard, Unicode,
escaped DN characters, binary GUID/SID, numeric and nested group-link cases;
record explicit target/NC, filter, source commit, Windows build, AD module and
PowerShell versions, permissions and both raw result sets. Preserve partial errors
and ensure positive controls actually match. Do not create fixtures implicitly.

No live AD filter matches or PowerShell differential runs have been performed for
this feature. Server/version, AD LDS, permission and link-rule result semantics,
and Windows arm64 live qualification remain pending. Keep issue #14 open until
those checks and the native extensible-value coverage gap are resolved.

References: [RFC 4515](https://www.rfc-editor.org/rfc/rfc4515.txt),
[RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.txt),
[AD matching rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5),
[AD search-filter semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/0bb88bda-ed8d-4af7-9f7b-813291772990).
