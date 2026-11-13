# AD filter expressions

`ParseADFilter(expression, ADFilterOptions)` compiles the AD PowerShell-style
filter language into the existing immutable `Filter`. Supply the result through
`SearchOptions.TypedFilter`; raw LDAP remains `SearchOptions.Filter`, and the two
remain mutually exclusive. Runtime parsing is portable Go with no PowerShell,
RSAT, command execution, provider, remote agent or directory discovery.

```go
filter, err := activedirectory.ParseADFilter(
    `Enabled -eq $true -and Surname -eq $surname -and LastLogonDate -ge $cutoff`,
    activedirectory.ADFilterOptions{
        Profile: activedirectory.ADFilterUser,
        Variables: map[string]any{
            "surname": "O'Neil",
            "cutoff": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
        },
    },
)
// Check err before searching.
result, err := client.Search(ctx, activedirectory.SearchOptions{
    Base: "OU=People,DC=example,DC=test",
    Scope: activedirectory.ScopeSubtree,
    TypedFilter: filter,
})
// Check err and result.Complete; native errors may retain partial objects.
```

Profiles select **property translation only**. They do not add a Get-ADUser or
Get-ADComputer structural class filter, choose a search base, or grant access.
Add object-class restrictions explicitly when needed. Search still uses the
existing client deadline, paging, result limit, diagnostics and ownership rules.

## Grammar and values

All documented comparison operators are recognized: `-eq`, `-ne`, `-le`, `-lt`,
`-ge`, `-gt`, `-approx`, `-like`, `-notlike`, `-band`, `-bor`, and
`-recursivematch`. Comparisons bind before `-not`, then `-and`, then `-or`.
Parentheses override that order. Operators/property aliases are case-insensitive.
One optional outer brace pair groups an expression; it never executes a script.
A standalone `*` compiles to objectClass presence.

Strings must be quoted. A doubled single quote escapes a single quote in a
single-quoted string; backtick-double-quote escapes a double quote in a
double-quoted string. Other backticks remain literal, as in the reference AD
parser. Double-quoted variables are literal text: `"$name"` is not interpolation.
Expression string literals accept LDAP hex escapes such as `\00`, `\5c` and
`\2a`; malformed hex escapes are rejected instead of forwarded to WinLDAP.
Only an unescaped `*` in a `-like`/`-notlike` operand introduces a wildcard.
`?` and brackets are literal characters. `-eq '*'` compares a literal asterisk.

Variables use `$name` or `${name}` and bind directly from the Go map. Names omit
the dollar sign and are case-insensitive; ambiguous duplicate keys are errors.
The constants `$true` and `$false` are reserved. Go strings are already values:
their backslashes remain literal and are not decoded as expression escapes.
`-like $pattern` deliberately interprets stars in that pattern as wildcards.
Use `-eq $value` for exact literal comparison, including injection-shaped input.
The compiler never calls arbitrary `String` methods or converts an object by
executing user code. Arrays, property access, indexing, type casts, subexpressions,
pipelines, commands, methods, assignments and script statements are rejected.

Integer literals support signed decimal and hexadecimal, preserving 64-bit
precision. Signed and unsigned Go integer types are supported. Integral float64
values are accepted only within the exact 53-bit range; fractional/nonfinite
values are errors. Fractional and exponent **expression literals** are currently
rejected explicitly: the observed module truncates `1.5` and coerces `1e3`, and
this SDK does not silently reproduce lossy numeric coercion. This is a remaining
compatibility gap, not full expression-language parity.

`$null`, missing variables and nil values are errors, matching the observed AD
parser's rejection of null operands. Use `property -like '*'` for presence and
`property -notlike '*'` for absence. Ordinary `-ne`, `-gt`, `-lt` and non-presence
`-notlike` add a presence condition, following the reference converter. Explicit
`-not` negates its child directly. These are directory filter predicates; an
absent attribute in returned data does not prove its value or access rights.

## Property and type conversion

The default `ADFilterObject` profile contains common ADObject aliases, including
`Created` → `createTimeStamp`, `Modified` → `modifyTimeStamp`, `Deleted` →
`isDeleted`, and `ObjectGUID`. `ADFilterUser`, `ADFilterComputer` and
`ADFilterGroup` select AD DS factory mappings verified from installed module
metadata. For example, user `EmailAddress` maps to `mail`, `Surname` to `sn`, and
principal `SID` to `objectSid`. The documentation's use of `email` does not make
it a verified `mail` alias; unknown LDAP names pass through unchanged.

The user/computer profiles implement persisted account-control boolean aliases,
including Enabled, PasswordNeverExpires, PasswordNotRequired, delegation flags
and DoesNotRequirePreAuth. The user profile also supports SmartcardLogonRequired.
GroupScope and GroupCategory compile to their groupType matching rules. These
computed properties accept equality/inequality with their appropriate values;
they do not accept arbitrary ordering or pattern operators.

GUID/SID canonical strings and typed `GUID`/`SID` values reuse the existing shared
parsers and LDAP byte encodings. `[]byte` and `RawValue` preserve arbitrary binary
assertions. Booleans produce LDAP TRUE/FALSE. Known FILETIME aliases accept
`time.Time` and `FileTime`, preserving 100ns precision and rejecting rounding.
Known generalized-time aliases accept `time.Time`, `GeneralizedTime`, or valid
generalized-time strings. UTC conversion is explicit. No locale-dependent date
strings are guessed, and numeric date sentinels retain their wire meaning.

Unknown attribute syntax is not inferred from its name. Unknown LDAP names accept
explicit scalar or binary values, but a `time.Time` needs a known descriptor:

```go
options.Properties = map[string]activedirectory.ADFilterProperty{
    "customDate": {Attribute: "myOrganizationTimestamp", Syntax: activedirectory.ADFilterFileTime},
}
```

Descriptors add or override direct aliases using caller-provided schema facts.
They cannot silently replace computed aliases. AD LDS callers can use the common
object profile plus explicit descriptors; AD LDS account/group factory-specific
translation is not qualified by this AD DS mapping set.

Directory-dependent or unsupported aliases return `ErrADFilterProperty`, including
Manager/ManagedBy identity resolution, IPv4Address/IPv6Address DNS lookup,
AccountExpirationDate special semantics, LockedOut, PasswordExpired, certificates,
security-descriptor properties and policy identity resolution. Computer
SamAccountName supports explicit names ending in `$` and wildcard patterns;
shortcut names that require directory resolution are rejected. Use an explicit
LDAP filter/builder when directly addressing the underlying attribute. Those
rejections are documented unfinished coverage, not parity claims.

## Errors, native limits and qualification

`ADFilterError` includes a byte offset and one-based Unicode line/column without
echoing assertion data. `errors.Is`/`errors.As` retain syntax, variable, property,
precision and native-value causes. Expressions are bounded to 1 MiB, 8,192 tokens
and depth 64, with the typed filter's output limits also enforced.

The [typed-filter native limits](filters.md#ad-matching-rules-and-the-native-boundary)
remain in force. Unsupported extensible values fail compilation rather than being
silently changed. WinLDAP's empty-equality parser error is preserved during search.
No alternate transport, replay or PowerShell execution is introduced.

`go run ./examples/adfilters -surname "O'Neil"` prints LDAP without contacting AD.
Add explicit `-server` and `-base` to perform a read-only search on Windows.

The checked-in `testdata/ad-filter-reference.json` records 41 offline cases and
93 factory mappings from module **1.0.1.0**, assembly file **10.0.26100.7920**,
host Windows **10.0.26300.0**. It retains raw output, module/assembly/collector
hashes, PowerShell version and the explicit `directory_contacted=false` scope.
The collector invokes the module parser and a whitelist of observed pure
converters; FILETIME and SID bytes use .NET conversion without schema discovery.
It does not run Get-AD cmdlets or establish a directory session.

The reference emits malformed negative LDAP fragments in several cases, just
as the official examples do. The differential test retains those raw fragments
and adds the missing child parentheses before comparison. It also normalizes
hex case, unnecessary slash escaping and repeated wildcards. It separately
asserts the two intentional numeric-literal rejections instead of counting them
as matching behavior. Regenerate the bounded offline fixture explicitly with:

```powershell
./scripts/reference/ad-filter-expressions.ps1 -OutputPath "$PWD/testdata/ad-filter-reference.json"
go test . -run TestADFilter
go test . -run '^$' -fuzz '^FuzzADFilterParser$' -fuzztime=30s -parallel=2
go test . -run '^$' -fuzz '^FuzzADFilterVariableIsData$' -fuzztime=30s -parallel=2
```

Native Windows tests inspect actual BER for parsed injection-shaped values,
Unicode/NUL, GUID/SID, date comparisons, flags, patterns and escaped-comma DNs.
They retain a partial permission error and verify all seven native ownership
counters return to zero. No live AD result sets, server-version matrix, AD LDS
factory profiles or Windows arm64 live execution have been qualified for this
feature. Keep issue #15 open for those checks and the stated conversion gaps.

Sources: [AD filter language](https://learn.microsoft.com/en-us/powershell/module/activedirectory/about/about_activedirectory_filter?view=windowsserver2025-ps),
[account-control flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties),
[createTimeStamp syntax](https://learn.microsoft.com/en-us/windows/win32/adschema/a-createtimestamp),
[lastLogonTimestamp representation](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp),
[groupType flags](https://learn.microsoft.com/en-us/windows/win32/adschema/a-grouptype).
