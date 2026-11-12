# Directory search

`Client.Search` performs an LDAP search against the connection's explicit endpoint.
It supports base, one-level and subtree scope, raw selected attributes, paging,
caller limits and cancellation. Execution requires Windows amd64 or arm64; options
and result types can be used on Linux and macOS. No PowerShell, RSAT or agent is
used at runtime.

```powershell
go run ./examples/search -server dc1.ad.sdk.test -base 'DC=ad,DC=sdk,DC=test'
```

The example uses the current Windows identity and prints up to 100 objects. The
[connection documentation](connection.md) describes explicit credentials.

```go
result, err := client.Search(ctx, activedirectory.SearchOptions{
    Base:        "OU=People,DC=example,DC=test",
    Scope:       activedirectory.ScopeSubtree,
    Filter:      "(objectClass=user)",
    Properties:  []string{"name", "objectGUID", "description"},
    PageSize:    256,
    ResultLimit: 0,
})
```

`Filter` is an LDAP filter, corresponding to `Get-ADObject -LDAPFilter`. This API
does not interpret PowerShell expressions. An empty filter selects `(objectClass=*)`.
`Base` is used exactly as supplied; an empty base selects the server root entry.
The zero scope is `ScopeBase`. No domain or naming context is inferred.

An empty property list requests `distinguishedName`, `name`, `objectClass` and
`objectGUID`. A supplied list replaces those defaults. `"*"` requests user
attributes the server returns for that wildcard; operational properties may need
explicit names. `"1.1"` alone requests only the entry DN and no attribute values.
The server validates LDAP filter grammar, DN syntax and attribute availability.

`Object.Attributes` contains lowercase LDAP attribute descriptions and owned byte
slices. Binary values, including `objectGUID`, are never converted through text.
`Object.DistinguishedName` is available even when it was not selected as a property.
`Object.Attribute` reports one of four states:

| State | Meaning |
| --- | --- |
| `AttributeUnloaded` | Not explicitly selected and not returned. |
| `AttributeAbsent` | Explicitly selected but not returned; ACLs or policy may hide it. |
| `AttributePresent` | The complete returned value set is available. |
| `AttributePartial` | A ranged description was returned; inspect its raw key. |

An unreturned name selected only through `"*"` stays unloaded because the SDK does
not know whether the name denotes an operational attribute. Ranged values remain
under their returned description, such as `member;range=0-1499`, and cause an
incomplete-result error. Range continuation is outside this API's current scope.

Page size defaults to 256. Zero result limit reads until the server sends an empty
paging cookie, including through empty intermediate pages. A positive limit caps
the objects returned. `LimitReached` reports that the caller's bound stopped the
search; it does not prove additional matches exist. `Complete` means the server
completed the entire search successfully. Directory changes during paging can
affect the set and order of entries; this is not a snapshot or sorted query.

Always check the error, even when objects were returned. `*SearchError` records the
returned count and unwraps to `ErrIncompleteResult` plus the underlying errors.
`errors.As` can retrieve `*LDAPError` with its numeric status, matched DN and server
diagnostic. Size/time limits, missing bases, permission failures, unavailable
paging controls, referrals and missing paging response controls are explicit
errors. Server diagnostics are omitted from ordinary error strings.

The caller deadline and `Config.Timeout` bound the whole search. Native result
waits poll at most every 50 milliseconds. Native send timeouts have one-second
granularity, rounded upward. Releasing a known server cookie uses a separate
cleanup allowance of at most 100 milliseconds, plus bounded native send time.
Cleanup failures are returned with any already copied objects.

Cancellation of an outstanding page abandons the request and retires the
connection because the server cookie may have changed. A cleanup timeout or
uncertain submission also retires it. Subsequent operations return `ErrClosed`;
create a new client when another operation is needed. Cancellation makes no
claim that a future submitted mutation was rolled back. Successful caller-limit
cleanup preserves the connection for reuse.

The server must support LDAPv3 and the critical simple-paged-results control
`1.2.840.113556.1.4.319`. Authorization is enforced by the server. Searches remain
pinned to their endpoint; referrals are reported as incomplete instead of being
silently chased.

## Validation

```powershell
go test ./...
go test . -run TestNativePagedSearch -count=1 -v
go vet ./...
```

The native suite uses real WinLDAP against an isolated loopback LDAP responder.
It covers zero/one/many pages, empty intermediate pages, limits, binary values,
ranges, server size/time/permission/capability errors, cancellation, cleanup
failures, a stalled cleanup response, and 100 repeated calls with balanced native
allocation counters. Portable tests cover options, attribute state and client
serialization. These tests do not establish AD server-version parity.

For the isolated `ad.sdk.test` lab, build the root test package and run the
reference harness from an authenticated lab member with the ActiveDirectory
module installed:

```powershell
go test -c -o search.test.exe .
$hash=(Get-FileHash .\search.test.exe).Hash
.\scripts\lab\reference-search.ps1 -Executable (Resolve-Path .\search.test.exe) `
    -ResultPath C:\ad-sdk-validation\search.json -Server dc1.ad.sdk.test `
    -ExpectedHash $hash
```

The harness owns a temporary OU and eight marked container objects. It compares
DNs, binary GUIDs, descriptions, scopes and result limits with `Get-ADObject`,
records Windows and module versions, and removes only its verified fixtures.
It writes the native artifact and a `.reference.json` companion with cleanup
status. Server 2016/2019/2022/2025, AD LDS and real directory permission outcomes
remain pending until those artifacts are recorded. See the
[native contract notes](research/winldap-paging.md).
