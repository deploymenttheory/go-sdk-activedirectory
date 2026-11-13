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
`Config.Partition` applies to `Client.Partition`; `Search` always uses its explicit
`Base`. To search a selected partition, call `Partition` and pass its returned DN
as the search base. AD LDS searches do not require AD DS capabilities or an
instance default naming context. The server still enforces the bound identity's
permissions and must support the requested paging control.

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
completed the entire search successfully. These are separate outcomes, not a
single success flag: a read stopped by the caller's own limit returns
`LimitReached` true, `Complete` **false** and a **nil error**, so testing
`err == nil && result.Complete` reports a successfully limited read as a
failure. Accept `Complete || LimitReached` where either outcome is wanted, and
reserve `Complete` alone for "the server ended the whole search". Directory
changes during paging can affect the set and order of entries; this is not a
snapshot or sorted query.

Always check the error, even when objects were returned. `*SearchError` records the
returned count and unwraps to `ErrIncompleteResult` plus the underlying errors.
`errors.As` can retrieve `*LDAPError` with its numeric status, matched DN and server
diagnostic. Size/time limits, missing bases, permission failures, unavailable
paging controls, referrals and missing paging response controls are explicit
errors. Server diagnostics are omitted from ordinary error strings.

The caller deadline and `Config.Timeout` bound the whole search, including time
queued behind another operation on the client. Native result
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

For the configured isolated `ad.sdk.test` lab, run the host action from an
elevated Windows PowerShell session:

```powershell
.\scripts\lab\lab.ps1 -Action TestSearch -ServerVersion 2025
```

The host snapshots the source and harness, builds a test binary, verifies owned
VMs, and records source/harness/binary hashes. Its guest harness owns a temporary
OU, eight marked container objects and one ordinary user. It compares
DNs, binary GUIDs, descriptions, scopes and result limits with `Get-ADObject`,
records Windows and module versions, and removes only its verified fixtures.
Fixtures are replicated before testing; cleanup is checked on both controllers.
The host retains native and reference artifacts even after guest failure and
writes `search-reference.json` with hashes, VM identity and cleanup status.
`source_dc_environment` records the owned source controller's running OS version,
build/revision and available ActiveDirectory module version. `member_reference`
records the test member's versions separately; `image` retains source-image
provenance and is not used as the controller's running version.

The permission case denies only `ReadProperty` for the description schema GUID
to the exact ordinary-user SID on one marked container, without inheritance.
It verifies that the other DACL entries are unchanged and that the ACE reached
the second controller. Administrator reads prove that both descriptions remain
set. The same ordinary credential then runs WinLDAP and `Get-ADObject`: both must
retain the target DN/GUID, omit its denied description, and return the visible
control's description. An explicitly selected omission is `AttributeAbsent`;
an unselected omission is `AttributeUnloaded`. This does not identify a hidden
value as truly unset. Credentials reach the native process only through bounded
redirected stdin; plaintext/base64 password output is suppressed. Public proof
is retained in the reference artifact and `search.json.permission.json`.

Offline guards run without directory access:

```powershell
powershell.exe -NoProfile -File scripts/lab/test-search-fixture-cleanup.ps1
powershell.exe -NoProfile -File scripts/lab/test-search-permission.ps1
```

After the owned LDS fixture has been configured, qualify search separately:

```powershell
.\scripts\lab\lab.ps1 -Action TestLDSSearch -ServerVersion 2025
```

This read-only action reuses the owned application partition and native LDS
reader over validated LDAPS on both explicit instance ports. It compares raw
base, one-level and subtree results with a PowerShell-hosted
`System.DirectoryServices.Protocols.LdapConnection` using the same SIMPLE
credential. Page size one exercises multiple pages; caller-limit results must
match a member of the complete reference set because LDAP order is unspecified.
Zero results, a missing base, binary GUIDs, selected attributes, native allocation
cleanup and the replica's absent default partition are checked. AD DS capability
rejection is recorded separately from authorization; successful reader searches
do not establish broader access rights. The existing LDS fixture is retained and
no directory objects or permissions change. Process, reference connections and
host sessions are cleaned up, with source/harness hashes and actual LDS server
and test-client versions recorded separately from ISO provenance.

Server 2016/2019/2022/2025, AD LDS and real directory permission outcomes
remain pending until those artifacts are recorded. See the
[native contract notes](research/winldap-paging.md).
