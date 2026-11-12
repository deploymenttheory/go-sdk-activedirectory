# Domain-controller discovery and current domain context

The SDK can locate one advertised domain-controller candidate and resolve a
domain name from the local computer or calling Windows identity. This is the
first part of delivery ticket #27. Domain/forest/trust projections, DC identity
lookup and filtered enumeration remain unimplemented; this API does not provide
complete `Get-ADDomainController`, `Get-ADDomain`, `Get-ADForest`, or `Get-ADTrust`
parity. The [coverage report](coverage.md) remains unverified for those operations.

```go
domain := activedirectory.DomainName{
    Name: "ad.example.com",
    Format: activedirectory.DomainNameDNS,
}
candidate, err := activedirectory.DiscoverDomainController(ctx,
    activedirectory.DiscoveryOptions{
        Domain: &domain,
        Writable: true,
        Services: activedirectory.ServiceKDC,
    })
if err != nil {
    return err
}
endpoint, err := candidate.Endpoint()
if err != nil {
    return err
}
client, err := activedirectory.Dial(ctx, activedirectory.Config{
    Endpoint: endpoint,
})
if err != nil {
    return err
}
defer client.Close()
```

Discovery runs through the local Netlogon service using generated Win32
bindings. It does not authenticate the returned name, accept explicit LDAP
credentials, open a connection, or require PowerShell/RSAT. `Dial` separately
authenticates the chosen endpoint using the existing [connection API](connection.md).
The caller owns endpoint selection; no failed bind silently triggers rediscovery.

## Criteria and preferences

`DiscoveryOptions.Validate` works on every platform. Native execution requires
Windows amd64 or arm64. Domain names are tagged as DNS or NetBIOS; Windows
validates their existence and applies the host's locator policy. A nil domain
uses the local computer's domain, or its forest when requesting a global catalog.
An explicit global-catalog domain must name the forest root.

The explicit format also permits a historical dotted NetBIOS name without
guessing that it is DNS. Windows naming recommendations for creating new domains
are not a reason to reject a reference to an existing domain. See Microsoft's
[naming guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/naming-conventions-for-computer-domain-site-ou).

`Services` combines `ServicePrimaryDC`, `ServiceGlobalCatalog`, `ServiceKDC`,
`ServiceTime`, and `ServiceADWS`. Primary DC, global catalog and KDC are mutually
exclusive native criteria. Time and ADWS can accompany another service.
`Writable` requires a writable controller. `MinimumVersion` selects a minimum
DC service generation; it is separate from domain/forest functional levels.
The supported values are Windows2000, Windows2008, Windows2012, Windows2012R2
and Windows2016; the last is an SDK extension beyond the pinned cmdlet enum.

`PreferReliableTimeService` permits an ordinary time server when a reliable one
cannot be located. `NextClosestSite` tries another nearby site and may eventually
return a controller from another available site. It conflicts with `SiteName`
and `ServicePrimaryDC`. `AvoidSelf` applies only when the local machine is a DC.
These choices are recorded in `candidate.Requested`; returned service flags
describe what the candidate advertised.

Windows may use its locator cache unless `ForceDiscover` is set. Forced
discovery need not choose a different controller. Windows Server 2025 changes
NetBIOS discovery policy, so a short domain name's behavior can depend on its
mapping to DNS and the local host's configuration. See the
[research contract](research/native-directory-discovery.md) for native flags,
source references and qualification requirements.

## Results and failure behavior

`DiscoveredController` copies all returned data before releasing the native
owner. It preserves native controller/address strings, including their leading
backslashes, address type, domain GUID, domain and forest names, site information,
native flags and known advertised services. Optional string pointers distinguish
NULL from an empty native string. Unknown address-type and flag values survive.
`Endpoint` derives a DNS endpoint from the controller name; its zero port lets
the connection configuration select the default. It does not use the locator's
address field as the authentication hostname.
Names outside the connection API's current host syntax, such as a Unicode host,
remain available in the locator result even when `Endpoint` cannot convert them.

`NativeStatusError` retains the native operation and numeric Windows status;
LDAP bind/read errors remain `LDAPError`. Missing exports wrap `ErrUnsupported`.
Invalid native output wraps `ErrInvalidNativeResult`. Cleanup and cancellation
errors are retained alongside operation errors, and a non-nil error means the
result must not be treated as an unqualified success.

The locator and context APIs are synchronous Windows calls with no interruption
or timeout argument. Context cancellation is checked between calls and before
returning. A deadline cannot interrupt a running native call; the function waits
for it and releases owned memory before returning. There is no detached worker
that can keep using freed memory.

## Current domain selection

```go
domain, err := activedirectory.CurrentDomain(ctx,
    activedirectory.CurrentLocalComputer)
// Or explicitly select activedirectory.CurrentLoggedOnUser.
```

LocalComputer reads local join information and returns a NetBIOS domain name.
LoggedOnUser reads the calling security identity and returns its DNS domain
name, rather than interpreting a UPN suffix or environment variable. Neither
mode accepts explicit credentials or substitutes the other mode after failure.
Workgroup/unjoined hosts and an unmapped user identity return `ErrNoCurrentDomain`;
an unavailable domain controller retains its native lookup failure.

A caller that uses thread impersonation must lock its goroutine to the intended
OS thread before establishing impersonation and keep it there through context
resolution and authentication. The SDK keeps username resize retries on one
thread, but does not choose an interactive desktop user or establish impersonation.
Returned domain names are selection inputs, not authenticated domain objects.

## Validation status

Local tests check portable validation, exact native flag mapping, injected native
and cleanup failures, buffer copying, optional/malformed values, cancellation,
bounded username retries and real NetAPI allocation/release. They do not contact
a directory. Live cache/site/service behavior, current-context equivalence,
RODC/GC selection, real trusts, and Server 2016/2019/2022/2025 comparisons remain
required evidence. No operation's coverage status is advanced by these local tests.
