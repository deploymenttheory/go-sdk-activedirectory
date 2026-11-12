# Directory discovery and topology reads

The SDK provides native domain-controller location, current Windows domain
names, and authenticated LDAP projections for domains, forests, controllers and
trusts. These are development slices of ticket #27. Full identity forms, general
filter languages, property/range handling and reference qualification remain
unfinished. The API does not provide complete `Get-ADDomainController`,
`Get-ADDomain`, `Get-ADForest`, or `Get-ADTrust` parity. The
[coverage report](coverage.md) remains unverified for those operations.

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

## Authenticated directory projections

The service uses the existing client's endpoint, authentication and transport:

```go
directory := client.Directory()
domain, err := directory.Domain(ctx, activedirectory.DomainOptions{})
// DomainOptions{DistinguishedName: "DC=child,DC=example,DC=com"}
// selects an explicit domain NC on this same connection.
forest, err := directory.Forest(ctx)
controller, err := directory.DomainController(ctx,
    activedirectory.DomainControllerOptions{}) // connected server
// DomainControllerOptions{ServerDN: "CN=DC1,CN=Servers,..."}
// selects a server object, not a computer or NTDS-settings DN.

readOnly := true
controllers, err := directory.DomainControllers(ctx,
    activedirectory.DomainControllersQuery{
        IsReadOnly: &readOnly, PageSize: 32, ResultLimit: 10,
    })
trusts, err := directory.Trusts(ctx, activedirectory.TrustQuery{
    LDAPFilter: "(trustDirection=3)", Properties: []string{"description"},
})
trust, err := directory.Trust(ctx, "CN=partner.example,CN=System,...",
    activedirectory.TrustOptions{})
```

Check each error before using that call's result as complete. The examples show
independent calls; applications must handle their errors individually.
Domain and controller collection scope defaults to `Config.Partition`, then
RootDSE's `defaultNamingContext`. Forest reads use the endpoint's configuration,
schema and root-domain naming contexts. Every query stays on the original
connection; inaccessible links and referrals do not trigger discovery or rebinds.

| Projection | Implemented reads |
| --- | --- |
| Domain | Domain NC values and raw GUID/SID; functional level; suffixes and logon interval; manager, raw `gpLink` and subordinate references; all returned well-known container mappings; cross-reference DNS/NetBIOS names, parent/children; PDC, RID and infrastructure role owners; DSA replica identities and hosts. |
| Forest | Partitions-container functional level and suffixes; domain/application/external cross-reference observations; sites; configured GC candidates; schema and domain-naming role owners. Disabled cross-references remain visible with their enabled state. |
| Controller | Separate server, DSA, computer and site objects; GUIDs distinct from invocation ID; computer SID/account/OS values; enabled state; DSA generation, configured GC and RODC state; replica-kind records and deduplicated partitions; five role memberships with an explicit known/unknown flag. Live GC readiness is populated only for the connected DSA. |
| Trust | One explicit TDO DN or a scoped LDAP collection; partner name, flat name, partner SID, raw direction/type/attribute mask and encryption metadata; extra selected raw properties. Unknown numbers/bits survive decoding. |

Well-known containers use the server's `wellKnownObjects` GUID/DN mappings, so a
redirected Computers/System/Infrastructure container does not require a guessed
DN. [Microsoft well-known-object specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5a00c890-6be5-4575-93c4-8bf8be0ca8d8).
Controller scope uses `msDS-HasDomainNCs`, while writable, read-only full and
partial replicas remain distinct. RODC classification resolves `objectCategory`
to its schema class, and the GC option represents configuration separately from
readiness. [Microsoft DSA specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ebf2419-1169-4413-88e2-12a5ad499cf5).

`DomainControllersQuery` supports explicit domain/site scope and nullable GC/RODC
criteria. Its result limit applies after those criteria. Candidate DSA pages are
currently read before joins, so a result limit does not cap the number of DSA
objects read. `LimitReached` means the caller stopped the projection; it does
not prove that another matching controller exists. Missing criterion values
produce a partial-result error instead of being coerced to false.

Trust queries default to the selected NC's well-known System container, with
one-level scope. `BaseDN` selects a container explicitly and is mutually
exclusive with `DomainDN`. This supports recording an LDS schema/query outcome
without imposing an unverified DS-only rule. It does not prove that the
PowerShell cmdlet supports that LDS operation. The default trust properties
exclude trust authentication secrets; explicitly requested raw properties,
especially `*`, can contain sensitive information.

## Partial results and deadlines

Every operation derives one deadline from the caller and `Config.Timeout`, then
passes it through sequential public `RootDSE` and `Search` reads. This includes
waiting for the first client gate. Calls can interleave with other operations;
these reads do not constitute an atomic snapshot. Native cleanup may finish
after a deadline according to the underlying search contract.

`DirectoryObservation` records the endpoint, RootDSE and every returned raw
object, including partial pages and repeated linked reads. `Complete` means the
planned reads/conversions finished; it does not prove visibility of all directory
objects or attributes. Nil scalars preserve unavailable values. Raw binary
GUIDs/SIDs retain LDAP byte representation; shared typed identity conversion is
still to be integrated. `Object.Attribute` retains unloaded, absent, present and
ranged states. Unreturned values do not distinguish unset from access-hidden.

A `DirectoryReadError` unwraps `ErrIncompleteResult` and the underlying LDAP,
capability, decode or context error. Partial fields remain available. An empty
successful collection is distinct from a failed or missing identity read;
`ErrDirectoryObjectNotFound` means no matching object was returned, not proof
that it does not exist. Ranged values remain raw with an explicit incomplete
error; this layer does not yet retrieve subsequent ranges.

## Remaining acceptance boundary

- #13 is the shared identity-resolution and typed/raw attribute-preservation
  seam: domain/forest GUID, SID, DNS/NetBIOS and object references; DC host/IP,
  GUID, DSA/computer/reference identities; trust identity forms; and verification
  of Current selections against the explicit endpoint remain unfinished here.
- #14 supplies escaped typed LDAP filters and the raw LDAP alternative. Current
  fixed schema queries use private literal escaping; they should reuse that
  shared surface when integrated.
- #15 supplies the AD PowerShell-style filter parser. General domain-controller
  semantic filters must handle joined properties and apply limits after matching;
  the few explicit criteria above do not implement that language.
- Additional property selection, typed conversion and range retrieval remain
  implementation gaps. They are not assigned to #15.
- Trust InputObject mapping, partner-name identity, forest-versus-domain scope
  and exact LDS applicability still require reference probes. The current API
  states its narrower LDAP scope explicitly.
- Complete property-by-property comparison, real trust positives, RODC/GC and
  multi-domain topology, permissions, transport, Server 2016/2019/2022/2025 and
  native arm64 evidence remain required by the research inventory.

These are implementation seams and acceptance gaps, not new tracker dependency
edges: #27's recorded native dependency remains closed #9. See the
[research report](research/native-directory-discovery.md) for the full inventory
and empirical probe matrix.

## Validation status

The reference harness is being developed separately from the runtime API.
`directory_reference_test.go` currently supplies portable, allowlisted fact
extraction/comparison and profile validation. `core` requires positive domain/DC
metadata; `topology` additionally requires an RODC, GC/non-GC controllers and
multiple domains; `trust` requires an external AD TDO identity plus successful
secure-channel verification records for every configured trust direction;
`extended` requires both positive profiles. Empty results cannot satisfy these
profiles. Facts tagged `.schema` identify supplemental LDAP-attribute comparisons,
not proven PowerShell property-alias parity; `.binary` comparisons preserve case.

This is a tested scaffold only: the PowerShell reference collector, actual
`netdom trust /verify` execution, opt-in native test entry point, artifact writing
and lab orchestration are not yet implemented. A supplied verification record
is validated for structure/direction only; this scaffold cannot establish its
provenance or claim a real trust was verified. The eventual collector must
execute verification and retain binary/script/source hashes and fixture
provenance. Microsoft documents `/verify` as secure-channel secret verification;
the harness must never use `/reset`, `/add` or `/remove` for this comparison.
[Netdom trust documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netdom-trust).
No reference run or new lab qualification has been performed by this scaffold.

Development of directory projections integrates draft prerequisites #11 at
`5799c70d51b4b679c2e3d46bfac7bce5c0dee5cd` and #12 at
`2255df40c151faaca1808d40719e46562f13ec90`. The TLS merge resolved the two
documentation indexes; the search merge resolved those indexes, the shared
session interface and test seam, generated-binding pin/checksums, native API
fields and response parsing, and the lab action list. Both feature sets are
retained. Shared response parsing now uses bounded UTF-16 copying and frees
failed-parse string outputs without reading them. These prerequisite commits
are development inputs, not landed or live-qualified dependencies. Ticket #27
cannot merge or close until both prerequisites land and its own full evidence
is complete.

The projection layer now uses those public APIs without changing the client gate
or copying their implementation. Its portable tests exercise redirected
containers, role/topology joins, separate identifiers, RODC/GC state, limits
after criteria, signed/unknown masks, LDS guard boundaries, empty versus partial
outcomes, malformed/ranged values, native error preservation and one composite
deadline. Its trust objects are synthetic injected records, not a real trust
fixture or reference evidence.

Local tests check portable validation, exact native flag mapping, injected native
and cleanup failures, buffer copying, optional/malformed values, cancellation,
bounded username retries and real NetAPI allocation/release. They do not contact
a directory. Live cache/site/service behavior, current-context equivalence,
RODC/GC selection, real trusts, and Server 2016/2019/2022/2025 comparisons remain
required evidence. No operation's coverage status is advanced by these local tests.
