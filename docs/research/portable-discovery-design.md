# Portable explicit-domain discovery basis

SDK-10 (#175) adds an explicit portable discovery boundary. Existing native
`DiscoverDomainController` and `CurrentDomain` remain Windows APIs; Linux/macOS
do not acquire a Windows join state or calling-thread identity. Broader native
identity/filter/property/trust and reference-parity work remains tracked in #78.

## Candidate observations

[MS-ADTS DNS discovery](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7fcdce70-5205-44d6-9c3a-260e616a2f04)
defines the domain DC query `_ldap._tcp.dc._msdcs.<domain>` and the site-specific
form `_ldap._tcp.<site>._sites.dc._msdcs.<domain>`. Lookup sends one absolute name
through Go's resolver, retaining SRV priority/weight/target/port and canonical
name/address observations. It does not authenticate, send an LDAP ping, infer
service flags or implement automatic locator failover.

The production path creates a fresh standard-library resolver using normal OS
DNS selection. In installed Go1.27.4, forcing the Go resolver on Windows skips
private DNS adapters without a gateway; the normal Windows DNS API respects
those configured adapters. No gateway/route, DNS setting or AD join identity is
created. The exact installed implementation and failed first live observation
are [retained](portable-discovery-evidence/failed-live-cd15/README.md).

OS DNS queries can complete after their context is cancelled. Each lookup has a
private buffered completion boundary so the aggregate caller wait remains
bounded, completed partial responses remain incomplete and late results cannot
mutate returned observations. The OS owns any still-running native query until
it finishes; the SDK neither waits beyond cancellation nor retries a query.

[RFC2782](https://www.rfc-editor.org/rfc/rfc2782.html) distinguishes service
advertisements from address records and requires SRV targets to be names rather
than aliases. A root target advertises unavailable service. The SDK rejects
unusable/alias/missing responses and incomplete observations; it groups records
by advertised host/port. Multiple legitimate A/AAAA addresses remain one host
identity. A caller must explicitly select a host, and a port when that host has
multiple advertised endpoints. Priority/weight values are preserved, not used
to try another endpoint after authentication fails.

DNS input uses literal ASCII DNS labels, optional trailing root dots and the
existing connection API's host syntax; no IDNA, credential or DNS-suffix rewrite
occurs. DNS site labels have the DNS label limit; explicit LDAP site constraints
retain ordinary directory text. Queries obey the DNS name-length limit. A 4,096
record/address budget bounds materialization; exceeding it is incomplete, not
proof that DNS or the directory is empty. Go's resolver does not expose TTL or
DNSSEC validation, so the result claims neither. The canonical name is the
value reported by the platform resolver, not an independent raw DNS owner
measurement.

## Authenticated identity

Microsoft explicitly supports [disjoint namespaces](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/disjoint-namespace):
a DC can register host addresses outside its AD domain's DNS suffix while
continuing to publish SRV records under the AD domain. Consequently hostname
suffixes never establish domain membership and are not a rejection criterion.

The advertised LDAP port and the explicitly configured transport port are
independent. For normal AD advertisements on 389, the caller can explicitly
select LDAPS on 636 for the same selected hostname; the SRV record remains 389,
and no connection to 389 is attempted. DNS never chooses or rewrites transport.

The caller configures one endpoint and its protected authentication/realm/SPN.
`DialDomainController` authenticates that endpoint once and validates the same
owning session. `Discovery.ValidateDomainController` provides the verification
for an existing client. Actual complete TLS or requested SASL protection is
observed before authoritative identity reads; requested settings alone do not
establish it. No global factory, locator fallback, referral chase or endpoint
substitution exists. Failed constructor validation closes the new client and
retains partial observations.

[NC naming](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d9ee9c9f-88b7-45f1-a42b-46c5ff832684)
binds the domain DNS name to its domain NC. The implementation checks the
authenticated default NC, domain GUID/SID, and one domain
[cross-reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/cbb36818-4e8a-4d16-819e-f473d83973a9)
with matching NC/DNS name and domain/forest flags. Disabled, external, duplicate,
missing and mismatching references remain failures. Observed optional fields
remain nullable rather than being invented.

[DC existence relationships](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/803edcd5-476d-4554-a700-a9f27480c0f1)
bind the RootDSE DSA to its parent server, server reference and computer. Exact
returned base-object DNs, class values, hostnames, GUIDs, hosted domain NCs and
computer/domain SID membership are verified. Optional expected GUID/SID and
site constraints must match. All reads remain on the original connection;
foreign linked identities are refused before being followed.

After validation, existing Domain/Forest/DomainController/DomainControllers
projections use that same client. Their partial/unloaded/ranged values and
permission/transport errors remain intact. Sequential DNS, identity and topology
reads are not an atomic snapshot.

## Verification boundary

Owned UDP/TCP DNS fixtures exercise real resolver traffic, truncation, aliases,
missing/malformed answers, disjoint targets, multiple addresses, ambiguity and
cancellation. Real TLS LDAP fixtures exercise protected authentication, identity
relationships and the existing topology projections, with wrong-domain,
refusal, referral, partial, connection-loss and cleanup cases. Real owned
Kerberos exchanges cover three credential sources and all supported protection
profiles. These are offline fixtures, not AD qualification. Linux/Windows
Server2016/2019/2022/2025 live evidence and required PR CI remain separate gates.
