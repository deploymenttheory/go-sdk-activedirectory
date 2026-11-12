# AD LDS connection qualification

The owned member hosts two AD LDS instances in one configuration set; DC2 runs
the SDK and reference clients. The retained [fixture](fixture.json) records
service names, custom ports, configuration/DSA names, native-reader GUID, and
certificate metadata. It contains no password or private key.

The latest direct run, `lds-20261112T164046Z-a334db4e`, passed:

- Native Go LDAPS and StartTLS SIMPLE bind/read and current-identity TLS Negotiate.
- Explicit and discovered default partitions, an existing non-partition subtree,
  LDAP 32 for a missing partition, and LDAP 49 for an incorrect password.
- Explicit partition use on the replica without a default, and the precise
  missing-default error when no partition is supplied.
- AD LDS capability detection and the AD DS-only prerequisite guard.
- Seven RootDSE properties and the partition compared with AD PowerShell for
  each transport; native-user reads and both error statuses compared with .NET.

The [native result](positive/lds.json) and [reference record](positive/lds-reference.json)
retain negotiated TLS details, source/harness/binary hashes, toolchain, and guest
versions. All 33 recorded source files and nine harness files matched the source
at collection, including the failed-bind diagnostic preservation fix.
Both artifact copies were hash-checked against the host results. The guest is
Windows Server 2025 build 26100.32230, amd64, Windows PowerShell 5.1.26100.7462,
and ActiveDirectory module 1.0.1.0. This does not establish ARM64 guest or older
AD LDS server qualification.

[Repeated configuration](idempotency.json) preserved the fixture ID, root and
leaf thumbprints, and native-reader GUID, then reran the passing direct test.
The fixture remains available between tests; full profile removal destroys its
guest-local keys, trusts, services, and data. The complete LDS teardown/rebuild
is running. The strict [eight-case certificate matrix](tls-before-rebuild/lds-tls-reference.json),
`lds-tls-20261112T170431Z-524a48e1`, passed before removal. All 41 source files
and six harness files matched at collection; both copied artifacts were hash-checked.
Each SDK and .NET attempt had one matching Windows SSL-policy event with the
expected leaf, hostname, LSASS and impersonated identity, closed time/record
window, and zero policy-ignore flags. The public leaf thumbprints are tied to
the [SHA-256 certificate manifest](tls-before-rebuild/certificate-generation.json).

| Certificate | SDK and .NET policy result, both transports |
| --- | --- |
| Valid | `0`, authenticated partition read |
| Expired | `800B0101`, rejected before bind |
| Wrong hostname | `800B010F`, rejected before bind |
| Untrusted root | `800B0109`, rejected before bind |

All twelve invalid-certificate connections had zero bind requests and zero LDAP
forwarding. Both valid controls completed a validated connection to the actual
LDS backend. Temporary trust, firewall, process, and logging-state cleanup passed.
The full rebuild and qualification on fresh guests remain required before issue
#11 can close; this evidence does not establish full cmdlet parity.

The [initial certificate matrix](failed-proxy-upstream.json) rejected all six
invalid-certificate cases and confirmed cleanup, but failed both valid controls:
the proxy could not connect to its LDS backend. The
[unchanged-code upstream probe](upstream-dns-probe.json) reproduced the failure
twice before TCP connection. The member's DNS name resolved to link-local IPv6
and the expected private IPv4; the peer's address guard rejected that set. The
harness now selects the owned member's numeric IPv4, while retaining the same
certificate hostname, explicit CA, and private-address guard. No SDK TLS policy
was relaxed.

The first direct native run passed, but its reference comparison failed because
the PowerShell capability projection included display text with the OID. The
[failed reference record](failed-reference-projection.json) remains separate;
the corrected comparison uses the identifier's `Value` and has an offline
regression. [Installed help](setup-help.json), [instance setup](instances.json),
[installer 20085](installer-20085.json), and the [private-key provider observation](certificate-provider.json)
retain setup evidence. The current-user installer branch and explicit CSP
metadata accessor resolved those setup failures without storing source-account
passwords or changing the required key provider.
