# Portable Kerberos validation

**Draft qualification status, 2026-11-18:** implementation and local checks are
ready for review. The full Windows/Linux × Server 2016/2019/2022/2025 lab matrix
and required PR CI remain completion gates. The fresh Server 2025 matrix is
running. This document does not claim SDK-04 or SDK v1 complete.

## Actual implementation and build source

All five current lab binaries were built with Go 1.27.4 from
[`958d4a426561bb36a5cd6104f0e253e2a7aa7b2f`](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/958d4a426561bb36a5cd6104f0e253e2a7aa7b2f).
Later workflow/documentation commits do not relabel that actual build.

The [actual-input manifest](portable-kerberos-evidence/build/source-provenance.json)
records all 2755 tracked inputs and proves the 448 production Go/module files
equal raw committed Git bytes. The independent
[canonical-input proof](portable-kerberos-evidence/build/canonical-input-proof.json)
checks every tracked input, including all 842 Go/module files, tests, examples
and embedded data. Its [verification program](portable-kerberos-evidence/build/canonical-inputs.py.txt)
uses raw Git blob identity; checkout line-ending conversion is not treated as
source equivalence. The
[binary manifest](portable-kerberos-evidence/build/binary-manifest.json) records
the two public clients, two engine test binaries and count-only fault relay.
Public/relay executables stamp `vcs.modified=false`. Go test binaries omit VCS
stamps; their checked linker label is accompanied by independent input proof.

The implementation provides explicit password, keytab and FILE-cache Kerberos,
endpoint-pinned realm/SPN and KDC exchanges, verified TLS certificate binding,
mutual authentication, actual ticket/context lifetime checks, and protected
session retirement. It never retries through NTLM, simple bind, another
credential source, backend, realm or service identity. A FILE cache requires a
valid TGT and may include the selected service credential; caller files are
read-only. MIT tools produce independent lab credentials and are not SDK runtime
dependencies.

`ChannelBindingSent` records the actual certificate-derived authenticator
binding. `ChannelBound` remains unconfirmed: mutual Kerberos authentication
does not acknowledge peer enforcement. Actual Always-policy qualification
requires the separate successful/correct and server-refused missing/tampered
binding probes. See the [authentication contract](../authentication.md).

## Completed local checks

| Check | Result |
| --- | --- |
| Go 1.27.4 full Windows amd64 `go test -mod=readonly -count=1 ./...` | [Pass](portable-kerberos-evidence/build/windows-tests.log) |
| `go vet ./...` | [Pass](portable-kerberos-evidence/build/windows-vet.log) |
| golangci-lint 2.15.0, complete changed files, retained security/static checks and 180-character Go limit | [Pass, 0 issues](portable-kerberos-evidence/build/required-lint.log) |
| Windows/Linux/macOS amd64 and arm64 full-source builds | [All six pass](portable-kerberos-evidence/build/cross-builds.log) |
| Coverage contract | [Pass, 151 operations; no inventory promotion](portable-kerberos-evidence/build/adcoverage.log) |

Owned KDC/GSS/TLS socket tests cover real encrypted AS/TGS/AP exchanges, each
credential source, mutual replies, exact certificate bindings, wrong credentials
and service identities, malformed/trailing replies, cancellation, final bind
refusal/lost acknowledgement, expiry and key retirement. SASL fixtures retain
authenticated sequence, tamper, fragmentation and uncertain-write cases. The
standalone relay records counts and termination facts without LDAP/GSS tokens.
These checks are distinct from real AD acceptance. macOS and arm64 are build/unit
targets; they have no claimed live-directory qualification.

## Four-server acceptance gate

The tracked [prepared-profile runner](../../scripts/lab/kerberos-qualification.ps1)
uses bounded stdin, immutable credential-file digests, explicit source/binary
manifests, strict policy leases and marker/GUID-owned fixtures. Its 84 process
cases per profile comprise **68 actual AD protocol/context cases, 12 local
configuration refusals and 4 local expired-credential refusals**. A local
configuration error is never counted as a server CBT rejection.

The authentication cases include password, keytab, populated/TGT-only/keytab-issued
FILE caches, correct CBT, real missing/tampered-CBT server refusals, wrong SPNs,
genuinely expired unedited MIT tickets, and active service-context expiry. The
expiry probe requests a fresh short KDC-issued service ticket, verifies its
authenticated end time, reads before expiry and checks operation admission after
the real deadline. It does not change clocks or ticket/cache timestamps.

Final per-profile records, exact policy restoration and independent account,
certificate, process, credential-file and network cleanup must be retained before
this gate is reported complete. Earlier native, TLS/simple-bind and pre-final
Kerberos captures do not qualify the current implementation.

## AD compound-layer investigation

The earlier source
[`c6bcb8ee96edab7b08dee30ce21214e62433e1bc`](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/c6bcb8ee96edab7b08dee30ce21214e62433e1bc)
allowed explicit TLS plus SASL Sign/Seal. A real Server 2025 Windows
[bind observation](portable-kerberos-evidence/investigation-c6/bind-observation.json)
recorded mutual authentication and final LDAP success with no application
operation. All four subsequent public LDAPS/StartTLS × Sign/Seal probes failed
their first protected RootDSE read:
[LDAPS Sign](portable-kerberos-evidence/investigation-c6/traffic-windows-ldaps-sign.json),
[LDAPS Seal](portable-kerberos-evidence/investigation-c6/traffic-windows-ldaps-seal.json),
[StartTLS Sign](portable-kerberos-evidence/investigation-c6/traffic-windows-starttls-sign.json),
[StartTLS Seal](portable-kerberos-evidence/investigation-c6/traffic-windows-starttls-seal.json).
The [read-probe cleanup](portable-kerberos-evidence/investigation-c6/read-probe-cleanup.json)
was independently verified; the probes made no directory/policy changes. Their
[original source/binary proofs](portable-kerberos-evidence/investigation-c6/build/binary-manifest-v2.json)
remain labelled with the earlier source. These are failed interoperability
observations, not final qualification or server authentication refusals.

MS-ADTS specifies that AD does not permit SASL integrity/confidentiality layers
on TLS. The current public validation and direct engine guard reject that
combination with `ErrInvalidConfig` before credential loading or network I/O.
Supported profiles are verified TLS with None/Default, or plain LDAP with
required Sign/Seal. Generic owned LDAP compound-layer conformance controls are
retained separately. [MS-ADTS Using SASL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/284923c1-6a5b-4510-b97a-631963c0c3bd),
[Using SSL/TLS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/2c3ea153-eff9-46a7-8614-19b677efa4e0).
