# Portable Kerberos validation

**Draft qualification status, 2026-11-18:** implementation and local checks are
ready for review. The full Windows/Linux × Server 2016/2019/2022/2025 lab matrix
and required PR CI remain completion gates. The final Server 2025 runner passed
all 84 cases and independently verified its cleanup. Server 2019 also passed all
84 cases with the same SDK binaries. Both profiles have verified outer account,
TLS and credential teardown; Server 2016/2022 remain pending. This document does
not claim SDK-04 or SDK v1 complete.

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

### Completed Server 2025 runner

The final [shared manifest](portable-kerberos-evidence/server2025/manifest.json)
records both operating systems, `Scope=All`, no case filter, all five final
binaries, and all 84 passing process cases from the actual source above.
The [authentication artifact index](portable-kerberos-evidence/server2025/artifact-index.json)
retains 40 authentication cases and common provenance, policy and cleanup bytes.
Those 40 comprise 32 actual protocol/context cases and eight local refusals.
The remaining 44 SASL cases are retained by the separate SDK-05 qualification.

Both clients passed all five credential variants over LDAPS and StartTLS.
All eight missing/tampered binding probes received actual LDAP 49 with
`SEC_E_BAD_BINDINGS(0x80090346)`, observed no final acceptance and made no
application request. See representative
[Linux missing-binding](portable-kerberos-evidence/server2025/auth-linux-ldaps-cbt-missing.json)
and [Windows tampered-binding](portable-kerberos-evidence/server2025/auth-windows-starttls-cbt-tampered.json)
records. Each of the four active service-expiry probes observed a real short
service deadline, read before it and refused operation admission after it.

The [strict-policy readback](portable-kerberos-evidence/server2025/strict-policy.json)
records CBT Always (`2`), signing required (`2`) and the Server 2025 enforcement
override (`1`). It deliberately does not claim enforcement from registry values
alone. The actual negative probes above supply that separate evidence.
[Before](portable-kerberos-evidence/server2025/credential-digests-before.json)
and [after](portable-kerberos-evidence/server2025/credential-digests-after.json)
digests verify all five caller credential files remained unchanged on both
systems. [Runner cleanup](portable-kerberos-evidence/server2025/directory-policy-cleanup.json)
independently confirms contact/child-OU removal and exact policy restoration;
[Windows](portable-kerberos-evidence/server2025/windows-files-cleanup.json) and
[Linux](portable-kerberos-evidence/server2025/linux-files-cleanup.json) execution
files were reconciled.

The separate [outer cleanup](portable-kerberos-evidence/server2025/outer-cleanup.json)
then confirmed the owned user/parent absent on both DCs and the original exact
policy presence, type and values. It retired five member credential files,
eleven Linux credential files (including the failed early `krb-` directory and
an extra expired cache), and six host private files including `client.clixml`.
Original Linux private directories and the host secrets directory are absent.
Public journals/configuration were preserved under `retired-public-*`; member
public binaries/results remain. No private payload was published.

[TLS cleanup](portable-kerberos-evidence/server2025/outer-tls-cleanup.json)
verified original certificate baselines and zero owned certificates/private
keys. The independent [store-set comparison](portable-kerberos-evidence/server2025/outer-store-reconcile.json)
also matched all four original stores exactly, including all fourteen machine
roots. A separate [strict-trust probe](portable-kerberos-evidence/server2025/outer-tls-probe.json)
opened fresh LDAPS and StartTLS connections with both TLS 1.2 and 1.3; all four
observed no peer certificate and no cached owned leaf, without credentials or
directory mutations. The [executed cleanup source](portable-kerberos-evidence/server2025/outer-cleanup-executed.ps1.txt)
and [probe source](portable-kerberos-evidence/server2025/outer-tls-probe.py.txt)
are retained. An initial cleanup stopped on a PowerShell array-construction
error after directory/member retirement. The successful attempt reconciled
already-absent paths before completing Linux/host cleanup; it did not replay
directory writes. Its first executed source is preserved separately.

### Completed Server 2019 runner

The [shared manifest](portable-kerberos-evidence/server2019/manifest.json)
records all 84 passing Windows/Linux cases with the same actual SDK source and
five binaries. The [artifact hashes](portable-kerberos-evidence/server2019/artifact-hashes.json)
retain 113 authentication/common records; the separate
[SASL hashes](portable-sasl-evidence/server2019/artifact-hashes.json) retain 249
records. The profile again distinguishes 68 actual AD protocol/context cases,
12 local configuration refusals and four local expired-credential refusals.

Both DCs required the [documented Kerberos correction](server2019-kerberos-servicing.md)
before the unchanged SDK could qualify. Failed pre-update observations remain
separate. The [outer cleanup](portable-kerberos-evidence/server2019/outer-cleanup-20261118t184208831z.json)
verified owned objects absent on both DCs, exact policy/certificate baselines,
no owned TLS leaf, and retirement of Windows/Linux/host private credential files.
All three Server 2019 VMs were restored to their original Off state.

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
