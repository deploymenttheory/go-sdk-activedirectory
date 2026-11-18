# Portable LDAP implementation validation

The tested SDK-02 runtime is commit
`eb991333999d8c043e64627ef91f854653564236`, using Go 1.27.4. Later documentation
commits retain these captures without relabeling the tested source. This report
covers portable TLS simple-bind sessions and their protocol dependencies.
Public portable Kerberos execution remains unavailable; these results do not
qualify ticket acquisition, real Kerberos/SASL interoperability or SDK v1.

## Source and dependency identity

The recorded Git source archive contains 2323 files and has SHA-256
`5594b41b544f51e44ae54367ee5a27e02d3e2cc19b21d25e7fbc0c99ccaab955`.
Its retained [per-file manifest](portable-ldap-evidence/source-manifest-eb99133.json)
has SHA-256
`a0d24e2bcd3f9ab7ed482e7ed2a7e6ac39ddacee8ea1aac0bd0c22cf373a8a02`.
The [validation record](portable-ldap-evidence/validation.json) records capture
hashes and command outcomes. Raw evidence bytes are preserved by `.gitattributes`.
That Windows Git archive applied CRLF checkout conversion to text files. Its
per-file hashes describe those captured bytes. The shared lab collector's
production-file identity check compares its actual LF build files with raw
SDK-02 committed Git blobs; it does not claim raw identity with a Windows
checkout or the archive's line-ending variant. Normalizing only archived
Go/module line endings reproduces the corresponding LF source hashes.

The owned LDAP base is official `go-ldap/ldap`
`a41b2a26f37f9bda6d29f97904389dd733dfea84`; the owned Kerberos base is official
`jcmturner/gokrb5` `855dbc707a37a21467aef6c0245fcf3328dc39ed`.
Their `UPSTREAM.json`, licenses and `PATCHES.md` files describe ownership and
local changes. Root dependency pins include `x/crypto v0.59.0` and
`x/net v0.63.0`. The final [vulnerability check](portable-ldap-evidence/vulnerability-check.log)
reported no affected symbols, imported packages or required modules. That is a
dated dependency check; it does not replace review of the owned protocol code.

## Local and independent consumer checks

| Check | Recorded result |
| --- | --- |
| Full Windows amd64 `go test -mod=readonly -count=1 ./...` | [Passed](portable-ldap-evidence/windows-tests.log) |
| Windows amd64 `go vet ./...` | Passed |
| golangci-lint 2.15.0, retained checks and 180-character Go limit | Passed, 0 issues |
| Coverage contract | Passed, 151 cmdlets; no inventory promotion |
| Linux amd64 race detector, SDK and owned protocol packages | [20 tested packages passed](portable-ldap-evidence/linux-race-result.json), [log](portable-ldap-evidence/linux-race.log) |
| Fresh independent OpenLDAP fixture, full owned LDAP/GSS suite with race detector | [Passed](portable-ldap-evidence/openldap-linux-race.log) |
| Independent downloaded module ZIP consumer | [Passed](portable-ldap-evidence/module-consumer.json) |

The OpenLDAP fixture was reset independently from the Windows fixture. It uses
`osixia/openldap:1.5.0`, image digest
`18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28`.
It proves retained LDAP interoperability against a disposable owned service.
Upstream fixture convenience tests include their own relaxed TLS setup; this
is separate from the SDK's mandatory certificate verification and live AD tests.

The canonical module ZIP was created with `golang.org/x/mod/zip v0.43.0`.
All 2323 intended files, including all 262 third-party files, were included with
zero nested modules, replacements or canonical omissions. Its SHA-256 is
`1ea1bad9d62421514cef03316c4a702634a5f250a6bb862759469d565298ea63`.
A fresh independent consumer downloaded that identical ZIP through a local
file proxy with `GOWORK=off`, resolved 58 SDK package imports from the downloaded
module, executed unit tests on Windows/Linux amd64 and built for
Windows/Linux/macOS amd64 and arm64. These are packaging and compilation checks;
cross-builds do not establish arm64 or macOS directory runtime qualification.

Owned wire tests cover verified LDAPS/StartTLS simple bind, binary values,
paging and opaque repeated cookies, base/ranged reads, critical controls,
Add/Modify/Delete/ModifyDN, actual refusals, partial observations, malformed
results, lost acknowledgements and cancellation. Response fuzzing completed
138834 executions in the recorded ten-second run. Four AES profiles retain
known cryptographic vectors and protected-frame regressions. Passing generated
GSS exchanges does not establish live Kerberos acceptance.

## Actual AD lab acceptance

The actual shared collector build is
[`ca38eb1ac624c4452ac6aecb47ff6c3cda617d3a`](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/ca38eb1ac624c4452ac6aecb47ff6c3cda617d3a).
Its [source ledger](portable-ldap-evidence/collector-source-ca38eb1.json) records
all build inputs and proves that 437 production Go/module files used for that
build are byte-identical to the committed SDK-02 runtime above. The
[identity check](portable-ldap-evidence/runtime-identity.json) explains the
comparison and records the retained [provenance tool](portable-ldap-evidence/portable-source-provenance.go.txt).
Each profile manifest records the actual source revision, binary hashes,
server/profile identity and capture times. The exact tested collector is also
included in this PR; it is not relabeled as having run from a later docs commit.

All 16 Windows/Linux amd64 × LDAPS/StartTLS × server-version SDK cells passed,
with 16 direct public TLS positives and 72 controlled TLS peer cases. See the
[machine-readable matrix](portable-ldap-evidence/ad-matrix.json).

| AD DS server | Windows LDAPS | Windows StartTLS | Linux LDAPS | Linux StartTLS | Measured direct TLS |
| --- | --- | --- | --- | --- | --- |
| 2016 | [Pass](portable-ldap-evidence/server2016/windows-ldaps-sdk.json) | [Pass](portable-ldap-evidence/server2016/windows-starttls-sdk.json) | [Pass](portable-ldap-evidence/server2016/linux-ldaps-sdk.json) | [Pass](portable-ldap-evidence/server2016/linux-starttls-sdk.json) | TLS 1.2 |
| 2019 | [Pass](portable-ldap-evidence/server2019/windows-ldaps-sdk.json) | [Pass](portable-ldap-evidence/server2019/windows-starttls-sdk.json) | [Pass](portable-ldap-evidence/server2019/linux-ldaps-sdk.json) | [Pass](portable-ldap-evidence/server2019/linux-starttls-sdk.json) | TLS 1.2 |
| 2022 | [Pass](portable-ldap-evidence/server2022/windows-ldaps-sdk.json) | [Pass](portable-ldap-evidence/server2022/windows-starttls-sdk.json) | [Pass](portable-ldap-evidence/server2022/linux-ldaps-sdk.json) | [Pass](portable-ldap-evidence/server2022/linux-starttls-sdk.json) | TLS 1.2 |
| 2025 | [Pass](portable-ldap-evidence/server2025/windows-ldaps-sdk.json) | [Pass](portable-ldap-evidence/server2025/windows-starttls-sdk.json) | [Pass](portable-ldap-evidence/server2025/linux-ldaps-sdk.json) | [Pass](portable-ldap-evidence/server2025/linux-starttls-sdk.json) | TLS 1.3 |

Every SDK cell exercised copied binary GUID/photo readback, paging and cookie
release, actual `servicePrincipalName;range=0-0` then `1-*` continuation matching
all 22 normal SPN values, critical permissive modification, Add/ModifyDN/Delete,
normal LDAP 32 absence and show-deleted tombstone identity. Assertion was
unadvertised in all cells: each recorded an actual rejected LDAP 12 for the
critical probe and unchanged readback. Its requested change was never retried
without the assertion; a separate permissive duplicate-add operation passed.
These captures qualify unsupported-control refusal, not assertion acceptance.

Tests scope groups to `CN=Users` and the DC computer to `OU=Domain Controllers`
within the lab naming context, avoiding subordinate naming-context references
while preserving the SDK's incomplete-result behavior. The 72 controlled TLS
cases comprise 16 valid peers, 48 untrusted/expired/wrong-name rejections and
8 StartTLS refusals; rejected peers observed no bind requests. These are owned
controlled peers alongside each AD profile, not claims that AD presented an
invalid certificate.

Independent cleanup verified zero owned live directory objects, certificates,
private-key files, peer processes or firewall rules and no cached owned leaf.
Normal AD deletion tombstones were retained. Original stores were preserved;
all cleanup results and raw process/peer records are retained per profile.
The [stdin checks](portable-ldap-evidence/stdin-validation.json) separately verify
bounded JSON, missing/unknown fields, trailing objects and request non-echo.

These captures do not advance the 151-operation coverage inventory. Native
evidence and planned identifiers do not qualify a portable implementation.
