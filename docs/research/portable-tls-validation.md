# Portable TLS qualification — 18 November 2026

All sixteen Windows/Linux × LDAPS/StartTLS × AD DS server-version cells passed
using Go 1.27.4. Each cell has a public SDK TLS/RootDSE run and a separate actual
LDAP collector run. The same binaries were reused across every server profile.

| AD DS server | Observed direct TLS | Windows/amd64 | Linux/amd64 | Fresh capture and cleanup |
| --- | --- | --- | --- | --- |
| 2016 | TLS 1.2 | LDAPS + StartTLS passed | LDAPS + StartTLS passed | [manifest](portable-ldap-evidence/server2016/manifest.json) |
| 2019 | TLS 1.2 | LDAPS + StartTLS passed | LDAPS + StartTLS passed | [manifest](portable-ldap-evidence/server2019/manifest.json) |
| 2022 | TLS 1.2 | LDAPS + StartTLS passed | LDAPS + StartTLS passed | [manifest](portable-ldap-evidence/server2022/manifest.json) |
| 2025 | TLS 1.3 | LDAPS + StartTLS passed | LDAPS + StartTLS passed | [manifest](portable-ldap-evidence/server2025/manifest.json) |

Every successful direct session reported verified TLS, at least 128 cipher bits,
complete measured protection and the expected isolated AD DS RootDSE. Simple
bind did not claim Kerberos mutual authentication, channel binding or delegation.
The generic LDAP collector additionally exercised paging, binary GUID/photo
values, actual two-part DC SPN ranges, controlled mutations, rename/GUID stability,
normal LDAP 32 after deletion and an actual critical ShowDeleted tombstone read.
The shared [LDAP validation ledger](portable-ldap-validation.md) records that scope
and its actual unsupported critical-assertion response without a downgrade.

Each profile also passed eighteen controlled TLS peer cases: four verified
forwarding controls, twelve expired/wrong-host/untrusted certificate cases, and
two StartTLS refusals. Across all profiles this is 72 cases, including 48 bad
certificate cases and eight refusals. Rejected protection had zero bind envelopes,
plaintext binds, LDAP application bytes and forwarded bytes. Every refusal also
observed client EOF with zero subsequent bytes. These controlled peers are
separate from the direct AD DS session evidence; their positive controls verified
the real DC's private-CA LDAPS upstream before forwarding LDAP.

## Source and evidence identity

Actual tested source:
[`ca38eb1ac624c4452ac6aecb47ff6c3cda617d3a`](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/ca38eb1ac624c4452ac6aecb47ff6c3cda617d3a).
The separate SDK-02 runtime baseline is
`eb991333999d8c043e64627ef91f854653564236`. The provenance tool compared the raw
bytes of all 437 production Go/module files used for the SDK-03 build with the
raw committed SDK-02 Git blobs. Actual SDK-03 build files were prepared with LF
line endings before comparison and compilation. This does not claim equality to
a Windows checkout's CRLF representation. The ledger also hashes all 2,335
tracked build inputs, and each capture records the five actual binary digests.

Raw JSON, public certificates, peer observations, process output and cleanup
records are retained once under [portable-ldap-evidence](portable-ldap-evidence/).
The matching source ledger and provenance-tool source are shared with SDK-02.
No password or private key was copied into these public artifacts. Earlier failed
collector runs remain in the original host captures; their accepted effects were
independently reconciled before any fresh run. Whole-domain referral observations
were retained rather than discarded or followed automatically.

## Independent cleanup

Every run independently verified removal of its marked live directory fixture,
owned certificate stores/private key files, peer processes/private key files and
exact firewall rule. Baseline certificates were preserved. Deletion tombstones
remain as expected AD DS history. Certificate reload diagnostics, including LDAP
48 after removal of the final identity, are retained separately from the fresh
no-owned-certificate observation. The 2025 supplementary strict-trust TLS 1.2/1.3
probe independently confirmed no certificate was offered after cleanup, without
LDAP authentication or a directory mutation.

All twelve original Windows VM power states and private NIC assignments were
restored: 2016/2019/2022 off and the original 2025 trio running. The owned Linux
client was returned to its starting private 2025 switch and retained for the next
authentication milestones. Host routing and switch isolation were unchanged.

This qualifies the portable verified TLS/simple-authentication foundation on
these amd64 client/server combinations. It does not qualify Kerberos, SASL
signing/sealing, channel binding, macOS/arm64 live execution, AD LDS, every typed
service workflow or the complete SDK/provider release gate. Inventory states and
historical native evidence are unchanged.
