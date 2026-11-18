# SDK-owned LDAP source

This directory contains upstream go-ldap/ldap at commit
`a41b2a26f37f9bda6d29f97904389dd733dfea84`, with the local changes listed in
[PATCHES.md](PATCHES.md). [UPSTREAM.json](UPSTREAM.json) records the exact source
revision and original Git blob SHA256 hashes. [LICENSE](LICENSE) retains the
upstream MIT terms. The unmodified upstream README is [UPSTREAM_README.md](UPSTREAM_README.md).

Source imports use the SDK-owned path
`github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3`.
This is part of the SDK Go module: there is no nested module, embedded Git
checkout or local replacement. Go module consumers receive the actual source.
`upstream-go.mod.txt` and `upstream-go.sum.txt` are original provenance records;
the SDK root go.mod/go.sum own the dependency pins. The SDK requires Go 1.27.4.

The public SDK selects supported sessions through its engine. Portable simple
bind runs only over verified TLS; portable Negotiate and Kerberos execution
remain unavailable. Retained upstream convenience authentication APIs do not
add an SDK authentication fallback. GSS/SASL prerequisites are locally tested
protocol code, not a claim of complete Kerberos qualification.

Keep upstream unit tests and guarded response decoders when updating this source.
Ordinary `go test ./3rd_party/ldap/v3/...` runs without a directory. Upstream
integration tests require explicit `ADSDK_VENDOR_LDAP_INTEGRATION=1`,
`LDAP_TEST_URL` and `LDAPS_TEST_URL` for a disposable owned fixture. The original
Makefile and LDIF fixtures are preserved for reproducibility; the default SDK
suite does not dial the upstream hardcoded example ports.

Changes to this owned source must preserve licensing/provenance, update the patch
ledger, and include relevant protocol or interoperability regressions. Retain
security/static/error analysis and the repository's 180-character line limit.
