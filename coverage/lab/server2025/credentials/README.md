# Explicit Negotiate credential qualification

Run `credentials-20261112T144101Z-7ba37309` passed on 2026-11-12 against the
isolated Server 2025 two-DC/member profile. The test binary ran on the member and
contacted `ADSDK25DC1.ad.sdk.test`.

| Property | Observed value |
| --- | --- |
| Guest OS | Windows Server 2025, build 26100.32230, AMD64 |
| Windows PowerShell / AD module | 5.1.26100.7462 / 1.0.1.0 |
| Schema / domain and forest levels | 91 / Windows Server 2016 |
| Go toolchain | go1.26.5 windows/amd64 |
| Native dependency | v0.6.1-0.20261112134443-9f51cb95639f |

`credentials-reference.json` records source, harness, and executable hashes,
native test output, PowerShell comparisons, version metadata, and cleanup.
`credentials.json` records the native results. Every recorded source and harness
hash matched the delivery worktree before retention; copied artifacts were also
checked byte-for-byte against their originals. The complete snapshots remain at
`H:\ad-sdk-lab\server2025\results\credentials-20261112T144101Z-7ba37309`.

The fixture used a non-ASCII account name and a password containing non-ASCII
and supplementary Unicode characters. Both separate domain/account and UPN
with omitted domain authenticated successfully. Each read RootDSE after the
temporary native identity buffers were erased; server and naming context matched
PowerShell under the same identity. Signing and sealing options remained enabled.

A valid container creation succeeded under the current identity (LDAP 0), then
failed under each explicit ordinary-user identity (LDAP 50). PowerShell confirmed
the same permission boundary. Wrong and empty explicit passwords returned LDAP
49 without current-identity fallback. Fixture ownership and removal were checked,
and absence was confirmed on both domain controllers before the run passed.

Credentials reached the native executable through redirected standard input,
without secret arguments, environment variables, or credential files. Retained
errors contain types and numeric codes, not exception messages or secret input.
Offline regressions additionally verify independent cleanup failures, ownership
guards, aggregate error preservation, and native permission-code classification.

This qualifies the issue #10 explicit-credential slice on the recorded Server
2025 build. It does not establish TLS/Basic, AD LDS, older-server explicit binds,
Kerberos selection, a hard aggregate Negotiate deadline, or complete
`Get-ADRootDSE` parity. Native ARM64 execution is covered by unit CI, not an ARM64
directory guest run.
