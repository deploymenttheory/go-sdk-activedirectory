# Current-identity connection qualification

Run `connection-20261112T132801Z-b7861b20` passed on 2026-11-12 against the
rebuilt isolated Server 2025 lab. The test binary ran on the domain member and
contacted the explicitly selected `ADSDK25DC1.ad.sdk.test` server.

- Windows build: `26100.32230`, amd64.
- Reference Windows PowerShell: `5.1.26100.7462`; ActiveDirectory module: `1.0.1.0`.
- Forest/domain functional levels: Windows Server 2016; schema: 91, recorded in
  the [rebuild reference](../rebuild/reference-first.json).
- Go toolchain: `go1.26.5 windows/amd64`.
- Native dependency: `v0.6.1-0.20261112122428-33694fcc8fb1`, an immutable
  development commit fixing LDAP buffer ownership in upstream PR #63.

`connection-reference.json` records source/harness/binary hashes, native test
output, 21 matching PowerShell properties, and authentication-denial/cleanup
results. `rootdse.json` retains the copied raw values and measured connection
results. Source and harness hashes were checked against the delivery worktree
before retaining these files. The complete source/binary snapshot remains under
`H:\ad-sdk-lab\server2025\results\connection-20261112T132801Z-b7861b20`.

The successful run includes default, selected, and wildcard reads; typed/raw
projection; time and USN bounded by before/after reference reads; ten repeated
open/read/close cycles; invalid endpoint status; and a 1001 ms wait against an
unused private address with a one-second configured timeout (LDAP status 81).
A separate temporary local identity was rejected at bind with status 49, and
account removal was confirmed. Unit/native tests in the same executable cover
missing exports, allocation release, malformed values, partial results, abandon
failure, and concurrent Close behavior. Offline PowerShell regressions separately
cover lookup/removal failure, ownership mismatch, and accumulated cleanup errors.

These results qualify the issue #9 connection slice. They do not establish
explicit-credential/Basic/TLS behavior, AD LDS applicability, older-server
compatibility, Kerberos selection, or a hard aggregate Negotiate deadline.
The operation inventory retains those unverified requirements and does not
report complete `Get-ADRootDSE` parity.
