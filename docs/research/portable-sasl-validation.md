# Portable Kerberos SASL validation

Server 2025 passed the complete Windows/Linux matrix using actual source
`958d4a426561bb36a5cd6104f0e253e2a7aa7b2f` and Go 1.27.4. Server 2016, 2019
and 2022 remain pending. This draft does not yet qualify the complete four-server
matrix; unit tests do not substitute for those remaining captures.

| Server | SDK-05 checks | Actual AD / local compatibility | Independent cleanup |
| --- | --- | --- | --- |
| 2025 | 44 / 44 passed, both clients | 36 / 8 | Verified |
| 2022 | Pending | Pending | Pending |
| 2019 | Pending | Pending | Pending |
| 2016 | Pending | Pending | Pending |

The [Server 2025 hashes](portable-sasl-evidence/server2025/artifact-hashes.json)
identify 249 byte-preserved case, relay and fixture records. Common source,
binary, policy and cleanup proofs are retained once by SDK-04 under
`portable-kerberos-evidence/server2025/`. The combined profile has 84 / 84 checks
passed, including its actual AD and explicitly local checks.

## What the matrix proves

Each prepared server profile has 84 explicit checks. The manifest separates
68 checks that contact AD, 12 local configuration refusals and four local
expired-credential refusals. SDK-05 contributes 36 actual AD checks and eight
local refusals; SDK-04 contributes the other checks. Local refusals are not
server interoperability evidence.

The SASL cases use Windows/amd64 and Linux/amd64 clients with explicit password,
keytab and FILE-cache credentials. Both signing and sealing must protect a
GUID-targeted description write and its readback under the server's actual
signing-required policy. Plain LDAP's default must establish sealing. An
authenticated peer selecting signing for a client requiring sealing must fail
before any application operation. AD has no server policy requiring sealing;
sealing is the exact client requirement tested under server signing policy.

Independent pass-through controls precede opaque-record corruption,
reordering, truncated-prefix and truncated-body cases. A reordered schema read
first proves that the independent valid response exceeds one protected record.
The relay must prove it forwarded the actual fault; merely attempting injection
or causing a timeout is insufficient. Counts and protocol phases are retained;
the relay never records token bodies or keys.

A damaged mutation reply must preserve the public uncertain outcome, retire the
connection and refuse a second write. A separately established direct connection
then reconciles the owned contact by GUID. Successful reconciliation does not
retroactively turn the original unverified write result into acceptance.

## AD-specific TLS compatibility

MS-ADTS disallows a SASL traffic layer over TLS, although the generic LDAP
protocol permits layering. Actual Server 2025 accepted all four Windows
LDAPS/StartTLS × Sign/Seal binds and then reset each connection on its first
protected RootDSE read. The retained
[bind observation](portable-kerberos-evidence/investigation-c6/bind-observation.json)
and [read probe](portable-kerberos-evidence/investigation-c6/traffic-windows-ldaps-sign.json)
remain labelled with their actual pre-guard source, `c6bcb8e`.

The AD-specific SDK now returns `ErrInvalidConfig` for these profiles before
credential-file access or network activity. The eight matrix checks exercise
that local refusal and must not be described as server refusals. The owned LDAP
library retains its generic layering support and conformance tests.

## Fixture and source ownership

The tracked [qualification runner](../../scripts/lab/kerberos-qualification.ps1)
consumes the independently prepared account, TLS and MIT-reference manifests.
It records actual SDK and relay source revisions separately, verifies binary
transfers, and preserves raw source and result bytes. The SDK binaries run
directly on each client; PowerShell Direct and pinned SSH only orchestrate the
isolated lab.

The strict policy lease precedes the child contact fixture. The dedicated client
receives only description WriteProperty on that owned contact, with the schema
GUID resolved live. Cleanup independently verifies contact and child-OU absence
before restoring the exact original policy presence, type and value. Each relay
has a fresh owned directory, exact PID/start identity and a scoped firewall
rule. Unknown files, changed ACLs or moved foreign descendants prevent cleanup
mutations. No recursive directory deletion, password reset, clock alteration,
cache rewrite or automatic mutation retry is part of the collector.

Before and after collection, both clients' keytab and four cache-file digests
must match the independent transfer manifest. Secret inputs travel only through
bounded in-memory stdin or protected credential files. The public captures
contain no passwords, keytabs, ticket caches or private certificate keys.

## Verification boundaries

Go 1.27.4 unit, wire and cryptographic checks cover all four supported AES
profiles, framing, sequence/order validation, authenticated layer selection,
partial observations, uncertain writes and cancellation. Those vectors do not
claim real AD interoperability for every encryption profile. Live captures
must report their actual negotiated encryption type and strength.

macOS and Windows ARM64 have compile coverage. Only Windows/amd64 and
Linux/amd64 are intended live clients in this matrix. Historical native and
TLS/simple-bind evidence remains separate from this Kerberos qualification.
