# Server 2025 explicit discovery, password and sealing

Actual canonical public source `7c69c15ad3b959a76fe761e917dd11a55d93468e`,
Go 1.27.4, Windows/Linux amd64, existing explicit administrative password
credentials and mutual AES256 Kerberos SASL sealing. Both read-only runs observe
the exact absolute SRV query, independently advertised controllers, the selected
authenticated domain/DC identity and all four domain/forest/controller/list
projections on the selected owning session.

The independent native/Windows/Linux audit passes 129 checks. It verifies native
domain and DSA GUID/SID identities, exact controller relationships, domain and
forest role ownership, domains/sites/GC/controller sets, reported addresses and
controller state. All Windows/Linux identity/projection structures, ordering
and nullable values agree except explicitly retained RootDSE time/USN changes.
Native functional-level strings and collection wrappers remain unchanged; no
assumed numeric enum mapping or native nullability equivalence is claimed.
SDK-reported crypto facts are not independent packet decryption.

Root independently verified every one of the 4,369 ZIP and extracted source
files against committed raw Git blobs before live execution, including all 895
Go/module inputs. Build/provenance manifests and actual executable hashes bind
the source-owner binaries. Linux result bytes have exact remote/host SHA256
agreement. Byte-preserved originals and executed controller sources are indexed
by `artifact-hashes.json`; no private input, credential or executable is included.

The earlier forced-Go-DNS failure remains separately retained and unqualified.
The correction uses the normal configured OS resolver without changing a
gateway, DNS, network, account, ACL, policy, password or service setting. Its
bounded caller cancellation discards late OS-query results; an underlying OS
query may itself finish later. No authentication or endpoint fallback occurs.
These runs create no new private credential fixture.

The caller-preflight-only directory retains one aborted controller attempt:
its old manifest-key expectation failed before credential access or SDK calls.
Only its executed source exists; the fresh successful runs are separate.

This is two-client Server 2025 password/sealing evidence, not full SDK10 matrix
completion or release qualification. Other credential/protection profiles and
Server 2016/2019/2022 cells remain required under #175. No native-current-domain,
other-architecture live or provider-release support is inferred.

## Canonical Linux race completion

The full Go 1.27.4 Linux `go test -race ./... -count=1` run on corrected source
`7c69c15ad3b959a76fe761e917dd11a55d93468e` passes. All 4,369 canonical source
inputs remain unchanged after testing. The exact invocation/terminal receipt
and raw log hash are retained with the Server 2025 evidence. This offline check
does not qualify any omitted live client/server or authentication profile.
