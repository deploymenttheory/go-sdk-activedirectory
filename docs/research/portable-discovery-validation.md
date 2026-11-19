# Portable discovery implementation verification

The initial offline implementation and its historical public collectors used actual source
`cd15bbacd32180479b07d1bd9e5edc5fc20048a9`. These records establish offline
implementation/build checks. Full Windows and Linux qualification against
Server 2016/2019/2022/2025 remains pending under #175; no existing native evidence
qualifies this new flow or the broader #78 variants.

The [source manifest](portable-discovery-evidence/canonical-cd15/source-provenance.json)
records all 4,326 tracked inputs, including 892 Go/module files. Binary
`git cat-file --batch` read every raw blob; a separate second Git read verified
the generated ZIP and extracted build inputs byte-for-byte. No text-mode Git
output or archive conversion is used. The retained executable freezer source
can be copied to `tmp/freeze-discovery-canonical.py` in a checkout and invoked
with the full source revision. The ZIP hash is
`d73cfe7294030826aad864097041a9dececbb9a3287e0d90d53e0f11138e0fc7`.

The [binary manifest](portable-discovery-evidence/canonical-cd15/binary-manifest.json)
binds Windows/amd64 and Linux/amd64 public collectors to those inputs, Go
1.27.4 and the exact linker source label. VCS stamping is deliberately disabled;
no clean/dirty stamp is claimed. Both invalid-domain preflight smokes observed
the correct source label and refused before DNS/private credential-file access.
Their local socket-free refusal is not a live authentication result.

[Verification metadata](portable-discovery-evidence/canonical-cd15/verification.json)
records passing full Windows tests, vet, the 151-cmdlet inventory contract,
module tidy, Linux/macOS/Windows crossbuilds, the configured diff lint gate, and
full Linux race tests of the canonical inputs. The new wire tests include real
UDP/TCP DNS, verified TLS LDAP identity/topology, explicit SRV389/LDAPS636 port
separation, all three Kerberos sources across four protection profiles, partial
identity/refusal/loss, cancellation and caller-owned source preservation.

The configured lint gate reports zero issues. A separate all-history probe was
not clean: existing native/style findings remain, and representative Windows
checkout CRLF differences were checked against unchanged raw Git LF blobs.
The one introduced DNS complexity finding was fixed. No security check,
exclusion or formatting policy was relaxed, and unrelated source was not
reformatted. The final example-only duplicate-key guard is present in the
canonical Linux race source and separately passed focused Windows tests/vet.

The [artifact index](portable-discovery-evidence/canonical-cd15/artifact-index.json)
records exact retained bytes. The documentation/evidence follow-up does not
relabel either collector or claim every later tracked input equals the tested
source. See the [design and primary sources](portable-discovery-design.md) and
[secure public example](../../examples/portablediscovery/README.md).


## Windows OS resolver correction

The [first actual Windows25 attempt](portable-discovery-evidence/failed-live-cd15/README.md)
used canonical cd15 and failed during SRV lookup before authentication.
Independent Windows DNS returned both controllers; the isolated member had
configured private DNS and no gateway. Its exact Go1.27.4 source shows the
forced Go resolver skips no-gateway adapters. The original 16 records remain
byte-preserved and unqualified, with the Go BSD license retained additively.

The corrected production path uses a fresh standard-library resolver with normal
OS DNS selection. It retains explicit absolute queries and strict validation,
without changing host networking, selecting another controller or inferring AD
identity. [Red/green cancellation tests](portable-discovery-evidence/os-resolver-regression/artifact-index.json)
also reproduce the native OS boundary that can ignore caller cancellation at
SRV, canonical-name or address lookup. Private buffered completion lets the
caller return on cancellation; late OS results cannot make a partial result
selectable or mutate returned observations. The OS can retain its own query
resources until that query returns.

This is a production correction requiring fresh canonical collectors and live
qualification. The cd15 offline checks and original failed live report do not
qualify the changed runtime. The separate CI fixture repair allocates independent
UDP/TCP loopback ports while retaining actual truncated-UDP to TCP retry of the
same DNS question; it changes no production authentication/transport logic.


The [corrected canonical source/build proof](portable-discovery-evidence/canonical-7c69/README.md)
uses actual source `7c69c15ad3b959a76fe761e917dd11a55d93468e`, with 4,369
tracked inputs and independent raw-Git verification. Both public collectors are
bound by exact hashes and the matching source linker label. Full Windows checks
and three crossbuilds pass; fresh Linux race/live outcomes are recorded
separately when completed. This evidence follow-up changes no Go/module inputs.

## Actual Server 2025 password/sealing observations

The corrected canonical source `7c69c15ad3b959a76fe761e917dd11a55d93468e`
passes public Windows/Linux amd64 DNS, authenticated identity and all four
topology projections. The [byte-preserved live records](portable-discovery-evidence/server2025-password-seal-7c69c15/README.md)
include a passing 129-check independent native/Windows/Linux comparison and
root's independent verification of all 4,369 raw-Git ZIP/extracted inputs before
live use. Both sessions report complete mutual AES256 SASL sealing. No lab
network, DNS, directory or service setting was changed. These are password/Seal
observations only; the other credentials, protection profiles and server
versions remain required under #175. Historical failures stay unqualified.

## Canonical Linux race completion

The full Go 1.27.4 Linux `go test -race ./... -count=1` run on corrected source
`7c69c15ad3b959a76fe761e917dd11a55d93468e` passes. All 4,369 canonical source
inputs remain unchanged after testing. The exact invocation/terminal receipt
and raw log hash are retained with the Server 2025 evidence. This offline check
does not qualify any omitted live client/server or authentication profile.

## Actual Server 2019 password/sealing observations

The [byte-preserved Server 2019 evidence](portable-discovery-evidence/server2019-password-seal-7c69c15/README.md) retains
both public clients completing DNS, authenticated identity and all four
projections with mutual AES18/256 SASL Seal. The unchanged strict
native/Windows/Linux comparison passes 129 checks. Exact original source,
binary-transfer, execution and Linux-result digests are retained. Windows
power states and the Linux private Server 2025/Running state were independently
restored, with zero directory mutations. Actual source remains 7c69c15; other
credential/protection/server profiles remain required under #175.

## Remaining live qualification matrix

| Client | Server | Retained live status |
| --- | --- | --- |
| Windows amd64 | 2016 | Pending |
| Linux amd64 | 2016 | Pending |
| Windows amd64 | 2019 | Password/AES256 Seal identity and four projections pass; other credential/protection/refusal gates pending |
| Linux amd64 | 2019 | Password/AES256 Seal identity and four projections pass; other credential/protection/refusal gates pending |
| Windows amd64 | 2022 | Password/AES256 Seal identity and four projections pass; other credential/protection/refusal gates pending |
| Linux amd64 | 2022 | Password/AES256 Seal identity and four projections pass; other credential/protection/refusal gates pending |
| Windows amd64 | 2025 | Password/AES256 Seal identity and four projections pass; other credential/protection/refusal gates pending |
| Linux amd64 | 2025 | Password/AES256 Seal identity and four projections pass; other credential/protection/refusal gates pending |

Every row records only its actual profile. Full #175 qualification remains open.
