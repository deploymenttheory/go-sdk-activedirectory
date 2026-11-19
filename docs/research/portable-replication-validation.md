# Portable replication qualification status

The SDK07 implementation merged through PR204. Full live qualification remains
open in [#209](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/209).
The direct authenticated EPM/DRS/RPC path and secure public collector are enabled;
the remaining matrix prevents a release-ready claim. References to #172 below
retain the original implementation history, not an open-issue assertion.

The initial canonical server-scope source was
`d52ac60a8300fdab43d7bc6db718c369efbdc80e`. Its
[retained source/binary proof and public captures](portable-replication-evidence/canonical-d52/README.md)
bind actual inputs and binary hashes to that source. Earlier archive builds
were EOL variants, withheld from live use, and have an
[explicit provenance correction](portable-replication-evidence/source-basis-reconciliation/README.md).
Later documentation/evidence commits do not relabel the actual tested source.

## Completed evidence

The canonical Go 1.27.4 full Linux race run passed, including independently
implemented MIT AES17/18 DCE authentication and protected RPC bind/query/unbind.
Local full tests, vet, required lint, inventory checks and Linux/macOS/Windows
ARM64 builds passed. Owned wire tests cover all three credential sources,
authenticated category refusals, confirmed empty results, malformed valid
prefixes, tampering, cancellation, connection loss and association retirement.
These tests do not establish AD authorization or server-version qualification.

One actual live cell is retained: Windows amd64 to Server 2025, existing protected
administrative password credentials, server scope, partners/failures/queue.
All three normal-public-API queries completed. An independent native invocation
against the same selected host also completed. Their comparison passed 85
checks with all time/USN changes recorded, rather than suppressed. EPM and DRS
each reported actual mutual authentication, header signing, confidential AES256
records and valid service lifetimes for every query.

The administrator's result does not qualify least-privilege delegation. No
directory write, ACL grant, account password reset or policy mutation was part
of this cell. The retained preflight-only aborted caller capture started no SDK
process and is labelled separately.

## Remaining draft gates

| Client | Server | Retained live status |
| --- | --- | --- |
| Windows amd64 | 2016 | Pending |
| Linux amd64 | 2016 | Pending |
| Windows amd64 | 2019 | Corrected-source password: all five selection variants pass; strict domain comparison 324 checks; other credentials/refusals pending |
| Linux amd64 | 2019 | Corrected-source password: all five selection variants pass; strict domain comparison 324 checks; other credentials/refusals pending |
| Windows amd64 | 2022 | Corrected-source password: all five selection variants pass; strict domain comparison 324 checks; other credentials/refusals pending |
| Linux amd64 | 2022 | Corrected-source password: all five selection variants pass; strict domain comparison 324 checks; other credentials/refusals pending |
| Windows amd64 | 2025 | Corrected-source password: all five selection variants and domain native comparison pass; other credentials/refusals pending |
| Linux amd64 | 2025 | Corrected-source password: all five selection variants pass; other credentials/refusals pending |

The original scope remains: complete all applicable client/server cells;
qualify the remaining password/keytab/cache and topology-scope paths; collect
fresh ordinary-account 8453 refusals and partial results separately from empty
diagnostics; retain independent comparisons, source/binary identities and
ownership-guarded cleanup. Passing required PR CI remains mandatory. macOS has
build/unit coverage only, and amd64 captures do not qualify arm64 execution.


## Discovered peer principal regression

A subsequent Server 2025 domain-scope read exposed a peer-selection defect in
the original D52 implementation: the discovered peer was normalized against
the anchor's LDAP SPN before its caller-selected principal was applied. The
anchor row survived and the scope remained incomplete; this was not a server
refusal or an empty diagnostic result. The original server-scope proof above
is retained unchanged and does not qualify multi-controller expansion.

The [retained red/green regression](portable-replication-evidence/scope-principal-normalization/artifact-index.json)
reproduces the exact failure through real Kerberos/TLS LDAP domain, forest and
site expansion. Explicit multi-server selection already passed. The fix reuses
that same per-target identity/configuration path for discovered hosts, keeping
the existing transport-default topology port and the caller's original
credentials/SPN unchanged. No peer SPN, endpoint or authentication fallback is
invented. A missing map entry remains a precise per-server refusal; other rows
survive and no unmapped peer is contacted.

All three protected-wire expansion cases now pass alongside the explicit
multi-server, existing native/custom-anchor-port and unmapped-peer controls.
This is a production change requiring a fresh canonical source/build freeze
and live qualification. It does not relabel D52 captures or close #172.

## Corrected-source live scope qualification

The corrected canonical source is `ebb11a2aae28187c72ec0ea665bb5fe02aa451ed`.
[Fresh Windows/Linux Server 2025 evidence](portable-replication-evidence/canonical-ebb-live-server2025/README.md)
covers all five password selection variants, 30 public aggregate queries,
54 server diagnostic reads and 108 complete mutual/header-signed/confidential
AES256 EPM/DRS observations. An independent domain-scope comparison against
native Windows and portable Linux passes 318 checks with exact temporal and
session-metadata differences retained. Root separately verified all 4,474 raw
input hashes against the source-owner freeze before building. The canonical
full Linux race suite passed. None of this completes the remaining credentials,
ordinary refusals/partial cases or other server profiles listed above.

## Actual Server 2019 password scope observations

The [byte-preserved Server 2019 evidence](portable-replication-evidence/canonical-ebb-live-server2019/README.md) retains
Windows/Linux password reads across all five selections: 30 aggregate queries,
54 server reads and 108 complete protected EPM/DRS observations. The strict
domain comparison against native Windows and portable Linux passes 324
checks. Actual diagnostic failure rows remain distinct from successful query
completion, and every original difference/audit is preserved. Extra comparison
captures do not inflate the base counts. Original Windows power states and the
Linux private Server 2025/Running state were independently restored. Runtime
source remains ebb11a2; full #172 qualification is still incomplete.

## Current integrated-source ordinary-account observations

Source `4022967311b983ffb27f9cb59fedd100a3aca4b9` adds fresh Windows/Linux
Server2025 ordinary password/Seal observations across all five selections.
Partners complete while failures/queue retain actual per-server RPC8453 and
unavailable/incomplete states. The [exact public records](portable-replication-evidence/server2025-ordinary-4022967/README.md)
retain 30 aggregate queries, 54 server reads, 36 precise denial statuses and108
complete mutual/header-signed/confidential AES18/256 EPM/DRS stages. Independent
audit419 checks pass; both ordinary fixtures are independently cleaned and their
private credentials retired. No collector performed directory writes.

The new records do not relabel historical sources or complete a whole live
client/server cell. All remaining SDK07/10 acceptance requirements continue in
[#209](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/209).

## Actual Server 2022 password scope observations

The [byte-preserved Server 2022 evidence](portable-replication-evidence/canonical-ebb-live-server2022/README.md) retains
Windows/Linux password reads across all five selections: 30 aggregate queries,
54 server reads and 108 complete protected EPM/DRS observations. The strict
domain comparison against native Windows and portable Linux passes 324
checks. Actual diagnostic failure rows remain distinct from successful query
completion, and every original difference/audit is preserved. Extra comparison
captures do not inflate the base counts. Original Windows power states and the
Linux private Server 2025/Running state were independently restored. Runtime
source remains ebb11a2; full #172 qualification is still incomplete.
