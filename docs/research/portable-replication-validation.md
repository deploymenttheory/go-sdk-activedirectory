# Portable replication qualification status

This SDK07 implementation is a draft. The direct authenticated EPM/DRS/RPC
vertical slice and secure public collector are implemented. The qualification
branch enables the normal public dispatcher after offline packet/session review;
the remaining live matrix prevents a release-ready claim or completion of #172.

The canonical tested source is
`d52ac60a8300fdab43d7bc6db718c369efbdc80e`. Its
[retained source/binary proof and public captures](portable-replication-evidence/canonical-d52/README.md)
bind actual inputs and binary hashes to that source. Earlier archive builds
were EOL variants, withheld from live use, and have an
[explicit provenance correction](portable-replication-evidence/source-basis-reconciliation/README.md).
Later documentation/evidence commits do not relabel the actual tested source.

## Completed evidence

The canonical Go1.27.4 full Linux race run passed, including independently
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
| Windows amd64 | 2019 | Pending |
| Linux amd64 | 2019 | Pending |
| Windows amd64 | 2022 | Pending |
| Linux amd64 | 2022 | Pending |
| Windows amd64 | 2025 | Administrative password/server reads and native comparison passed; full cell pending |
| Linux amd64 | 2025 | Pending |

The original scope remains: complete all applicable client/server cells;
qualify the remaining password/keytab/cache and topology-scope paths; collect
fresh ordinary-account 8453 refusals and partial results separately from empty
diagnostics; retain independent comparisons, source/binary identities and
ownership-guarded cleanup. Passing required PR CI remains mandatory. macOS has
build/unit coverage only, and amd64 captures do not qualify arm64 execution.
