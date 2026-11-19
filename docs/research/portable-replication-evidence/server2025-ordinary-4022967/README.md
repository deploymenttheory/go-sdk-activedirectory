# Server2025 ordinary-account replication observations

Actual source: `4022967311b983ffb27f9cb59fedd100a3aca4b9`, Go1.27.4.
Windows/Linux amd64 used the normal public portable collector, a fresh explicit
ordinary account and required Kerberos SASL sealing. This is partial evidence
for [#209](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/209).

| Selection | Windows | Linux |
| --- | --- | --- |
| One server | Partners complete; failures/queue denied8453 | Same |
| Explicit two servers | Partners complete; both servers retain failures/queue8453 | Same |
| Domain | Partners complete; both servers retain failures/queue8453 | Same |
| Forest | Partners complete; both servers retain failures/queue8453 | Same |
| Site | Partners complete; both servers retain failures/queue8453 | Same |

Ten calls retain 30 aggregate queries, 54 server reads, **36 actual RPC8453
statuses** and **108 complete mutual/header-signed/confidential AES18/256 EPM/DRS
observations**. Denied failure/queue categories stay requested, unavailable and
incomplete; absent rows are not confirmed empty results. Successful partner
directions survive the separate category refusals. Collector exit1 records
aggregate denial, not failed authentication or a downgraded bind.

The independent original-record audit passes **419 checks** of source/client/input
identities, categories, precise statuses, actual protection and fixture cleanup.
Before building both binaries, the canonical ZIP/extraction was checked against
all **7,478 raw Git blobs**, including **978 Go/module inputs**. Every source input
remained unchanged after building. Binary/transfer/intent/result hashes bind each
invocation. Earlier ebb/7c records retain their original sources.

## Ordinary role and cleanup

Actor `sdk07-p25-20261119t061327773z`, GUID
`c1b28cdd-b3e0-41bc-a89e-8dfbd9483176`, has primary group513, no direct group
memberships and only the recorded unprivileged reference-token SIDs. No privileged
membership, policy, service, resolver, power or NIC configuration was changed.
Collectors performed zero directory writes.

The separate fixture lifecycle created one owned OU and ordinary user, then
deleted exactly those objects. Both GUIDs are independently absent on both DCs,
original policy checks pass and the protected credential is retired. Cleanup
retains intermediate replication observations without replaying deletes. The
Server2025 trio and Linux private profile remain Running. Credentials and
binaries are excluded from this publication.

Final19 offline admission cases reject Domain Admins, builtin Administrators,
unexpected memberships, changed private files and wrong owners. Additional
reference-token identities are documented by [MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab)
and [Microsoft security identifiers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).
This reference read does not replace the SDK's explicit ordinary authentication.

## Preserved stopped attempts

- Initial actor `sdk07-p25-20261119t061023166z` stopped before any SDK call:
  a two-group allowlist rejected documented ordinary token SIDs. Both objects
  were deleted. Second-DC absence initially failed; independent read-only
  reconciliation later verified absence and retired the credential with zero
  additional deletes. The original false cleanup field remains alongside proof.
- The Windows explicit-two SDK call completed before the host checker accessed
  an omitted success-only JSON property under StrictMode. Its stopped batch and
  original result remain unchanged. The419-check auditor verifies that result
  directly; only three unattempted Windows scopes ran afterward.
- A subsequent host-only parameter collision started no SDK call. Its empty
  batch/source remain separate. No selector or SDK mutation was retried.
- The baseline verified both synchronized DCs and Linux ownership. Its outer
  wrapper later sampled an internal helper exit code and reported failure;
  no lab operation restarted. Empty failed-wrapper stdout receipts are retained
  without being parsed as successful results.

The initial17-case review remains historical. The corrected19-case receipt and
actual executed source copies identify the final code.

## Records and limits

`captures/` separates ten exact reports and source/transfer/intent bindings by
client/selection. `fixtures/` retains both lifecycle histories without secret
files. `build/`, `receipts/` and `tools/` preserve manifests, actual outputs and
executed sources. `artifact-index.json` pins all163 preserved original/tool files.
The reusable raw-Git auditor checks the committed bytes, every canonical build
input, unchanged runtime and actual public observations without lab credentials:

```sh
python docs/research/portable-replication-evidence/server2025-ordinary-4022967/tools/audit-sdk209-committed.py \
  --tree . --revision HEAD --output sdk209-audit.json
```

The staged8040-check receipt predates the final auditor/receipt publication and
is labelled accordingly. Run the command above to verify the final commit.

Server2016/2019/2022, keytab/cache, applicable TLS/CBT/Sign profiles, remaining
failure/identity cases and discovery projections remain required. These ordinary
password/Seal observations do not complete SDK209 or provider release qualification.
