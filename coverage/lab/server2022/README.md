# Server 2022 qualification evidence

Captured on 2026-11-12 from the isolated two-DC/member Hyper-V profile on H:.
The profile was created from inspected Microsoft evaluation media, configured,
tested sequentially after Server 2025, and stopped after successful validation.
These are local executions, not CI results.

| Property | Observed value |
| --- | --- |
| Guest OS | Windows Server 2022 Standard Evaluation Core, build 20348.587, AMD64 |
| AD module | 1.0.1.0 |
| Windows PowerShell | 5.1.20348.558 |
| Schema objectVersion | 88 |
| Domain / forest levels | Windows Server 2016 |
| Topology | Two writable GC/DCs and one member; private switch |

`reference-first.json` and `reference-repeat.json` passed independently and have
identical normalized results: temporary user/group CRUD, membership replication,
member removal, and fixture cleanup. Image hashes, guest/host versions, directory
levels, and secure-channel results are retained in those files.

`module.json` records 147 cmdlets, 249 parameter sets, and 1,735 per-command
parameter names. `comparison.json` compares this capture with the pinned Server
2025 documentation. The four service-account migration commands and
`New-ADServiceAccount -CreateDelegatedServiceAccount` are absent. The approved
151-command inventory remains intact; this observation records version limits.

`native-conditions.json`, `conditions-corpus.json`, and
`conditions-reference.json` retain passing native SDDL tests and PowerShell/.NET
comparisons, audit-only policy storage/readback, permission denial, and fixture
cleanup on both DCs. `connection-reference.json` and `rootdse.json` retain passing
current-identity RootDSE tests, 21 stable PowerShell property comparisons,
time/USN interval checks, ten repeated sessions, invalid endpoint, a 1,000 ms
connect wait with a one-second timeout, and authentication denial with local
fixture cleanup. Source, harness, and binary hashes identify the tested code.

The complete snapshots remain under `H:\ad-sdk-lab\server2022\results`.
Retained files were copied byte-for-byte and checked against their source
hashes. This qualifies this lab profile and the recorded native slices; it does
not establish complete cmdlet parity, explicit-credential authentication, AD LDS,
or ARM64 guest execution.
