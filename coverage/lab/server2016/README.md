# Server 2016 qualification evidence

Captured on 2026-11-12 from the isolated two-DC/member Hyper-V profile on H:.
Provisioning, both reference runs, and the native connection test passed. The
condition reference initially failed at ordinary-user authentication; two full
repeats of the unchanged test passed after restarting the owned profile. The
profile was stopped after validation. These are local executions, not CI results.

| Property | Observed value |
| --- | --- |
| Guest OS | Windows Server 2016 Standard Evaluation Core, build 14393.693, AMD64 |
| AD module | 1.0.0.0 |
| Windows PowerShell | 5.1.14393.693 |
| Schema objectVersion | 87 |
| Domain / forest levels | Windows Server 2016 |
| Topology | Two writable GC/DCs and one member; private switch |

`reference-first.json` and `reference-repeat.json` passed independently and have
identical normalized results: temporary user/group CRUD, membership replication,
member removal, and cleanup on both DCs. They retain image provenance, host and
guest versions, directory levels, and the passing member secure-channel check.

`module.json` records 147 cmdlets, 249 parameter sets, and 1,733 per-command
parameter names. `comparison.json` records the four absent service-account
migration commands, absent `New-ADServiceAccount -CreateDelegatedServiceAccount`,
and absent `DisablePermissiveModify` on `Add-ADGroupMember` and
`Remove-ADGroupMember`, relative to the pinned Server 2025 documentation.
The approved 151-command target is unchanged.

`native-conditions.json` records a passing native conditions test suite.
`conditions-reference-failed.json` records the separate failed differential run:
all ten syntax comparisons and three policy storage/readback comparisons passed,
then `Get-ADDomain -Credential` failed while authenticating the newly created
ordinary user. The authorization-denial check was not reached. Fixture cleanup
was confirmed on both DCs. The cause has not yet been established; it is not
recorded as an SDK defect or an unsupported Server 2016 feature.

`conditions-reference-first.json` and `conditions-reference-repeat.json`, with
their corresponding `native-conditions-first.json` and
`native-conditions-repeat.json`, record the two later successful full executions.
Both include all 13 comparisons, authenticated ordinary-user authorization
denial, and cleanup on both DCs. The tested source hashes are unchanged from the
initial failed run. No retry behavior was added to the SDK or reference harness.

`connection-reference.json` and `rootdse.json` record a passing current-identity
connection run: 21 stable PowerShell property comparisons, time/USN intervals,
ten repeated sessions, an invalid endpoint, a one-second connect timeout, and
authentication denial with local account cleanup. Source, harness, and binary
hashes identify the tested code.

The complete snapshots remain under `H:\ad-sdk-lab\server2016\results`.
Retained files were copied byte-for-byte and checked against their source
hashes. Failed evidence is named explicitly and is not counted as a passing
qualification. A follow-up authentication probe passed short-name, FQDN, and UPN
cases before and after explicit fixture replication, but did not reproduce or
explain the earlier failure. The two successful repeats establish passing
executions, not the cause of the original intermittent failure. Broader stability
qualification remains part of the final SDK matrix; this evidence does not
establish full cmdlet parity, explicit credentials on Server 2016, AD LDS, or
ARM64 guest execution.
