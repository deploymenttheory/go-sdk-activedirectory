# Server 2016 reference evidence — qualification incomplete

Captured on 2026-11-12 from the isolated two-DC/member Hyper-V profile on H:.
Provisioning and both reference runs passed. The additional condition-reference
test failed at ordinary-user authentication; the native connection test has not
run. This profile is not yet fully qualified.

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

The complete snapshots remain under `H:\ad-sdk-lab\server2016\results`.
Retained files were copied byte-for-byte and checked against their source
hashes. Failed evidence is named explicitly and is not counted as a passing
qualification. The follow-up authentication probe and native connection run
require elevated Hyper-V guest access.
