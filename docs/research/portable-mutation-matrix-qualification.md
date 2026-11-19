# Portable mutation contract qualification matrix

The canonical runtime/collector remains
`8c891f4c83e8ceabfc7d93637751e71f33f26ac2`, built with Go 1.27.4 from raw Git
blobs. Each cell uses fresh GUID-recorded fixtures, six ordinary-actor public
cases and a distinct explicitly privileged owned-deletion case. No accepted
mutation is replayed between runs.

| AD DS target | Windows amd64 | Linux amd64 |
| --- | --- | --- |
| Server 2016 | Pending | Pending |
| Server 2019 | 7/7 | 7/7 |
| Server 2022 | Pending publication | Pending |
| Server 2025 | 7/7 | 7/7 |

The four published cells retain 28 passing public cases. Each measures complete
mutual AES-256 Kerberos SASL sealing. These runs do not use or qualify TLS/CBT,
another client architecture, or the provider release.

All cells exercise schema-proven manager DN representation, accepted clears,
statically denied attribute readback, accepted-then-denied group/site stages,
ordinary deletion visibility and a separate positive same-GUID deletion proof.
Raw acknowledgments, observations, actual LDAP statuses and per-stage identities
remain separate. The privileged reference never upgrades the ordinary result.

Every completed fixture has independent read-only reconciliation of all twelve
targets followed by both-DC, domain/configuration naming-context absence of all
fourteen fixture/actor GUIDs, exact original policy state and retired protected
actor credentials. Server 2019's original Off baseline and the Linux client's
Server 2025 private profile were restored before the next profile started.
Server 2022 work is a separate journaled lease in progress.

The first Server 2025 cells use fixture source `8c891f4`. Server 2019 uses
fixture helper `59718ec376006debc2e9fcc49f8aca4af52636b2`, which prevents an
ambient PowerShell AD-drive lookup in its temporary explicit-server provisioning
session. It changes no Go/module/runtime input from `8c891f4`; both PowerShell
5.1/7 fixture guards pass. Exact executed helper copies and their separate raw
Git source ledgers are retained with each cell.

See [Server 2025 details and preserved failures](portable-mutation-server2025-qualification.md).
Byte-preserved originals and per-directory hash ledgers are under
`portable-mutation-evidence/server*/`. Missing cells remain required under #174;
draft #202 is not a release or completion claim.
