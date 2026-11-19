# Portable mutation contracts: Windows and Linux / Server 2025

Frozen runtime and collector source `8c891f4c83e8ceabfc7d93637751e71f33f26ac2`,
built with Go 1.27.4 from 4,323 independently checked raw Git inputs, passes the
both applicable Server 2025 SDK-09 live cells, seven cases per client. Each uses
separate ordinary and privileged invocations through normal public SDK calls,
explicit password credentials over protected stdin, and mutual AES-256 Kerberos
SASL sealing. This is not TLS/CBT qualification.

The ordinary actor passes six cases:

| Case | Observed contract |
| --- | --- |
| Schema-proven manager DN representation | Accepted, raw normalized readback retained, unverified |
| Description clear | Accepted, omitted readback retained, unverified |
| Statically denied description read | Accepted effect retained, contradictory visible readback, uncertain |
| Group batch | First group accepted; second refused with actual LDAP 50; partial effects retained |
| Site/settings update | Site accepted and verified; settings refused with actual LDAP 50; root identity retained |
| Ordinary deletion | Accepted and absent from ordinary search; controlled readback LDAP 32 retained; unverified |

A separate explicitly privileged connection deletes its own distinct recorded
object. Its controlled exact-GUID BASE search returns one complete matching
deleted object and verifies that deletion. Its result never upgrades the
ordinary actor's observation or claims restore eligibility.

Independent privileged read-only reconciliation records all twelve fixture
targets, including the accepted manager/clear/hidden value, group membership,
site description, unchanged settings and both deleted GUIDs. An absent scalar
description is preserved as the reference reader's raw `[null]`; an empty member
collection is `[]`. These are reference observations, not substituted SDK results.

Cleanup independently verifies all fourteen fixture/actor GUIDs absent in both
domain and configuration naming contexts on both DCs for each client fixture,
exact original policy values and retired protected actor credentials. Server 2025 remains Running;
Linux network/resolver and other profiles were not changed by these runs.

## Retained failures and correction

`failed-preparation-04875f7` retains the pre-SDK setup failure: PowerShell rejected
an empty `OtherAttributes` argument before site creation. No SDK call occurred.
The recorded partial fixture and actor were independently cleaned: ten GUIDs
absent on both DCs. Helper-only source `761e93696dc18480a7e932cf20f3e6acac489b99`
corrected that invocation without changing the earlier runtime binary inputs.

`failed-deletion-proof-04875f7` retains the next actual public run: five ordinary
cases passed, while both deletions were accepted but their domain-subtree
controlled proof searches remained incomplete. The privileged result retained
the matching deleted object without incorrectly verifying it. Both results,
independent readback, sources and fourteen-GUID cleanup remain unchanged.

Source `8c891f4` uses one exact GUID BASE search with the selected critical
ShowRecycled/ShowDeleted control. It validates the canonical returned DN's
original naming context, GUID and deleted flag. It never retries another base,
ignores referrals or promotes an incomplete search to complete. The collector
retains allowlisted error facts and accepts only documented visibility outcomes
for the ordinary negative case. A fresh fixture supplies the successful seven
cases; no accepted mutation from the failed run was replayed.

## Evidence and remaining scope

Exact public originals and their hash ledgers are under
`portable-mutation-evidence/server2025/`; executables and private credentials
are excluded. Source and binary ledgers identify actual runtime revisions and
fixture source copies identify the executed helper bytes. Independent canonical
Linux race acceptance passes for both runtime revisions are retained under
`portable-mutation-evidence/offline/`; these offline artifacts are separate from
the fresh Linux public live results in `server2025/linux-8c891f4`.

Both clients against Server 2016/2019/2022 remain required: six further cells.
These Server 2025 cells do not close #174, #140 or #157, qualify another
architecture, or establish provider release readiness. Draft PR #202 retains
the complete implementation and current evidence; full delivery requires the
remaining applicable matrix and green required CI before merge.
