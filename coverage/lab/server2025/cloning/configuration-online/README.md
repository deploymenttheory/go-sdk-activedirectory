# Server 2025 online clone configuration qualification history

This directory preserves two failed qualifications, their separate successful
recoveries, and the subsequent [passing v3 matrix](qualified-v3/README.md).
Both original qualification results remain failed. V3 completed the ten-case
Server 2025 matrix, including successful SDK/reference online generation and
existing-file rejection. Broader cmdlet parity and completion of issue #55
are not claimed.

| Run | Completed observations | Outcome |
| --- | --- | --- |
| failed-v1 | Five cases passed; inventory then failed after inclusion creation. | Failed; recovered separately in recovery-v1. |
| failed-v2 | Six cases passed, including native online XML generation; seventh case failed with LDAP 82. | Failed; recovered separately in recovery-v2. |
| qualified-v3 | All ten cases passed on the SDK build containing the native cursor thread-ownership fix. | Passed; original file and membership state restored within the run. |

The first run passed missing-group SDK/reference checks, direct membership
addition, and excluded-application SDK/reference checks. After creating the
owned custom inclusion list, the inventory helper failed with
`PropertyNotFoundStrict` because the reference exclusion cmdlet emitted one
explicit null when no excluded applications remained. Recovery captured that
actual output shape, removed the exact owned list and membership, and verified
the original 28 exclusions, file state and both domain-controller replicas.
No configuration file had been created in that failed run.

The corrected inventory filters only null results before projecting Name and
Type. V2 uses the same SDK helper binary, SHA-256 9D2F0D3A3548E8CD719E741A46AB246B3E2AAF24430554F6EC1370DAD21C5D8F, built from SDK
commit c72c7b0a4a785f177a70f26729b7d9ffff140a46. The inventory correction changes the qualification harness.
Offline checks retained here passed in Windows PowerShell 5.1 and PowerShell 7:
90 inventory checks, 84 guest checks, 224 host checks, 40 first-recovery checks,
and 41 second-recovery checks. These checks do not convert the live failures
into passing qualifications.

V2 repeated the first five cases and then successfully called the SDK's online
generation API. Its one retained configuration file is schema-valid and names
ADSDK25CLONE. On the next call, which was intended to test existing-file
rejection, the SDK failed earlier with
`read cloning PDC RootDSE: LDAP attribute enumeration: LDAP status 82`.
The existing configuration's bytes, timestamps and ACL remained unchanged.
That failed call did not establish the expected existing-output error.
Reference existing-file rejection and reference successful generation were
never reached in v2. Its captured artifacts are unchanged. The later v3 run,
built from reviewed commit 59346e9641feada4915a3313273ee2fc845bdbeb with the LDAP
cursor thread-ownership fix, reached the typed SDK existing-output error and
both reference cases successfully. Both generated XML files were schema-valid
and matched in namespace, order and values; formatting bytes differed.

Both original runs have known-complete child/host processes and no recorded
process, publication, mutation or capture uncertainty. Their cleanup flags are
false because the test deliberately stopped at the observed failures.
Recovery-v1 reached verified restoration at 2026-11-12T22:55:18.3761703Z;
recovery-v2 reached verified restoration at 2026-11-12T23:07:33.9381808Z.
Each recovery removed only its recorded owned files and direct membership,
then verified file absence, original 28 exclusions and original membership
views on both DCs. The second recovery removed both the generated configuration
and custom inclusion list. All guest staging remains preserved.

V3 independently verified removal of both owned files and direct membership,
restoration of 28 exclusions, and original membership views on both DCs. All
ten child processes and three host jobs had known completion without uncertainty.

These are Server 2025 observations from the isolated disposable lab. They do
not prove an actual VM clone/boot, a complete version matrix, every online
prerequisite failure, nested group behavior, concurrent publication, or
completion of broader #55/#78. No VM was cloned or restarted.

The original failed-run and recovery artifacts are listed with their location,
byte length and SHA-256 in import-audit.json. V3 has its own separate audit in
qualified-v3/import-audit.json. Original transport envelopes are verified against
the raw files and capture manifests before import; their hashes and retained
H: locations are recorded instead of duplicating base64 payloads in Git.
Original archives, executables, staging and failed evidence remain on H:.
All copied bytes are preserved; .gitattributes disables text conversion.
Go source snapshots use .go.txt names to avoid SDK package discovery.
The importer performs file validation/copying only and never executes a lab
harness, changes AD, or updates coverage/ticket states.
