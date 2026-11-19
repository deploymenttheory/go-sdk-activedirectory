# Server 2016 authentication qualification

SDK-04/05's remaining Server 2016 matrix passed all 84 unfiltered Windows/Linux
cases using actual SDK source `958d4a426561bb36a5cd6104f0e253e2a7aa7b2f` and
Go 1.27.4. The successful manifest is from
`qualification-20261118t213705740z`: 68 actual AD cases, 12 local configuration
refusals and four local expired-credential refusals. These scopes are distinct;
local refusals are not server enforcement evidence.

The source-labelled binaries are unchanged from the other qualified server
profiles. Both DCs ran build 14393.8246. TLS credential-source cases report
verified TLS and channel binding sent; they do not claim a peer CBT acknowledgement.
Missing/tampered CBT received actual LDAP 49 / `SEC_E_BAD_BINDINGS`. SASL cases
cover exact signing/sealing, accepted writes/readback, real forwarded faults,
retirement/uncertainty and genuine ticket/context expiry without clock edits.

Both DCs reached build 14393.8246 through the documented servicing bridge. The selected original public records, executed sources, all 32 host-only quiet observations and original power baseline are preserved under `portable-kerberos-evidence/servicing-server2016`. Its hash ledger identifies 93 unchanged source files. The optional later cumulative update was not installed. All three VMs originally were Off; the temporary cold-export Running baseline is a separate observation.

The first authentication run stopped during report transfer after 39 admitted cases. Its completed final child report was independently recovered; the failed manifest remains failed. The next unfiltered run stopped during initial bridge staging before any SDK, policy or contact operation. Its normal cleanup verified restoration. The exact control-process retirement and timeout diagnosis are preserved; asynchronous close alone is never retirement proof.

The main-based transport repair requests asynchronous closure after timeout and blocks later control calls behind an independent reconciliation journal. Public-only ISO staging was then attempted to avoid bulk PSRP transfer. That attempt failed because its 25-character primary label was truncated to 16 characters in the actual Joliet descriptor. Its journal and independent host observation verify exact original device restoration. No SDK call ran during staging.

A fresh ISO uses a unique 16-character label. The corrected helper reads both actual volume descriptors before staging and rejects the unchanged original ISO in its regression check. Local bridge copy and full hash verification passed, original devices were restored, and pinned Linux SSH inventory passed. Nine original public records, source snapshots, offline guards and the successful staging receipt are preserved under `portable-kerberos-evidence/control-iso-server2016`; binary media and private files are excluded.

A subsequent run stopped after 65 cases in an idle PSRP peer-preparation request,
before the next SDK case began. Only its exactly identified idle control process
was retired. Its original failed manifest retains `cleanup_verified=false`;
independent fresh-session reconciliation separately verifies exact policy,
contact and peer cleanup. The final full run uses an independently staged,
hash/owner-checked public peer copied locally on DC1 for each case. This changes
lab transport, not SDK authentication or its frozen binaries.

`portable-kerberos-evidence/control-recovery-server2016/artifact-hashes.json` hashes the six original public diagnosis/staging records. These contain public executable and device metadata, not credential payloads. ISO files, VM disks and private credentials are excluded.

The successful run's cleanup and independent outer teardown both passed. Both DCs
show zero owned objects and exact original policy presence/type/value. Owned TLS
certificates/keys and Windows/Linux/host fixture-private credentials are retired.
The original resolver link `../run/systemd/resolve/stub-resolv.conf` is restored,
both public transport caches are absent, the Linux client returned to its original
Server 2025 private profile/Running state, and all three Server 2016 VMs returned
to their independently recorded original Off states.

`portable-kerberos-evidence/server2016` and `portable-sasl-evidence/server2016`
retain 464 original public files and flat SHA256 indexes. Failed 39/0/65 attempts
are explicitly prefixed and unchanged. Raw Git-blob auditing checks every indexed
hash, independently enumerates all 84 IDs, revalidates protocol claims and
credential immutability, and checks the successful cleanup records.

This completes the remaining authentication-profile evidence in #194. It does
not qualify all SDK operations, another architecture, portable RPC or a provider
release; their separate gates remain applicable.
