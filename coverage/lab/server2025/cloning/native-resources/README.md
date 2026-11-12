# Native resource-cycle qualification

`TestNativeResourceCycles` completed **100 real native inspections** on the owned
Server 2025 DC at 2026-11-12 19:37 UTC. Every cycle reported 28 exclusions,
`complete=true`, matching acquisition/release counts, and zero outstanding
owners. The [raw report](native-resources.json) records every cycle:

| Resource | Acquisitions | Releases | Outstanding after every cycle |
| --- | ---: | ---: | ---: |
| DsRole buffers | 100 | 100 | 0 |
| Registry handles | 600 | 600 | 0 |
| Service-manager handles | 100 | 100 | 0 |

The ledger wraps the actual Win32 calls used by the inspection core. It rejects
unknown releases before passing them to Windows, and counts a failed native
close as outstanding. This establishes observed ownership balance, not a bound
on working set or the Go heap. Injected error-path ownership tests are separate.

The [guest report](reference.json) records Windows Server `26100.32230`,
AD DLL `10.0.26100.7309`, the test output, and a second check of all 100 cycle
records. The [host qualification](qualification.json) records source/binary
digests and successful staging/process/session cleanup. Raw evidence was copied
back and hash-verified before guest deletion. Capture failure preserves staging.

The test source is commit `34b043bc69463fe0b4df32bceac3a1050e952a7b`.
Production files are unchanged from reviewed runtime commit `bfc8f8a`, used in
the [native custom-list and generation run](../native-cases/README.md).
The [build manifest](build.json) confirms Go 1.26.5, Windows amd64 and the
archived source. The CLI built from this test-only checkpoint has the same
SHA-256 as the generation run's CLI.

| Artifact | SHA-256 |
| --- | --- |
| Source archive | `FE2EA4DEB69C4C47684A1F099F1E5E98E921C28CE8B9C7C99290F85B39F69D67` |
| Native test executable | `AF258C6120747CBAAB1DA304A34A53F7BF4C83221441F77577473DD24901A092` |
| Raw resource report | `A555998478E7E572BEA0BAD3A6E38462BFEF97B91FB2554A2757CE15C765FCBB` |
| Guest report | `2C43963BA3FCE0C29334F2A1B464FB3DBDD366249109CF29A369CAD31A7F21C9` |
| Host qualification | `26CF89F52CAA92FB321F6DA5B7661C293A35A204830A513FD35EBF2C3B9D03E7` |

Original report and helper bytes are preserved. Windows PowerShell remoting
attached metadata to the host report's `raw_resource_report_sha256`; its
`value` property holds the digest above. The raw report was verified before
cleanup, and this serialization detail does not change its bytes or the result.
The scripts are historical qualification snapshots with explicit owned-lab
identities, not general provisioning entry points.

Live access-denied scenarios and older-server comparisons remain pending.
No native ARM64 DC execution or complete issue #54 parity is claimed.
