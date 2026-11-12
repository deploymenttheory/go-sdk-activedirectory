# Server 2025 bootstrap evidence

Captured on 2026-11-12 from the isolated Hyper-V lab described in
[docs/lab.md](../../../docs/lab.md). These are local executions, not CI results.

| Property | Observed value |
| --- | --- |
| Guest OS | Windows Server 2025 Standard Evaluation Core, build 26100.32230, AMD64 |
| AD module | 1.0.1.0 |
| Windows PowerShell | 5.1.26100.7462 |
| Schema objectVersion | 91 |
| Domain / forest levels | Windows Server 2016 |
| Topology | Two writable GC/DCs and one member; private switch |

`reference-first.json` and `reference-repeat.json` are independent passing
runs. Their `normalized_reference` objects match exactly. Both observed user
and group membership replication, member removal, and fixture subtree cleanup
on both DCs. The second run records the explicit AMD64 architecture and full
host build; the first captured the less specific OS `64-bit` description.

`module.json` records the installed module surface: 151 cmdlets, 253 parameter
sets, and 1,754 distinct per-command parameter names, excluding common shell
parameters. `comparison.json` compares it with the pinned documentation's
151 cmdlets, 253 sets, and 1,756 names. It records parameter-set label mappings
separately from functional surface differences.

The only parameter differences are `PreferredWINSServer` and
`AlternateWINSServer` on `New-ADDCCloneConfigFile`, absent from this installed
module but present in the documentation and its OfflineExecution and
IPv4StaticSettings syntax. This observation does not establish behavior on
older Server versions. Their inventory entries and planned tests remain.

`native-conditions.json` records a passing execution of the compiled Go
`conditions` tests inside the member VM, using go-bindings-win32 v0.6.0. It
includes the executable SHA-256, source hashes, build settings and toolchain,
guest build, architecture, exit code, and test output. The harness built from
a retained source snapshot and verified that it stayed unchanged during the
build. The package's syntax, round-trip, invalid-input,
repeated-compilation, allocation/free balance, injected native/cleanup failures,
and fuzz-seed cases passed. `conditions-corpus.json` contains ten SDDL cases
emitted by that same guest executable. `conditions-reference.json` records the
passing run `conditions-20261112T113740Z-ccc5466b`: all ten agree with
PowerShell/.NET normalization and rejection, including Unicode, compound
conditions, unknown claims, and a full descriptor. Three From/To descriptors
also match after storage and readback through `New-ADAuthenticationPolicy` and
`Get-ADAuthenticationPolicy`. All policies were audit-only and unassigned.
An authenticated ordinary fixture user received access denied when creating a
policy. Cleanup was confirmed on both DCs. Source, binary, corpus, and retained
reference-script hashes link the comparisons to the tested implementation.

These artifacts establish the reference lab and local native SDDL syntax
behavior and policy descriptor storage. They do not establish general AD
operation parity, claim existence, authentication-policy logon enforcement,
older Server compatibility, or ARM64 execution. No operation has been promoted
to `validated` based solely on this Server 2025 evidence.

`removal-enumeration.json` records two failures of host-wide adapter enumeration
while the exact owned switch and direct CIM queries remained usable. The
replacement removal guard is exercised by `removal-guard.json`: an empty switch
passes, a stopped diskless VM outside the profile blocks removal, the profile
and switch survive rejection, and removal becomes eligible after deleting only
that uniquely owned probe VM. These are guard checks; completion of the full
rebuild cycle is recorded separately when it finishes. Offline regressions run
the actual removal action with mocked native commands, including query failure,
malformed references, and unrelated connections.
