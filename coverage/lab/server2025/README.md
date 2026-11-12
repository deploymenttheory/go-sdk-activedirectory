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
emitted by that same guest executable for subsequent PowerShell comparisons;
emission alone does not establish differential parity.

These artifacts establish the reference lab and local native SDDL syntax
behavior. They do not establish AD operation parity, authentication-policy
From/To semantics, older Server compatibility, or ARM64 execution. No operation
has been promoted to `validated` based solely on this bootstrap evidence.
