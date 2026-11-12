# Server 2025 offline clone-configuration comparison

All ten explicit offline cases passed on `ADSDK25DC1` at
**2026-11-12T21:32:40.3242512Z**. The observed OS version was `10.0.26100.0`,
PowerShell `5.1.26100.7462`, ActiveDirectory module `1.0.1.0`, and management
assembly file version `10.0.26100.7309`. The OS field is the runtime-reported
version, not an independently collected UBR. Assembly and schema hashes are
retained in the raw summary.

The cases cover omitted/default settings, computer/site names, dynamic and
static IPv4, dynamic and static IPv6 DNS, both dual-stack modes, four ordered
resolvers, and replacement of an existing owned configuration. Every SDK result
reported `written`, `checks_skipped=true`, and incomplete prerequisites. Both
observers' XML validated against the retained Microsoft XSD; namespace/name,
child order, and scalar-value projections matched. The raw bytes differ in
formatting; this is semantic comparison, not byte equality.

The [host qualification](qualification.json) records three completed bounded
jobs with no timeout, uncertainty, or error. The guest process exited with code
zero. All staging is intentionally preserved under the recorded unique
`C:\ad-sdk-validation` directory. The fixture writes no NTDS clone configuration
and changes no directory objects, group membership, ACLs, or VM lifecycle state.

The host checks the exact three owned VMs, contained paths, private switch, and
all configured switch connections, including the powered-off member. Unrelated
management ports are excluded only after their different switch ownership is
corroborated through CIM. The same canonical profile mutex is held through
execution and capture. Unknown child completion prohibits subsequent guest
commands; no operation is retried.

The reviewed SDK source is `4120ce5d13dd49de490cef67d41767ac3b409715`.
The [build manifest](build.json) pins its archive and the executable SHA-256
`9FC1C95989517E0AC5753747B56FB17931C8ECB387E22083F6B0B60C6D4642B2`.
The archived-source build disables embedded VCS metadata; commit/archive and
file hashes are its provenance. The captured host/guest/reference scripts are
historical snapshots pinned to this run, not general lab entry points.

[The import audit](import-audit.json) records all 68 copied artifacts and their
SHA-256 hashes. `raw/` contains all 55 guest artifacts, including 20 XML files,
SDK JSON/stderr, PowerShell streams, the reference summary, and process record.
`capture-return.json` preserves the received envelope before parsing. The
retained PS5.1/PS7 checks each passed 137 offline guard/process/capture tests;
these checks are separate from the actual ten-case guest comparison.

This evidence covers successful explicit offline generation on this build.
Invalid-network reference differences, online prerequisites, unsupported hosts,
permission failures, resource lifetime, online collisions, and other supported
server versions remain separate qualification work under
[#55](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/55).
Coverage qualification states are unchanged.
