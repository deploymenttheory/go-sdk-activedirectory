# Standalone workstation rejection

The public `GenerateConfig` API rejected the local Windows 11 Enterprise
workstation with `ErrNotDomainController` at **2026-11-12T22:21:39Z**. Independent
CIM reads identified computer `SHOCONE`, domain role 0 (standalone workstation),
product type 1, and OS version `10.0.26300`. No separate OS revision/UBR was
collected. The probe ran under Windows PowerShell `5.1.26100.9818`.

The request explicitly selected online mode and a new scratch output directory.
The SDK returned `not_written`, `checks_skipped=false`, incomplete prerequisites,
and the observed machine role. Its helper exited with code 1; no configuration
file appeared. This is a native SDK observation, not an ActiveDirectory cmdlet
comparison or a Server 2025 guest result.

`initial-harness-failure/` retains the first attempt. Its native call returned
the same correct rejection, but the reporting script failed while reading an
optional JSON field that the SDK omits when unobserved. That run remains marked
failed. `corrected-harness/` handles absent optional fields and passed in a new
directory. The SDK binary was unchanged; both raw SDK outputs are byte-identical.
Both child processes completed with known exit status; no process was retried
while its completion was uncertain.

The source is `c72c7b0a4a785f177a70f26729b7d9ffff140a46`, using the same frozen
helper as the Server 2025 discovery check. Both build manifests pin its source
archive and executable SHA-256. The [import audit](import-audit.json) records
12 byte-preserved artifacts, including both probe snapshots, options, manifests,
raw streams, and qualification reports. All scratch staging remains preserved.
The probe changed no host configuration, directory data, or VM state.

This evidence covers one non-DC role and one host build. Other host roles,
successful online generation, permissions, and the remaining issue #55 matrix
are separate work. Coverage qualification states remain unchanged.
