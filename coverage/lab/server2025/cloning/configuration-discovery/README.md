# Server 2025 minimum-version discovery regression

The original forced PDC lookup with `MinimumVersion=Windows2012` failed with
Windows status 1004 on `ADSDK25DC1`. The fixed SDK completed the same request at
**2026-11-12T21:59:54Z**, returning `ADSDK25DC1.ad.sdk.test`. The full online
`GenerateConfig` call then passed source/PDC discovery and reported missing
Cloneable Domain Controllers membership at **22:00:10Z**. It returned
`not_written`, retained partial prerequisites, and published no file.

| Observation | Result |
| --- | --- |
| Original SDK: PDC, minimum 2012, force discovery | Status 1004 |
| Original SDK: remove only minimum version | Success |
| Binding call with original flags `0x40200091` | Status 1004 |
| Binding call with only `0x10` removed: `0x40200081` | Success; buffer release status 0 |
| Original SDK: add explicit DNS domain | Status 1004 |
| Fixed SDK: unchanged original request | Success |
| Original full online configuration call | Stops at PDC lookup with status 1004 |
| Fixed full online configuration call | PDC functionality 10; typed missing-group prerequisite |

The SDK combined the generic directory-service requirement with a
minimum-version requirement. [MS-NRPC section 3.5.4.3.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/fb8e1146-a045-4c31-98d1-c68507ad5620)
requires these flags to be mutually exclusive. The fix selects exactly one,
preserving the requested version, PDC requirement, forced discovery, and DNS
results. The generated binding needed no change.

The native-boundary regression failed before the fix for all four supported
minimum versions and passed afterward. Those logs and the unchanged diagnostic
and configuration-helper sources are under `helpers/`. Full Go tests and vet
also passed. The live run exercises the 2012 selector on this Server 2025 DC;
the other selector values have unit coverage here, not equivalent live results.

`before/` uses SDK commit `4120ce5d13dd49de490cef67d41767ac3b409715`;
`after/` uses `c72c7b0a4a785f177a70f26729b7d9ffff140a46`. The build manifests
record SDK commits and executable hashes; the full API build manifests also
pin the source archives. The helper sources are unchanged.
The [import audit](import-audit.json) records 76 byte-preserved artifacts across
eight observed runs, including process exit status, raw output, host journals,
received envelopes, and historical script snapshots. Go snapshots use `.go.txt`
so they do not become SDK packages.

Every held child process and host job completed. Failed locator probes retain
their expected failure verdict. All guest staging remains preserved. The
scripts verified the exact owned lab, private switch, disks, and VM identities,
holding the canonical profile mutex during execution. Both full API probes
used an independently verified unsupported scratch output directory. Neither
changed membership, application inclusion lists, ACLs, or VM lifecycle state.

This establishes the discovery fix and the observed missing-group result.
Application checks were not reached. It does not qualify successful online
configuration, reference equivalence for missing prerequisites, or full issue
[#55](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/55).
Coverage qualification states remain unchanged.
