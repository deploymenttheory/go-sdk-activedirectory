# Directory capability error compatibility

Run `capability-contract-20261118T104603Z` passed on 2026-11-18. This is local lab
evidence for #135, collected through PowerShell Direct on `ADSDK25MEM` against
`ADSDK25DC1.ad.sdk.test`, Windows Server 2025 build 26100, with the ActiveDirectory
module 1.0.1.0. It performed no directory writes.

All twelve typed reads in the existing capability sweep returned
`DirectoryCapabilityError` for an unrecognized directory. The same operations
read the real AD DS endpoint three times per session, refused the local unsupported
directory before searching, and released all seven tracked native resource types
after both successful reads and an invalid-naming-context failure. Client close
remained idempotent. `Get-ADObject` is recorded separately and excluded because
generic search intentionally has no directory-type prerequisite.

The unsupported directory is an owned in-process LDAP fixture advertising no
`supportedCapabilities`, reached through actual WinLDAP. It is not a live AD LDS
qualification. The accompanying portable regression verifies precise
`ErrUnsupportedDirectory` matching, preserved `ErrUnsupported` matching and
`ClassUnsupported`, and distinguishes backend absence from a wrong directory.

## Provenance

The binary was built from a dirty working tree based on
`1d18aca0388eae41c4fefa8c001c80e670353cd2`, including this capability fix. The
manifest records the SHA-256 of all 477 captured source files as bytes on the
Windows working tree at execution; it is not a claim that the base commit alone
contains the fix. The executable SHA-256 was checked independently inside the
guest before execution. The host capture retains the source snapshot and binary
under `H:\ad-sdk-lab\captures\capability-contract-20261118T104603Z`.

- [result.json](result.json): raw per-operation observations and explicit exclusions.
- [qualification.json](qualification.json): guest facts, source base and binary digest.
- [source-hashes.json](source-hashes.json): captured source file digests.
- [test-output.txt](test-output.txt): raw test output.
- [runner.ps1](runner.ps1): executed collector, with fresh host and guest run directories.
- [artifact-hashes.sha256](artifact-hashes.sha256): digests of these five raw artifacts.

The captured files retain their original bytes through `.gitattributes`. The
runner reads the existing lab credential file without copying credential values
into any artifact. To repeat it, approve a direct PowerShell invocation of
`runner.ps1 -Repo <checkout> -LabRoot <configured-profile>`; each invocation creates
a new capture and does not replace this evidence.

## Scope

This run does not claim missing-native-export behavior, other Server versions,
Linux or macOS execution, arm64 live acceptance, or portable authentication.
`full_ticket_complete` remains false in the sweep artifact. No historical evidence,
coverage inventory state or readiness gate was changed.
