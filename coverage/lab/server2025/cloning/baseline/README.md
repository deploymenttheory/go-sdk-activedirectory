# Native DC cloning exclusion baseline

On 2026-11-12 at 19:08:53 UTC, the native Go SDK and
`Get-ADDCCloningExcludedApplicationList` returned the same multiset of **28
typed exclusions** on the owned disposable `ADSDK25DC1` controller. The SDK
reported `complete=true` and `authorization_limited=true`. The reference harness
reported no process, output, comparison, or cleanup error; the parent
qualification also confirmed guest file/process/session cleanup.

This is the ordinary inventory baseline. It does not qualify native XML
generation, access-denied paths, repeated resource lifetime, older Windows
Server versions, or native ARM64 execution. Earlier program/custom-list/XML
captures under `docs/research/dc-cloning-evidence` are PowerShell-only probes;
offline SDK fixture tests, including exact XML bytes, are separate evidence.
Issue #54 remains under qualification.

| Identity | Value |
| --- | --- |
| Run | `cloning-native-20261112T190408Z-bbd0ec72` |
| OS / architecture | Windows Server 2025, `26100.32230`, AMD64 |
| PowerShell | `5.1.26100.7462` |
| AD module / DLL | `1.0.1.0` / `10.0.26100.7309` |
| AD DLL SHA-256 | `10116057543299F2FC333E4C1DA6B24411E050D043724376CAF5B3BCF49ED731` |
| SDK source commit | `de9572923ff7daa3d191f76b73dbf500d92d3549` |
| Archived source SHA-256 | `DAD09A1053C26EFCB5290CB3C35B40B0043EE58525DD49D5A4FEA3D06AE84669` |
| Executable SHA-256 | `DA8B98848CC31CD5E3CBAB79725216DDE31FE891235B3B327052F75F5245682D` |
| Harness source commit | `00c7fcf493b64f7ccc3b47658f2bf30f07068ff3` |
| Harness SHA-256 | `5334552AC1E690ED45D7DDCF7C85819A18FEB0593674087842BDC65BEB17AE5B` |

The parent built the archived source with `-trimpath -buildvcs=false
-mod=readonly`, verified the executable and harness hashes before use, and
copied the two reports back with SHA-256 verification. Both reports are retained
unchanged, including their original line endings; `.gitattributes` prevents
Git text conversion from invalidating their digests.

| Retained report | Original and retained SHA-256 |
| --- | --- |
| [reference.json](reference.json) | `0E51CDCCFAA1A40ECFE5416F808E1A23066E5BDCA1CABE46FA0F373E1103B9E9` |
| [qualification.json](qualification.json) | `541E01E9E6BE166ADE79DFF910788608C35C0E933B27C7ACE9C6DFE9B1A7CB86` |

The qualification's `reference_sha256` binds it to the retained reference
report. The latter includes both complete typed results and the observed
environment. No coverage acceptance IDs are promoted to validated by this
baseline alone.
