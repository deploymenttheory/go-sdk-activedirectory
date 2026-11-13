# Optional feature reference capture

Captured on 2026-11-13 from the isolated two-DC/member Hyper-V profile on H:
(`ad.sdk.test`). Local execution, not a CI result.

`scripts/lab/reference-optional-features.ps1` is read-only. It pins the
configuration naming context by GUID before reading, cross-checks every feature
returned by `Get-ADOptionalFeature` against a raw `Get-ADObject` read of the
same DN, and fails if the cmdlet and raw identities, feature GUIDs, or
disablability disagree with the documented flag bits.

| Property | Observed value |
| --- | --- |
| Source endpoint | `ADSDK25DC1.ad.sdk.test` |
| Collected from | `ADSDK25MEM`, Windows Server 2025 Standard Evaluation 10.0.26100 build 26100 |
| AD module | 1.0.1.0 |
| Forest functionality | 7 |
| DC functionality | 10 |

`reference.json` has `passed: true`. All three features agreed between the
cmdlet and raw projections:

| Feature | Feature GUID | Flags | Disablable | Required forest level |
| --- | --- | ---: | --- | ---: |
| Recycle Bin Feature | `766ddcd8-acd0-445e-f3b9-a7f9b6744f2a` | 1 | no | 4 |
| Privileged Access Management Feature | `ec43e873-cce8-4640-b4ab-07ffe4ab5bcd` | 1 | no | 7 |
| Database 32k Pages Feature | `52982ac6-1e73-754f-ae24-73ae2775aab8` | 1 | no | 10 |

None reports a required *domain* level. Every feature has flag bit 4 clear, so
none is disablable once enabled — which is why `Disablable` is uniformly false
rather than a property of this lab's state.

Note the interaction worth keeping: the forest runs at functional level 7, so
Database 32k Pages (requiring 10) **cannot be enabled here** even though it is
present in the configuration partition. Presence in `Get-ADOptionalFeature` is
therefore not applicability.

## What this is not

The artifact records `full_ticket_complete: false` and
`comparison_performed: false`. No native SDK readings were supplied through
`-NativeJSON`, so this is the PowerShell reference side only and nothing has
been compared. **No coverage state advances on this file.**
