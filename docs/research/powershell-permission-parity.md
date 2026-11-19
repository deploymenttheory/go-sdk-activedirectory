# AD PowerShell permission-update parity

On 2026-11-19, the changed public SDK was compared with the installed Active
Directory PowerShell module on an isolated Server2025 lab. The Windows/amd64
SDK client used Go1.27.4, the portable backend and explicit Kerberos SASL Seal.
PowerShell independently read the SDK target after each operation.

| Operation | PowerShell reference | SDK and independent readback |
| --- | --- | --- |
| Create OU with protection omitted | Protected | Protected |
| Disable OU protection | Unprotected | Unprotected |
| Enable OU protection | Protected | Protected |
| Disable OU protection again | Unprotected | Unprotected |
| Set CannotChangePassword true | True | True |
| Set CannotChangePassword false | False | False |

All six comparisons passed. Separate reference and SDK objects were beneath a
fresh owned parent OU. Cleanup verified all five object GUIDs absent on both DCs.
Run: `p20261119t070615156z`. No account credential, domain policy, VM power or
network setting changed. Full raw results remain in the owned lab capture.

The focused wire regressions cover ordinary writes, explicit version assertions,
permission denial, lost/malformed responses, cancellation and partial readback.
Explicit version requests remain strict; ordinary writes do not promise atomic
protection against concurrent permission changes. This comparison qualifies the
listed Server2025 operations, not the remaining SDK195 server/client matrix.

References: [New-ADOrganizationalUnit](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adorganizationalunit?view=windowsserver2025-ps),
[Set-ADOrganizationalUnit](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adorganizationalunit?view=windowsserver2025-ps),
[Set-ADAccountControl](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountcontrol?view=windowsserver2025-ps).
