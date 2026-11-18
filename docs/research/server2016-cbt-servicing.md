# Server 2016 LDAP CBT servicing route

Research date: 2026-11-18. Supporting SDK04/SDK05 research only; no package was
downloaded, installed, or tested on a lab guest by this researcher.

## Baseline and decision

The coordinator supplied inventory from
`H:/ad-sdk-lab/portable-kerberos/preflight-server2016-20261118t155006080z.json`:
both 2016 DCs have `CurrentBuild=14393`, **`UBR=693`**, installed
`KB3213986`, `KB3192137`, `KB3211320`, and installed RollupFix
`14393.693.1.1`; `ntdsai.dll=10.0.14393.206`,
`wldap32.dll/kerberos.dll=10.0.14393.0`. These are supplied observations,
not this researcher's probes. Do not describe these machines as RTM/UBR 0.

The original Server 2016 CBT milestone remains **KB4025339, July 11, 2017,
14393.1480**: Microsoft's CVRF maps CVE-2017-8563 to that KB for products
10816/10855 and marks restart required. The July deployment table identifies
`Windows10.0-KB4025339-x64.msu`. The observed `.693` baseline predates that
milestone; this is servicing evidence, not an enforcement-test result.
[CVRF](https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2017-Jul),
[KB4025339](https://support.microsoft.com/en-us/servicing/os/windows-10/2017/07/july-11-2017-kb4025339-os-build-14393-1480),
[deployment table](https://support.microsoft.com/en-us/servicing/os/windows/2017/07/security-update-deployment-information-july-11-2017).

**Do not plan around an unverified July 2017 download.** The official Catalog
search returned no results for KB4025339 on the research date, despite the
KB's surviving Catalog link. An authentic downloadable MSU and its exact
historical SSU prerequisites were not established here. This does not prove
that every historical Microsoft CDN copy is unavailable.
[Catalog observation](https://www.catalog.update.microsoft.com/Search.aspx?q=KB4025339).

For a current Server 2016 baseline, the documented sequence from the supplied
old baseline is **latest SSU KB5131083 → bridge CU KB5062560 → current CU
KB5131291**, completing any required reboot between stages. The current CU
is November 10, 2026, **14393.9688**, and explicitly requires a CU released
on/after July 8, 2025, such as KB5062560 (**14393.8246**), even for Catalog
installation. The bridge requires the latest SSU. KB5131083 has no published
prerequisites and supersedes the bridge article's July SSU KB5062799;
therefore a separate KB5062799 installation is unnecessary. This sequence is
an inference from Microsoft's prerequisites/supersedence, **not a successful
installation on `.693`**; package applicability remains to be checked.
[current CU prerequisites](https://support.microsoft.com/en-us/servicing/os/windows-10/2026/11/kb5131291-windows-10-1607-security-update),
[bridge prerequisites](https://support.microsoft.com/en-us/servicing/os/windows-10/2025/07/july-8-2025-kb5062560-os-build-14393-8246),
[SSU prerequisites](https://support.microsoft.com/en-us/servicing/os/windows/ssu/2026/11/kb5131083-windows-10-1607-ssu),
[SSU supersedence](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=10d139d8-ce5a-4ba0-a1d7-23f709fc9676).

For CBT qualification alone, stopping at the verified bridge would already
exceed the 2017 implementation milestone; it would leave the lab behind the
current CU. Neither latest OS servicing nor the later 2020 CBT GPO/events is
the original CBT implementation requirement. The 2020 controls/events are a
separate milestone; after supported servicing, the CBT DWORD `2` means
Always, and registry changes are dynamic without a computer restart. The
older-system Extended Protection prerequisite in KB4034879 concerns Server
2008 and earlier, not Server 2016.
[CBT implementation/configuration](https://support.microsoft.com/en-us/servicing/os/windows-server/2020/02/kb4034879-use-the-ldapenforcechannelbinding-registry-entry-to-make-ldap-authentication-over-ssl-tls),
[2020 milestone](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412).

## Verified official x64 packages

Each row is the Catalog entry specifically titled **Windows Server 2016 for
x64-based Systems** (AMD64, all languages). URLs and digests were obtained
from Microsoft's `DownloadDialog.aspx` metadata, POSTing the row's Catalog
`updateID`; each direct URL returned HTTP 200 to a HEAD request with the byte
length shown. HEAD establishes availability only, not downloaded-content
authenticity. The corresponding details pages identify product/architecture.
[Catalog download endpoint](https://www.catalog.update.microsoft.com/DownloadDialog.aspx).

| Order / identity | Official MSU | Bytes / official SHA-1 |
| --- | --- | --- |
| 1. **KB5131083**, 2026-11 Servicing Stack Update. Catalog ID `10d139d8-ce5a-4ba0-a1d7-23f709fc9676`. [Details](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=10d139d8-ce5a-4ba0-a1d7-23f709fc9676) | [windows10.0-kb5131083-x64_e58efc0fc4de2972bf79a59ba35dc0e533b68728.msu](https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2026/11/windows10.0-kb5131083-x64_e58efc0fc4de2972bf79a59ba35dc0e533b68728.msu) | `13029550` / `e58efc0fc4de2972bf79a59ba35dc0e533b68728` |
| 2. **KB5062560**, 2025-07 Cumulative Update, **14393.8246**. Catalog ID `2071c0f7-f5d7-42b2-a704-1dd0f4ff4582`. [Details](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=2071c0f7-f5d7-42b2-a704-1dd0f4ff4582) | [windows10.0-kb5062560-x64_eab2ba1274fcf4fc3169e7dcfff8be1aeca1de08.msu](https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2025/07/windows10.0-kb5062560-x64_eab2ba1274fcf4fc3169e7dcfff8be1aeca1de08.msu) | `1756681042` / `eab2ba1274fcf4fc3169e7dcfff8be1aeca1de08` |
| 3. **KB5131291**, 2026-11 Cumulative Update, **14393.9688**. Catalog ID `563d1041-2048-4977-aadc-614237e30adb`. [Details](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=563d1041-2048-4977-aadc-614237e30adb) | [windows10.0-kb5131291-x64_d8d8e50d7311255186cfec29c7851d690d50dc06.msu](https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2026/11/windows10.0-kb5131291-x64_d8d8e50d7311255186cfec29c7851d690d50dc06.msu) | `1938904951` / `d8d8e50d7311255186cfec29c7851d690d50dc06` |

The three DownloadDialog `digest` values decode to the SHA-1 values above;
its `sha256` fields were **empty**. No Microsoft-published SHA-256 was verified.
Record a local SHA-256 after validating the download, then compare it after
every transfer; do not label it a published Microsoft checksum. SHA-1 alone
is insufficient authenticity evidence. Validate Microsoft's trusted signature
chain and timestamp on the MSU and relevant inner CAB/catalog, retaining the
validation output. `Get-AuthenticodeSignature` reports signature information;
SignTool supports `verify /pa /v`, and `verify /pa /v /c <catalog.cat>
<catalog-member>` checks catalog membership. A valid catalog alone does not
establish that an arbitrary extracted file belongs to it. Stop for failed or
unresolved trust verification rather than bypassing checks.
[hash guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash),
[Authenticode](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature),
[SignTool verification](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-verify-a-file-signature).

## Offline installation and recovery boundary

Recommended operator journal: baseline build/UBR, edition/architecture,
installed and pending CBS packages, reboot-pending state, free disk, DC
health/replication, unchanged policy values, recovery artifact IDs, package
source/ID/size/hashes/signatures, each process exit code, servicing logs,
reboots, and post-reboot package/build/health verification. This is a lab
procedure recommendation. Obtain the exact **CBS package identity and
applicability** from the verified downloaded CAB using DISM `/Get-PackageInfo`;
it accepts CAB, not MSU. Those internal identities were not inspected here.
[DISM package inventory](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-operating-system-package-servicing-command-line-options).

For a running, network-isolated 2016 guest, use its WUSA for the local MSU,
one explicitly named file at a time, with `/quiet /norestart /log:<path>` and
wait for completion; confirm the target's supported switches with `wusa /?`.
`/norestart` defers activation when a reboot is required. Do not interpret an
installer exit or a newly created registry value as CBT qualification: finish
servicing/reboots, verify installed packages and running binaries, then run
the correct/omitted/wrong-CBT tests in the existing prerequisites note.
[WUSA behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/command-line-switches-deploy-update-packages).

Plan a controlled reboot boundary after each CU; both Catalog entries can
request restart. For KB5131083, Support says a restart **might** be required,
whereas Catalog installation metadata says **Never restarts**: preserve that
source discrepancy and honor the guest's actual pending-reboot state before
continuing. All three Catalog entries say installation requires no network.
[bridge installation metadata](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=2071c0f7-f5d7-42b2-a704-1dd0f4ff4582),
[current CU installation metadata](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=563d1041-2048-4977-aadc-614237e30adb),
[SSU Support](https://support.microsoft.com/en-us/servicing/os/windows/ssu/2026/11/kb5131083-windows-10-1607-ssu),
[SSU Catalog](https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=10d139d8-ce5a-4ba0-a1d7-23f709fc9676).

SSUs **cannot be uninstalled**. The CU entries describe removal through
Installed Updates, but that is not a promise of exact baseline recovery.
Before installation, the owner must establish a recoverable DC/lab baseline;
DC snapshot recovery relies on hypervisor VM-Generation ID safeguards and
can trigger AD recovery/replication. Do not assume an arbitrary disk rollback
restores a consistent directory. Preserve uninstall options by avoiding DISM
`/ResetBase`, which prevents uninstalling installed updates.
[SSU permanence](https://support.microsoft.com/en-us/servicing/os/windows/ssu/2026/11/kb5131083-windows-10-1607-ssu),
[DC safe-restore architecture](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/virtualized-domain-controller-architecture),
[DISM cleanup semantics](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-operating-system-package-servicing-command-line-options).

Remaining checks are downloaded-content/signature verification, actual guest
applicability from the `.693`/KB3211320 baseline, disk/reboot/recovery readiness,
successful ordered servicing, and observed CBT enforcement. The original
July 2017 package/prerequisite route remains unverified; it is not needed for
the current route documented above.
