# Active Directory reference lab

The initial lab has two writable domain controllers and one member server on a
dedicated Hyper-V private switch. Scripts and reference tests use PowerShell;
the SDK itself has no PowerShell or RSAT runtime dependency.

The Server 2025 profile has passed two reference runs with matching normalized
results and confirmed cleanup. The native Go condition tests also pass in its
member VM. See the [recorded evidence](../coverage/lab/server2025/README.md).

## Prerequisites

Run Windows PowerShell 5.1 as Administrator on a Windows Hyper-V host. This is
the [documented default on Server 2016 and later](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_windows_powershell_5.1),
including Server 2025. It avoids a separate PowerShell 7 bootstrap dependency
in isolated guests. The inspected Server 2025 image produced PowerShell
5.1.26100.7462; servicing can change the exact build, so every run records it.
This requirement applies to the lab harness, not the Go SDK.

Supply an
amd64 Windows Server installation ISO and a local NTFS storage volume with at
least 150 GB free. The three guests use 2 virtual CPUs and 4 GB RAM each. Their
64 GB dynamic differencing disks share an unbooted base image.

The default storage root is `H:\ad-sdk-lab`. The initial Server 2025 media is
`H:\ad-sdk-lab\isos\WindowsServer2025-en-us.iso`. Image 1 in this inspected ISO
is Standard Evaluation Server Core; verify the image index when using other
media. The script checks the selected image's architecture and Server version
and records its name, version, index, and ISO SHA-256.

The host's deployment tools must support the selected image. The disposable
guest disk layout includes EFI, MSR, and Windows partitions; it does not include
a recovery partition. BCDBoot explicitly targets the new VHDX's EFI partition.

## Provision and test

From the repository root in an elevated Windows PowerShell session:

```powershell
.\scripts\lab\lab.ps1 -Action New
.\scripts\lab\lab.ps1 -Action Configure
.\scripts\lab\lab.ps1 -Action Reference
.\scripts\lab\lab.ps1 -Action Status
```

`New` creates the base disk, private switch, and three guests. `Configure`
installs AD DS on the DCs and AD PowerShell tooling on all three machines,
creates `ad.sdk.test`, promotes DC2, and joins the member. It waits for guest
reboots, AD services, SYSVOL/NETLOGON, and domain discovery. Both functional
levels are explicitly set to Windows Server 2016 for the base profile.

| Guest | Role | Address |
| --- | --- | --- |
| ADSDK25DC1 | First writable DC, DNS, GC | 10.77.23.10/24 |
| ADSDK25DC2 | Second writable DC, DNS, GC | 10.77.23.11/24 |
| ADSDK25MEM | Domain member and reference runner | 10.77.23.20/24 |

Guests have no default gateway. The switch has no host or physical-network
connection. PowerShell Direct provides host-to-guest management independently
of network remoting. Existing VMs and switches are not adopted by name.

`Reference` collects the installed AD module's command/parameter-set inventory
and records host and guest architecture, OS builds, module version, schema
version, functional levels, DC roles, and the member's secure channel. It then
creates a uniquely named OU, disabled user, and group; checks user updates and
membership; observes replication to DC2; removes membership; and removes the
fixture subtree. Cleanup must be observed on both DCs before the run passes.
The normalized result omits generated fixture names so repeated successful
runs are comparable.

Compile and run the current native condition tests in the member VM:

```powershell
.\scripts\lab\lab.ps1 -Action TestConditions
```

Install Go 1.25 or later on the host first. This action snapshots the package
sources and module files, builds a Windows amd64 executable with that toolchain,
and verifies the snapshot has not changed during the build. It copies the
executable through PowerShell Direct, verifies its hash, records build settings,
source hashes and guest output, and removes the guest test files. The source
snapshot and executable are retained alongside the results for inspection.
The same executable emits an SDDL corpus for comparison with PowerShell/.NET.
The reference harness creates three unassigned audit-only authentication
policies, checks From/To descriptor storage and readback, and verifies that a
temporary ordinary user cannot create a policy. It removes its policies, user,
and OU and confirms cleanup on both DCs. A failed policy deletion does not skip
other independently owned fixtures; cleanup errors are collected with the
original operation error. The offline `test-reference-cleanup.ps1` regression
checks successful cleanup, deletion failure, and rejection of an unowned policy
under Windows PowerShell 5.1 without accessing a directory.
This validates descriptor acceptance
and storage, not claim existence, policy assignment, or logon enforcement.

Results are under `server2025\results\<run-id>`. `module.json` is an observation
of the installed reference module, not a replacement for the pinned Microsoft
documentation snapshot. `reference.json` proves reference-tool and lab behavior;
it does not claim native SDK operation parity. Keep failed runs distinct from
passing evidence.

## State, credentials, and recovery

The native connection qualification runs with:

```powershell
.\scripts\lab\lab.ps1 -Action TestConnection -ServerVersion 2025
```

It retains a source snapshot, source/harness/binary hashes, native test output,
and PowerShell RootDSE comparisons. It tests current-identity authentication,
selected/wildcard properties, repeated open/read/close, an invalid port, and a
one-second connect wait to unused private address `10.77.23.254`. It also creates
a uniquely marked temporary local administrator on the owned member solely to
run PowerShell Direct under an identity with no AD account; the native bind must
fail with LDAP status 49. The account is removed by checked SID/name/marker,
including after a lost creation response. Lookup or removal failure fails the
run; operation and cleanup errors are retained together. No fixture password is
written to the evidence. Ten offline cleanup checks run on Windows PowerShell
5.1 in CI. Nonsecret guest test artifacts remain in their unique run directory
for diagnosis. See the [recorded connection results](../coverage/lab/server2025/connection/README.md).

The explicit-credential qualification runs with:

```powershell
.\scripts\lab\lab.ps1 -Action TestCredentials -ServerVersion 2025
```

This action is awaiting its first live qualification under #10. It builds from
a retained source snapshot and records source, harness, and executable hashes.
The reference creates a unique ordinary user with a non-ASCII account name and
password, replicates the user and its OU to the second DC, and passes credentials
to the test process through redirected standard input. Passwords are excluded
from arguments, environment variables, and retained evidence.

The native test checks domain/account and UPN forms, RootDSE after credential
buffers are erased, signing/sealing options, invalid and empty password rejection,
and a valid container creation denied to the ordinary user. A current-identity
creation first establishes that the request itself is valid. PowerShell compares
RootDSE and the same permission boundary. Cleanup checks object ownership, removes
known children independently, uses nonrecursive OU removal, and requires absence
on both DCs. All aggregate failure branches and numeric AD error codes are
retained without exception messages. The offline
`test-credential-fixture-cleanup.ps1` checks these guards and error handling in CI.

Each profile has an ownership manifest containing the lab ID, VM IDs, switch ID,
image provenance, and configuration status. VM operations verify the manifest,
VM ownership note, attached disk paths, and the switch's identity, ownership,
and private type before every VM action. Reparse points
are rejected in managed paths. A failed partial disk build is retained for
inspection instead of overwritten on retry.

The lab directory grants access only to the creating user, Administrators, and
SYSTEM. A random lab password is stored as a DPAPI-protected credential file,
usable by the same Windows account on the same host. It is supplied to initial
setup, domain administration, and DSRM inside this disposable lab. No password
is written to the repository or result JSON. Bootstrap automatic logon is
disabled and its stored password and answer file are removed after setup.

`events.log` records progress. `last-run.json` records the current action as
running, passed, or failed. A per-profile mutex rejects concurrent actions.
An abruptly terminated action can leave a stale running status. `Configure` can be
retried after an interrupted promotion: it checks the guest's current role and
uses domain credentials when the guest has already become a DC.

Stop or remove only the owned profile:

```powershell
.\scripts\lab\lab.ps1 -Action Stop
.\scripts\lab\lab.ps1 -Action Remove
```

`Remove` checks both live switch ports and configured connection records before
deleting the switch. A stopped VM attached from outside the owned profile also
blocks removal. CIM query failures are errors, not evidence that a switch is
unused. This avoids host-wide Hyper-V adapter enumeration, which can fail on
unrelated host objects. An interrupted removal can resume using the manifest's
remaining VM and switch IDs.

`Remove` permanently deletes the owned VMs, switch, and profile directory,
including its results and protected credential. It retains the source ISO and
other version profiles. Export required nonsecret evidence before removal.

Evaluation media requires activation within Microsoft's initial activation
window and expires after 180 days. This private lab does not provide an Internet
activation path; rebuild disposable evaluation instances or supply appropriately
licensed media for longer-lived use. See the
[Microsoft evaluation terms](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025).

## Version and expansion profiles

`-ServerVersion 2016`, `2019`, `2022`, or `2025` selects separate profile storage
and VM names. Supply its corresponding ISO with `-IsoPath` and the inspected
`-ImageIndex`. Run version profiles sequentially to bound resource use. The
initial executable profile has been validated against Server 2025; the older
version combinations need their own recorded runs before compatibility claims.
The [Server 2025 evidence](../coverage/lab/server2025/README.md) includes a
completed teardown/rebuild, two matching reference runs on the fresh guests,
and repeated native condition qualification.

The following expansion profiles are specified for later scenario tickets;
the current scripts do not provision them:

| Stage | Additional resources and gates | Scenarios |
| --- | --- | --- |
| Child domain | One new DC for `child.ad.sdk.test`; verify parent-child trust, DNS delegation, and RID masters | Cross-domain membership and moves |
| Second forest | Separate forest DC, reciprocal conditional DNS forwarding, explicit forest-trust direction and verification | Trust discovery and claim transformation |
| RODC | Additional guest, existing site, writable replication source, restricted disposable password-replication principals | PRP, cache usage, and write rejection |
| Replicated AD LDS | Two member-hosted instances in one configuration set, dedicated LDAP/LDAPS ports, trusted certificates | LDS applicability and replication |
| Server 2025 dMSA | Supported DCs and workload hosts, confirmed schema/capabilities, replicated KDS root key and activation delay | Managed-account migration and recovery |
| Destructive operations | Separate disposable copies of the required topology, built from clean pre-directory images | Role seizure, level transitions, DC cloning |

Do not use ordinary VM checkpoint rollback as a directory-fixture reset. In
particular, an AD LDS replica requires a supported recovery procedure or a
freshly rebuilt configuration set. Exact expansion prerequisites and primary
sources are in the [provisioning research](research/ad-lab-provisioning.md).

Privileged lab CI must run only on isolated trusted Windows runners. Do not
give pull-request jobs from untrusted forks access to the lab credentials,
Hyper-V administrator rights, or the domain.
