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

Use a local NTFS storage volume with at
least 150 GB free. The three guests use 2 virtual CPUs and 4 GB RAM each. Their
64 GB dynamic differencing disks share an unbooted base image.

`provision.ps1` downloads missing English amd64 evaluation media from the
Microsoft Evaluation Center using the host's BITS service. The guests remain
isolated. Alternatively, pass an existing installation ISO with `-IsoPath`;
that path is read-only input and no media download occurs.

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
.\scripts\lab\provision.ps1 -ServerVersion 2025 -StorageRoot H:\ad-sdk-lab
.\scripts\lab\lab.ps1 -Action Status
```

The provisioning entry point validates or downloads the ISO, then runs `New`,
`Configure`, and `Reference` in order. Any failed stage stops the build. These
actions can still be run individually with `lab.ps1`. The entry point never
removes an existing lab; reruns use the same ownership checks as those actions.
It provisions the base three-machine topology, not the expansion profiles
listed below. SDK test actions are separate from building/configuring the lab.

Use `-MediaOnly` to download and inspect media without creating VMs. Downloads
use uniquely named staging files and a recorded BITS job; a rerun resumes the
recorded job. Only an ISO with a readable matching amd64 Windows Server WIM is
promoted to the cache name. Existing cached media is inspected again before use.
A failed validation retains its media for inspection and does not overwrite a
cached ISO. An interrupted transfer whose job and output are both missing fails
with a diagnostic instead of adopting another job. Run retries as the same
Windows account so BITS can find its job.

Microsoft's download links can change the supplied image build. ISO SHA-256,
image index, name, and version are recorded beside the cached ISO and in the
lab manifest. For an exact image rebuild, retain that ISO and pass
`-ExpectedSHA256 <recorded-hash>` to `provision.ps1`; a mismatch stops before VM
creation. A locally recorded hash identifies the inspected image; it is not a
Microsoft-published authenticity checksum. The committed download links come
from Microsoft's evaluation pages for
[2016](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2016),
[2019](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019),
[2022](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022), and
[2025](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025).

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

This action has passed the [Server 2025 credential qualification](../coverage/lab/server2025/credentials/README.md).
It builds from a retained source snapshot and records source, harness, and executable hashes.
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

Search qualification uses the same source snapshots, binary hashes and owned VM
checks as connection qualification:

```powershell
.\scripts\lab\lab.ps1 -Action TestSearch -ServerVersion 2025
```

It compares native paging, selected binary properties, scopes and limits with
`Get-ADObject`, retains failure evidence, and verifies removal of its marked
fixture on both domain controllers. See [directory search](search.md).

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

To destroy and rebuild the Server 2025 base lab from a clean profile:

```powershell
.\scripts\lab\lab.ps1 -Action Remove -ServerVersion 2025 -StorageRoot H:\ad-sdk-lab
.\scripts\lab\provision.ps1 -ServerVersion 2025 -StorageRoot H:\ad-sdk-lab
```

The second command creates fresh VM disks, a private switch, a new domain, and
new protected credentials. It does not depend on credentials or files from the
deleted profile. The cached ISO is reused; if the cache is absent, the media is
downloaded again. An empty storage root can also be provisioned directly without
running `Remove`. Use the scripted removal rather than deleting VM files or
`state.json` manually: it needs the ownership manifest to remove registered
Hyper-V resources safely. The existing Server 2025 teardown/rebuild evidence
qualifies the underlying `Remove`/`New`/`Configure`/`Reference` actions. The new
download/orchestration entry point has separate offline regression checks; it
does not extend that evidence to unimplemented expansion profiles.

Evaluation media requires activation within Microsoft's initial activation
window and expires after 180 days. This private lab does not provide an Internet
activation path; rebuild disposable evaluation instances or supply appropriately
licensed media for longer-lived use. See the
[Microsoft evaluation terms](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025).

## Version and expansion profiles

`-ServerVersion 2016`, `2019`, `2022`, or `2025` selects separate profile storage
and VM names. Supply its corresponding ISO with `-IsoPath` and the inspected
`-ImageIndex`. Run version profiles sequentially to bound resource use. The
recorded profile results are:

| Server | Reference CRUD and replication, twice | Native conditions / reference | Current-identity connection |
| --- | --- | --- | --- |
| [2025](../coverage/lab/server2025/README.md) | Passed, including teardown/rebuild | Passed | Passed |
| [2022](../coverage/lab/server2022/README.md) | Passed | Passed | Passed |
| [2019](../coverage/lab/server2019/README.md) | Passed | Passed | Passed |
| [2016](../coverage/lab/server2016/README.md) | Passed | Passed twice after an initial reference authentication failure | Passed |

Server 2016 initially failed ordinary-user authentication in the PowerShell
condition reference after all syntax and policy-storage comparisons passed.
Cleanup passed on both DCs. Two full repeats of the unchanged test passed after
restarting the profile, including authorization denial and cleanup. The initial
failed artifact is retained separately and its cause remains undetermined. The older
profiles' module inventories and differences from the pinned documentation are
retained with their evidence. These runs qualify only the recorded slices,
not complete AD cmdlet parity, AD LDS, or ARM64 guest execution.
The [Server 2025 evidence](../coverage/lab/server2025/README.md) includes a
completed teardown/rebuild, two matching reference runs on the fresh guests,
and repeated native condition qualification.

### Replicated AD LDS on Server 2025

Build the base lab and its LDS fixture from an empty storage root, or configure
LDS on an existing owned Server 2025 profile:

```powershell
.\scripts\lab\provision.ps1 -ServerVersion 2025 -WithLDS
# Alternatively, after the base profile is configured:
.\scripts\lab\lab.ps1 -Action ConfigureLDS -ServerVersion 2025
.\scripts\lab\lab.ps1 -Action TestLDS -ServerVersion 2025
.\scripts\lab\lab.ps1 -Action TestLDSTLS -ServerVersion 2025
.\scripts\lab\lab.ps1 -Action TestLDSSearch -ServerVersion 2025
```

The member hosts two replicas in one configuration set. LDAP/StartTLS ports are
51300 and 51400; LDAPS ports are 51301 and 51401. Only the owned DC2 client address
is admitted by the fixture's firewall rule. Setup imports the installed
MS-User.LDF schema and uses the verified current domain-administrator identity;
no password is written into an installer answer file.

Each service's Personal certificate store receives the fixture's server leaf,
with NetworkService read access to its exact persisted machine key. The public
test root is trusted only inside the member and DC2 guests. Provisioning checks
the certificate actually presented to a validating .NET client. Host trust
stores are untouched. An ordinary native LDS user receives the application
partition's Readers role. Its password is retained only as a protected host
credential and passed to tests through redirected standard input.

The primary instance advertises the application partition as its default; the
replica deliberately has no default. `TestLDS` snapshots and builds the native
SDK test, checks both transports, then compares seven RootDSE properties and
the partition with AD PowerShell. .NET tests the same native-user bind/read and
invalid-password/missing-partition statuses. Results retain source, harness, and
binary hashes, guest/module versions, and failures separately from passing runs.
The dedicated fixture remains available after a test; removing the owned Server
2025 profile removes its services, keys, trust stores, accounts, and disks.

`TestLDSSearch` reads the owned application partition through both explicit
LDAPS ports using the native LDS reader. The SDK and PowerShell-hosted .NET
reference use the same credential and compare raw base/one-level/subtree results,
page-size-one continuation, caller limits, zero matches and missing-base errors.
It also verifies that the replica's absent default partition does not prevent an
explicit-base search. It retains the fixture, records no directory mutations,
and records the actual LDS server build separately from the DC2 test client and
ISO provenance. Source/harness hashes and failure artifacts use the Search host
runner. See [directory search](search.md) for scope and pending qualification.

`TestLDSTLS` builds a bounded Go test peer and runs eight cases: valid, expired,
wrong-host, and untrusted certificates over both LDAPS and StartTLS. The SDK and
.NET clients connect sequentially to each listener. Both valid controls must
bind and read the actual LDS application partition through a separately
validated TLS connection. Negative cases must reject TLS before any LDAP bind
or forwarding. The peer records certificate fingerprints and protocol counters,
never credential payloads.

The certificate-policy check captures CAPI2 SSL-policy events in separate
record/time windows around each client attempt. It matches the exact leaf,
hostname, LSASS identity and impersonated SID, then checks the expected result
and zero ignore flags. Missing or ambiguous events fail qualification. Logging
is enabled only in the owned client guest when necessary and its previous state
is restored without clearing existing events. The temporary public test root,
listener firewall rules, and peer processes have explicit ownership and cleanup
checks. Private test keys remain in the protected member-guest run directory
until the profile is removed; they are not copied to host evidence.

For a complete LDS rebuild, run the explicit profile `Remove` action, then the
same `provision.ps1 -ServerVersion 2025 -WithLDS` command. No credentials or keys
from the removed profile are required. The direct native/reference checks have
passed; the controlled negative-certificate matrix and a full LDS lifecycle run
remain qualification gates before issue #11 is closed. The other server-version
profiles have not been qualified for LDS by this fixture.

The following expansion profiles are specified for later scenario tickets;
the current scripts do not provision them:

| Stage | Additional resources and gates | Scenarios |
| --- | --- | --- |
| Child domain | One new DC for `child.ad.sdk.test`; verify parent-child trust, DNS delegation, and RID masters | Cross-domain membership and moves |
| Second forest | Separate forest DC, reciprocal conditional DNS forwarding, explicit forest-trust direction and verification | Trust discovery and claim transformation |
| RODC | Additional guest, existing site, writable replication source, restricted disposable password-replication principals | PRP, cache usage, and write rejection |
| Server 2025 dMSA | Supported DCs and workload hosts, confirmed schema/capabilities, replicated KDS root key and activation delay | Managed-account migration and recovery |
| Destructive operations | Separate disposable copies of the required topology, built from clean pre-directory images | Role seizure, level transitions, DC cloning |

Do not use ordinary VM checkpoint rollback as a directory-fixture reset. In
particular, an AD LDS replica requires a supported recovery procedure or a
freshly rebuilt configuration set. Exact expansion prerequisites and primary
sources are in the [provisioning research](research/ad-lab-provisioning.md).

Privileged lab CI must run only on isolated trusted Windows runners. Do not
give pull-request jobs from untrusted forks access to the lab credentials,
Hyper-V administrator rights, or the domain.
