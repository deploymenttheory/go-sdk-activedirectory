# DC clone configuration

`dccloning.GenerateConfig` prepares `DCCloneConfig.xml` on Windows amd64/arm64.
`dccloning.EncodeCloneConfiguration` validates and serializes a configuration on
any platform. Neither operation clones, exports, shuts down, or reboots a machine.
The SDK uses generated Win32 bindings and its native LDAP client; PowerShell and
RSAT are used only by the optional reference qualification harness.

```go
configuration := dccloning.CloneConfiguration{
    ComputerName: "CLONE-2",
    SiteName: "Default-First-Site-Name",
    Static: true,
    IPv4Address: "192.0.2.20",
    IPv4SubnetMask: "255.255.255.0",
    IPv4DNSResolvers: []string{"192.0.2.10"},
}
result, err := dccloning.GenerateConfig(ctx, dccloning.ConfigOptions{
    Configuration: configuration,
    Timeout: 30 * time.Second,
})
// Always inspect err, result.Outcome, and result.Prerequisites.Complete.
```

Online preparation uses the current Windows identity. It checks the local AD DS
role (writable DC and RODC are accepted), polls the VM-generation-counter device,
binds to the source, locates and authenticates a Windows Server 2012-or-newer PDC,
and corroborates PDC ownership from the domain object's `fSMORoleOwner`. It reads
the source computer's GUID/SID on both endpoints, then checks transitive
`tokenGroups` membership in the source domain's RID-522 cloning group. Missing
or unreadable group data is incomplete evidence, not proof of nonmembership.
The LDAP requests use base scope and explicit property projections.

The existing local application inventory must complete without remaining
exclusions after default/custom inclusions are applied. Its
`AuthorizationLimited` flag is retained: SCM can omit services that the caller
cannot inspect. Group membership does not evaluate arbitrary changes to the
domain's clone-control-access-right ACL. A successful preparation is not a
vendor-support statement, destination-hypervisor check, future DRS RPC test, or
guarantee that cloning will succeed. No eligibility check changes directory
objects, group membership, or application inclusions.

Online output defaults to the local `DSA Working Directory`. An explicit
directory must be that directory, `%windir%\NTDS`, or a writable removable-drive
root. `AllowListFolder` is an application-inclusion location and is excluded.
Preparation checks every supported location for an existing `DCCloneConfig.xml`
and refuses any collision or unreadable candidate. It does not create directories.
Path matching is lexical and uses Windows ordinal case-insensitive comparison;
alternative junction/symlink aliases are not resolved into supported paths.

## Offline mode

Offline is an explicit request to skip **all** host, directory, application,
generation-counter, and supported-location/collision checks. It requires an
existing `Directory` and replaces an existing file there, matching Microsoft's
documented offline behavior. Syntax validation, context/deadline checks, and
file-publication errors still apply. The result sets `ChecksSkipped=true` and
`Prerequisites.Complete=false`; it conveys no online eligibility.

```powershell
go build -o tmp/dccloneconfig.exe ./examples/dccloneconfig
New-Item -ItemType Directory -Force tmp/clone-output | Out-Null
./tmp/dccloneconfig.exe -offline -directory tmp/clone-output `
  -computer-name CLONE-2 -static -ipv4-address 192.0.2.20 `
  -ipv4-mask 255.255.255.0 -ipv4-dns 192.0.2.10

# Portable validation/XML only; does not publish a file or inspect the host.
./tmp/dccloneconfig.exe -encode-only -ipv6-dns 2001:db8::10
```

## Network and XML contract

| Input | Behavior |
| --- | --- |
| No network fields | Omits `IPSettings`; clone service selects defaults. |
| IPv4 dynamic | DNS resolvers only; no address, mask, or gateway. |
| IPv4 static | Requires address, contiguous nonzero mask, and DNS; gateway optional. |
| IPv6 dynamic/static | DNS resolvers only; schema has no IPv6 address/prefix/gateway. |
| Dual stack | Explicit offline mode only; one `Static` choice applies to both families. |
| DNS | One to four nonblank literal addresses in each selected family; order and duplicates retained. |
| Computer name | Optional nonnumeric ASCII DNS label, at most 15 characters. |
| Site | Optional trimmed XML-valid text, at most 255 UTF-16 units, without control characters. |

The encoder writes UTF-8 without BOM, with only the root in
`uri:microsoft.com:schemas:DCCloneConfig`; descendants are unqualified. It escapes
XML metacharacters and follows Microsoft's captured XSD field ordering.
Computer/site omission is preserved. Site existence, address reachability,
duplicate addresses, and site/subnet matching are not checked.

The SDK rejects malformed addresses, family mismatches, IPv6 zones, mapped IPv6,
unspecified/multicast addresses, the IPv4 limited-broadcast address
`255.255.255.255`, malformed masks, blank DNS entries, and invalid
XML characters. This is intentionally stricter than the inspected Microsoft
cmdlet's string-valued validation. It correctly escapes literal XML characters
that the inspected cmdlet concatenates before parsing. WINS fields and `Force`
are absent from the inspected installed command/schema and are not SDK options;
stale Microsoft examples still mention them. The source VM-generation check is
additional SDK evidence. These differences are recorded in the
[primary-source research](research/dc-clone-configuration.md), including versions
and hashes; exact byte-for-byte PowerShell parity is not claimed.

## Failures and ownership

The result retains partial prerequisites on error. `NativeError` preserves Win32
codes; LDAP errors remain discoverable through wrapping. The operation owns and
closes its directory connections, registry/service handles, role allocation,
device handle, and temporary output file. Cleanup errors remain visible.

`Outcome=not_written` means publication was not called. `written` means the
native publication returned success. `uncertain` means publication returned an
error and callers must inspect the destination before deciding what to do next.
The SDK flushes and closes an owned temporary file before `MoveFileExW` with
write-through; online publication refuses destination replacement, offline
publication permits it. Replacement uses a newly created temporary file's
inherited security descriptor; it does not preserve a destination's custom ACL.
Publication is never retried and no rollback is claimed.
Concurrent writes in another supported directory can race the preflight scan;
the SDK does not lock the whole host or guarantee exclusive clone-file selection.

The default whole-operation deadline is 30 seconds. A shorter caller deadline
wins. Synchronous native locator, host, and filesystem calls cannot be forcibly
interrupted; cancellation is observed between calls. Reading a current source
VM generation identifier does not prove destination VM support.

## Qualification

Focused unit tests cover validation, XML shape/escaping, offline overwrite and
skipped checks, online collisions, publication uncertainty, stale/partial PDC
data, transitive group SID matching, and native resource/error ownership. The
Windows offline publication test uses only temporary directories. The following
schema check runs nine SDK cases against the retained Microsoft Server 2025 XSD
without loading the AD module:

[Retained local checks](research/dc-clone-configuration-evidence/offline-checks.json)
record Go test/vet results, the unchanged coverage qualification states, PS5.1/PS7
schema runs, host/tool versions, and source/binary/schema-evidence hashes.

```powershell
./scripts/lab/test-dc-clone-config-schema.ps1 -SdkBinary ./tmp/dccloneconfig.exe
```

The reference harness can run in an assigned disposable lab profile:

```powershell
./scripts/lab/reference-dc-clone-config.ps1 `
  -SdkBinary ./tmp/dccloneconfig.exe -ArtifactDirectory ./tmp/clone-reference
```

It invokes `New-ADDCCloneConfigFile -Offline` in unique owned directories for ten
cases, validates both XML files against the captured XSD, compares namespace and
value projections, and retains raw files, diagnostics, hashes, host/module
versions, and a summary. Module initialization is part of the observed reference.
All ten cases passed on Server 2025 with module `1.0.1.0` and assembly
`10.0.26100.7309`; see the [retained live comparison](../coverage/lab/server2025/cloning/configuration-offline/README.md).
Both XML documents were schema-valid and matched structurally and in values;
formatting bytes differed. The bounded host/guest runner preserves all raw
artifacts and staging. This establishes successful explicit offline generation
on that build, not online eligibility or all failure cases.

The [19-case offline comparison](../coverage/lab/server2025/cloning/configuration-negative/README.md)
adds two positive controls and 17 invalid-input cases. Eight invalid cases
produce no reference file; nine demonstrate intentionally stricter SDK
validation where PowerShell writes a configuration. The retained evidence
distinguishes those outcomes instead of claiming error-code parity.

The [online discovery regression](../coverage/lab/server2025/cloning/configuration-discovery/README.md)
records the original Windows status 1004 and the corrected minimum-version PDC
lookup. The full online API subsequently reached the typed missing-cloning-group
prerequisite on Server 2025 and published no file. Application checks and
successful online preparation remain unqualified.

`TestIntegrationCloneConfiguration` is skipped unless
`ADSDK_CLONE_CONFIG_OPTIONS` names a `ConfigOptions` JSON fixture and
`ADSDK_CLONE_CONFIG_WRITE=1`. The lab owner must select an explicit supported
directory, prepare the source prerequisites, and restore the owned file after
the run. The test logs the full result and checks the published bytes. It does
not alter prerequisites or perform VM lifecycle actions.

Live online/reference qualification remains pending under issue #55: supported
versions and RODC, missing/denied generation device, missing PDC/GC, nested group
membership, restricted LDAP/SCM access, application exclusions, supported-path
aliases, output collisions/concurrent publication, and cases beyond the retained
invalid-network matrix. The inclusion-list evidence tracked by #77 is separate evidence;
neither that issue nor a compilation result qualifies clone configuration.
