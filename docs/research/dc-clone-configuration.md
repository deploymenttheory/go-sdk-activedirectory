# DC clone configuration contract

Research checkpoint: 2026-11-12, issue #55, starting from `main` commit `025b7f2`. This note combines Microsoft documentation, an existing captured Microsoft XSD, and read-only inspection of the installed Microsoft AD management assembly. No AD cmdlet, native cloning export, VM operation, directory mutation, or reference generation was executed for this research. Runtime and differential qualification remain outstanding.

## Evidence and confidence

| Evidence | Scope |
| --- | --- |
| [New-ADDCCloneConfigFile documentation](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-addccloneconfigfile?view=windowsserver2025-ps) | Public operation and options. Several examples and parameter tables conflict with the installed implementation; do not treat examples as executable contracts. |
| [Microsoft deployment guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/virtualized-domain-controller-deployment-and-configuration) | Prerequisites, offline overwrite, and clone configuration discovery locations. |
| [Retained Server 2025 artifacts](dc-cloning-evidence/server2025-readonly.json) | Existing observation of `ADSDK25DC1`, 2026-11-12 18:35:09 UTC; AD assembly file version `10.0.26100.7309`. Includes `DCCloneConfigSchema.xsd`, 3,783 bytes, SHA-256 `DBC8E4F53A0C078E50F52523425C59F2636C157501A2CFF9B4EB179C8B2CD62D`, and `SampleDCCloneConfig.xml`, 928 bytes, SHA-256 `1C23DCB3D11449C2EA1C4FEB87A9D9CE09A1EAE8B24232F23C3DD16E8C343E08`. This is schema evidence, not execution of this cmdlet. |
| Installed Microsoft assembly | `C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\v4.0_10.0.0.0__31bf3856ad364e35\Microsoft.ActiveDirectory.Management.dll`; assembly version `10.0.0.0`, file version `10.0.26100.7920`, SHA-256 `0DF8B9B0B77C652BB65971C3745B2B7E99AA899A0390CDDAB12142ED96EB1FC7`. Metadata and method bodies were read with reflection; no inspected method was invoked. Findings below are observations of this binary, not a Microsoft cross-version guarantee. |

The local inspection covered `Microsoft.ActiveDirectory.Management.Commands.NewADDCCloneConfigFile`, its `NewADDCCloneConfigFileParameterSet`, and the named methods below. It used `GetCustomAttributesData`, `GetMethodBody().GetILAsByteArray()`, and metadata-token resolution. Reflection ran under the host PowerShell/.NET runtime; resolved framework type versions are therefore not evidence of the target assembly's original runtime dependencies.

## Public behavior and documented prerequisites

The command prepares `DCCloneConfig.xml`; it does not itself clone a DC. Online checks include a sufficiently recent PDC, cloning-group membership, and unresolved application exclusions. Offline requires an explicit directory and omits those prerequisites. The documented pipeline output is `None`. Computer/site settings are optional; the cmdlet documentation describes a 15-character computer-name limit. Its examples containing `Force`, WINS options, or combined online IPv4/IPv6 settings require correction against the metadata below. [Cmdlet contract](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-addccloneconfigfile?view=windowsserver2025-ps).

The deployment guide requires VM-Generation ID support and an available Windows Server 2012-or-newer PDC. It explicitly supports both writable and read-only source DCs, including global catalogs and FSMO holders. A writable-source-only restriction would be an SDK limitation, not the documented cloning contract. Online defaults to the DSA Working Directory; offline overwrites existing output. The clone consumer searches DSA Working Directory, `%windir%\NTDS`, then removable read/write roots in drive-letter order, selecting the first file. `AllowListFolder` belongs to the application allow list and is not a clone configuration location. [Deployment and placement](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/virtualized-domain-controller-deployment-and-configuration).

The supplied site defaults to the source's site when omitted. Omitted computer naming is performed during cloning; configuration generation should preserve omission. The old deployment introduction locates Microsoft's schema/sample in `%windir%\System32` and says offline generation can run on a computer outside the domain. [Microsoft introduction](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831734%28v%3Dws.11%29).

## Exact parameter metadata observed locally

All sets accept optional `CloneComputerName` and `SiteName`. `Path` is optional in online sets. String properties carry `ValidateNotNull` and `ValidateNotNullOrEmpty`; the metadata inspected contains no IP-address-specific validation attribute. The table is derived from the installed binary identified above.

| Set | Mandatory | Other network properties |
| --- | --- | --- |
| `IPv4DynamicSettings` | None | `IPv4DNSResolver` |
| `IPv4StaticSettings` | `Static`, `IPv4Address`, `IPv4SubnetMask`, `IPv4DNSResolver` | `IPv4DefaultGateway` |
| `IPv6DynamicSettings` | None | `IPv6DNSResolver` |
| `IPv6StaticSettings` | `Static`, `IPv6DNSResolver` | None |
| `OfflineExecution` | `Offline`, `Path` | `Static`, all IPv4 fields above, `IPv6DNSResolver` |

Neither `PreferredWINSServer` nor `AlternateWINSServer` exists as a parameter property in this assembly. `Force` does not exist either. No online parameter set accepts both address families. Offline permits both families but exposes one shared `Static` switch. A Go API with independent per-family modes is a useful schema-level interface; mixed combinations beyond the cmdlet's binder must be described as an intentional extension, not exact parameter-set parity.

`GetPassedInParameters` trims path, computer name, site, IPv4 address, mask, and gateway. It stores DNS arrays before serialization trims individual values. Its mode selection is:

- IPv4 static only when `Static` is true and address, subnet mask, and a non-null DNS array are present.
- Otherwise IPv4 dynamic when the IPv4 DNS array is present. Dead WINS fields are also tested, but the inspected parameter collection never assigns them.
- IPv6 static when `Static` and the IPv6 DNS array are present; otherwise IPv6 dynamic when that array is present.
- Without any network parameters, neither family is selected and the file omits `IPSettings` completely.

These decisions are visible at `GetPassedInParameters` IL offsets `021E` through `02AE`; no directory request occurs in that method.

## Offline validation, writing, and online collision behavior

`NewADDCCloneConfigFileBaseProcessCSRoutine` branches on `_offline` at IL `000A`. Offline goes directly to the shared validation stage (`009F`), bypassing `LocateLocalDC`, `PreCloningCheck`, and the pre-write `CheckExistingFiles`. The post-write location check is independently skipped at `0175`. With a nonempty explicit path, `GetOutputFileFullName` also bypasses `GetDitLocation`. This proves the inspected command's processing routine does not intentionally contact the directory, inspect applications, inspect VM generation, or read NTDS path configuration on its valid offline path. Inherited cmdlet pipeline setup has not been exhaustively traced; no end-to-end offline invocation was performed here.

Offline does **not** skip all input validation. Shared `ValidateIpv4StaticSettings` rejects any supplied IPv4 address, mask, or gateway unless address, mask, a non-null IPv4 DNS array, and `Static` are all present. The shared routine also rejects either DNS array with more than four entries. These checks run in both modes. The observed methods do not parse IP addresses, validate masks, resolve site names, test computer-name uniqueness, or validate the emitted document against XSD. DNS whitespace-only entries are skipped during serialization, potentially leaving a structurally invalid static block. A strict SDK validator should explicitly document its stronger behavior.

`GetOutputFileFullName` resolves a directory with `Path.GetFullPath`, appends a separator if necessary, and then appends `DCCloneConfig.xml`. Without a path, `GetDitLocation` reads `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\DSA Working Directory`; it does not manufacture a `%windir%\NTDS` fallback when the registry value is absent. `GenerateXmlFile` constructs an `XmlTextWriter` at that filename using `UTF8Encoding(false)`, so the observed writer selects UTF-8 without BOM. No directory-creation code was found in these methods. Actual path-error and overwrite exceptions still need invocation tests.

The online collision guard is broader than checking only the requested target. `CheckExistingFiles` invokes `DsRolepCheckExistingCloneConfigFile(out bool, stringBuffer, 768)` with **no target directory**. Before writing, any discovered clone file prevents generation. After writing, a second discovery check must find a clone file; otherwise the command warns and deletes the file it just generated. The native helper's exact search, errors, race behavior, and status handling are not independently qualified. The managed caller discards its integer return code. Do not emulate that loss of error information or publish a handwritten ABI for this undocumented helper. Candidate SDK behavior is to inspect the documented clone locations before publication and reject an online destination outside them, using generated filesystem/registry bindings.

The processing routine calls no `WriteObject`. Its user-facing information goes through `ConsoleWrite`, which invokes `Write-Host`, plus warnings/errors. A Go result containing output path, write outcome, performed/skipped checks, and qualification limits is an SDK contract, not a PowerShell object type. Failure should preserve an existing file and expose whether publication might have occurred; an explicit offline operation can retain documented overwrite semantics while making that effect clear in its API.

## Captured Microsoft XML contract

The following rules are derived directly from the captured `DCCloneConfigSchema.xsd` and sample in [the retained Microsoft artifact observation](dc-cloning-evidence/server2025-readonly.json), not inferred from illustrative web XML.

| Location | Shape |
| --- | --- |
| Root | `DCCloneConfig` in namespace `uri:microsoft.com:schemas:DCCloneConfig`. |
| Descendants | Unqualified elements: schema has `elementFormDefault="unqualified"`. |
| Root children | Optional `SiteName`, `ComputerName`, and `IPSettings`, each at most once, inside `xs:all`. |
| `IPSettings` | Optional `IPv4Settings` and `IPv6Settings`, each at most once, inside `xs:all`. |
| Each family | Exactly one `StaticSettings` or `DynamicSettings` when the family element exists. |
| IPv4 static | Ordered sequence: one `Address`, one `SubnetMask`, optional `DefaultGateway`, one to four `DNSResolver` elements. |
| IPv4 dynamic | Zero to four `DNSResolver` elements. |
| IPv6 static | One to four `DNSResolver` elements; optional unqualified `Reserved` string attribute. |
| IPv6 dynamic | Zero to four `DNSResolver` elements; optional unqualified `Reserved` string attribute. |
| Scalar values | `xs:string`: the XSD does not enforce IP syntax, address families, contiguous masks, computer-name length, nonempty values, or site existence. |

There are no WINS elements, IPv6 address/prefix/gateway elements, or wildcard extension points. Do not invent them. A namespace prefix belongs only on the root; a default namespace would qualify unprefixed descendants unless each subtree resets it. Empty root is valid. Empty static family blocks are not. `xs:all` permits root and family-container order variation; the IPv4 static field sequence is mandatory.

The local writer's `GenerateXmlContentString` creates the `d3c` root prefix and emits `ComputerName`, then `SiteName`, then `IPSettings`; inside it, IPv4 precedes IPv6. It emits only fields selected by the mode logic above. DNS order and duplicates are retained after trimming/removing blank entries. It concatenates strings into XML before parsing through `XmlReaderUtil`/`XmlDocument`, so XML metacharacters are not escaped at the concatenation stage. The Go implementation should use an encoder and preserve literal values correctly rather than copying this defect. `GenerateXmlFile` enables indented formatting. Exact byte formatting, declaration text, newline convention, and final newline have not been captured for this cmdlet.

A minimal schema-valid static example, synthesized from the captured schema, is:

```xml
<?xml version="1.0" encoding="utf-8"?>
<d3c:DCCloneConfig xmlns:d3c="uri:microsoft.com:schemas:DCCloneConfig">
  <ComputerName>CLONE01</ComputerName>
  <IPSettings>
    <IPv4Settings>
      <StaticSettings>
        <Address>192.0.2.20</Address>
        <SubnetMask>255.255.255.0</SubnetMask>
        <DNSResolver>192.0.2.10</DNSResolver>
      </StaticSettings>
    </IPv4Settings>
  </IPSettings>
</d3c:DCCloneConfig>
```

Recommended SDK validation, explicitly stronger than the observed cmdlet: require actual addresses of the declared family; reject address zones/prefix notation where the field expects an address; validate a contiguous IPv4 mask; enforce static-field completeness and DNS cardinality; reject XML-invalid characters; distinguish omitted from explicitly invalid empty values. Address reachability, duplicate-address detection, site/subnet matching, and uniqueness are separate operational questions. Do not imply that syntactic validation establishes them.

## Native and LDAP implementation facts

The existing [`dccloning` implementation](../../dccloning/cloning.go) and [exclusion research](dc-cloning-exclusions.md) provide the application-list operation. Reuse `Inspect`, whose result subtracts both default and selected custom inclusions; `Generate` intentionally computes a different default-only list. An empty exclusion list means none were observed under the caller's access. Preserve `Complete` and `AuthorizationLimited`; do not invent a universal safe-to-clone verdict.

| Concern | Supported contract and consequence |
| --- | --- |
| Local AD DS role | `DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, ...)` returns local state, and its buffer belongs to `DsRoleFreeMemory`. `DSROLE_PRIMARY_DS_RUNNING` and `DSROLE_PRIMARY_DS_READONLY` are independent flags. Record read-only state; do not reject it merely by inference. [Function](https://learn.microsoft.com/en-us/windows/win32/api/dsrole/nf-dsrole-dsrolegetprimarydomaininformation), [structure](https://learn.microsoft.com/en-us/windows/win32/api/dsrole/ns-dsrole-dsrole_primary_domain_info_basic). |
| PDC discovery | `DsGetDcNameW` with `DS_PDC_REQUIRED`, `DS_DIRECTORY_SERVICE_8_REQUIRED`, and DNS-name return selects a 2012-or-newer PDC. Free output with `NetApiBufferFree`. Locator results can be cached and do not prove current availability or authenticated identity; actually bind/use the server. The local cmdlet explicitly requests forced discovery. [DC Locator](https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamew). |
| PDC feature corroboration | RootDSE `domainControllerFunctionality` describes the individual DC; value 5 corresponds to Windows Server 2012. Do not substitute domain or forest functional level. [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6dab41f1-e379-4404-a12e-30135b711729). |
| Group identity | Use the source domain SID with RID `522`, not a localized group name. [Microsoft group definition](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn579255%28v%3Dws.11%29). |
| Membership query | `tokenGroups` supplies transitive SID membership. In AD DS it can be absent when no GC can evaluate membership; `tokenGroupsNoGCAcceptable` can be incomplete. Missing/unreadable data is not a successful negative membership check. Exact equivalence to the cmdlet's `Get-ADPrincipalGroupMembership` path remains unqualified. [MS-ADTS tokenGroups](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/01002598-92db-4c59-822e-b22f53168c90). |
| Cloning permission | Extended right `3e0f7e18-2c7a-4c10-ba82-4d926db99a3e` applies to `Domain-DNS`. Group membership alone cannot prove effective access when administrators change the domain DACL. [Extended right](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-clone-domain-controller), [Microsoft permission repair example](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/reference/virtual-dc/virtualized-domain-controller-technical-reference-appendix). |
| Actual clone RPC | `IDL_DRSAddCloneDC` creates directory objects; it is not a read-only prerequisite probe and must not be called by configuration generation. A successful LDAP bind cannot prove future DRS RPC reachability from the clone. [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/ef0bfb1d-037b-4626-a6d9-cc7589bc5786). |
| Saved VM generation | `msDS-GenerationId` is system-only, nonreplicated, single-valued, and exactly 16 bytes. If inspected, query the source DC's local copy. Its presence is historical AD state, not proof of current device availability. [MS-ADA2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/11b969e5-180c-4c16-89b4-2a2bf3317660). |

The local cmdlet's `PreCloningCheck` locates a PDC, obtains the local DC, queries that computer's group memberships using the PDC as server, compares each group SID with domain SID plus 522, and invokes the exclusion-list cmdlet. `LocateLocalDC` requests the local computer by name. None of the inspected command methods examines the domain DACL or VM-generation device. A Go implementation can add a current-host eligibility check, but must distinguish that extra evidence from reference-cmdlet parity.

Microsoft documents a direct VM-generation probe: open `\\.\VmGenerationCounter` with read/write access, shared read/write, and `OPEN_EXISTING`; poll using `IOCTL_VMGENCOUNTER_READ` with no input and a `VM_GENCOUNTER` output. Administrator/system privileges are required. Interface GUID `3ff2c92b-6598-4e60-8e1c-0ccf4927e319` is an alternative discovery mechanism. Preserve missing-device, access-denied, and IOCTL failures separately. Use polling: the event-driven form waits for a generation change. [Device access recipe](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/virtual-machine-generation-identifier), [IOCTL contract](https://learn.microsoft.com/en-us/windows/win32/api/vmgenerationcounter/ni-vmgenerationcounter-ioctl_vmgencounter_read).

Pinned bindings `v0.6.1-0.20261112183048-fa6dc8c4593e` already contain `filesystem.CreateFile`, `io.DeviceIoControl`, `foundation.CloseHandle`, `hypervisor.VM_GENCOUNTER`, and `hypervisor.IOCTL_VMGENCOUNTER_READ`, plus AD role and discovery calls. Their generated `VM_GENCOUNTER_SYMBOLIC_LINK_NAME` contains a leading backslash; compose the final device path carefully. The generated `DeviceIoControl` accepts byte slices, marshaling empty input to NULL/zero. Validate the returned byte count and release the handle. [Pinned generated IO wrapper](https://github.com/deploymenttheory/go-bindings-win32/blob/fa6dc8c4593e/bindings/win32/system/io/io_functions.go), [hypervisor constants](https://github.com/deploymenttheory/go-bindings-win32/blob/fa6dc8c4593e/bindings/win32/system/hypervisor/hypervisor_constants.go). These files were inspected in the local module cache. New unsupported wrappers belong in the generator/upstream bindings, never as SDK-local dynamic syscalls.

## Qualification gaps and acceptance boundaries

- No end-to-end invocation of `New-ADDCCloneConfigFile` was performed, online or offline. A future explicitly offline probe in owned scratch directories should capture default/name/site/network outputs, overwrite, invalid values, DNS array edges, and exact bytes without touching NTDS configuration. Inherited command initialization still needs verification before declaring that probe completely directory-free.
- XML shape and parameter metadata are established for the recorded artifacts; other Windows Server versions remain unqualified. Cross-compilation for Windows ARM64 proves compilation only, not an available AD DS host or native behavior.
- The native online clone-file discovery helper is undocumented in the sources examined. Validate all documented candidate locations, same-directory aliases, missing/removable/unreadable media, concurrent publication, and file preservation against a disposable reference DC before claiming parity.
- Online validation has not been compared on writable DC/RODC, missing GC, nested group membership, replication lag, modified DACLs, stale PDC locator results, denied LDAP attributes, partial SCM inventory, or absent/denied generation device. LDAP bind and group membership must be reported with their actual scope.
- The current source VM's generation support does not establish the eventual destination hypervisor's support. Microsoft describes boot-time comparison of current and saved generation identifiers; failure without a generation identifier can lead to DSRM. [Cloning architecture](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/virtualized-domain-controller-architecture).
- Explicit per-family network modes, strict literal validation, XML escaping, typed results, and atomic publication are reasonable SDK choices. Document differences from the inspected cmdlet instead of manufacturing permissive legacy behavior or claiming exact runtime equivalence.

This checkpoint is sufficient to implement schema-conforming serialization, explicit offline generation, and native online evidence gathering. It is not evidence that actual cloning or all reference failure cases have been qualified.
