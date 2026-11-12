# AD LDS fixtures for native TLS and partition tests

Research date: 2026-11-12. This is a provisioning design, not a record of completed deployment. Commands are skeletons for Windows PowerShell 5.1 inside the owned Server 2025 guests. They are outside the SDK runtime. Use the existing private-switch lab and PowerShell Direct described in [ad-lab-provisioning.md](ad-lab-provisioning.md); the hypervisor host's certificate stores are never targets. Native client contracts and certificate-failure tests are in [winldap-tls-lds.md](winldap-tls-lds.md).

## Decisions and evidence gaps

- Host both LDS instances on the existing owned member guest. Run the native SDK client on the existing owned DC2. Use the member's actual FQDN, unique instance names, and four unoccupied ports: LDAP/StartTLS `51300`, LDAPS `51301`; replica LDAP/StartTLS `51400`, LDAPS `51401`. These values are fixture policy, not reserved ports.
- A second replica in the same configuration set can have no default naming context while the first has one. The protocol defines `defaultNamingContext` using **that instance's** `nTDSDSA.msDS-DefaultNamingContext`; these are distinct DSA objects even though both are replicated in the shared configuration partition. Configure by each endpoint's `dsServiceName`, never by the first matching `nTDSDSA`. This is an inference directly from the per-DC contract, to be checked on both endpoints after replication. [MS-ADTS defaultNamingContext](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c1ad47fb-e4a1-4240-a749-b8f07ee0ae91), [nTDSDSA objects](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ebf2419-1169-4413-88e2-12a5ad499cf5).
- Use NetworkService, a single eligible leaf in each **service's** Personal store, and the test root only in the member and DC2 guest LocalMachine Root stores. This avoids certificate selection ambiguity and host trust changes. Microsoft documents the LDS service store and the service account's need for read access to the private key. [AD LDS certificate configuration](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc725767(v=ws.10)).
- The owned guest's installed Microsoft `adaminstall.exe` and `adamuninstall.exe`, version **10.0.26100.1**, resolve the answer-file and uninstall grammar below. The read-only capture is [setup-help.json](../../coverage/lab/server2025/lds/setup-help.json), fields `install`, `uninstall`, and `schema_files`; help returned codes 20074/20058 without timing out, which are observations about help invocation, not installation-success codes. Public documentation independently establishes the Unique answer-file entry point. [Current Microsoft setup example](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-ldap-connector-prepare-directory).

## Installer input and ownership

Inside the owned member guest, install `ADLDS` with management tools and verify the result and restart requirement. Record the OS build, `adaminstall.exe`/`adamuninstall.exe` file versions and SHA-256, installed answer-file sample, and command help in the run artifacts. Inspect `C:\Windows\ADAM` after feature installation; the legacy executable name remains ADAMInstall. The documented entry point is `ADAMInstall.exe /answer:<file>`. [Microsoft setup](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-ldap-connector-prepare-directory).

Use a run GUID and a dedicated guest directory such as `C:\ProgramData\ADSDKLab\LDS\<run-guid>`. Persist intended instance names, ports, paths, guest VM IDs and administrator SID before launching installers; record actual service and directory identities after creation. A marker alone does not establish ownership of an existing service. Reject an existing name, listening port, data directory, service certificate store, or directory marker unless the manifest and independently read identities agree. Reject newline/control characters in interpolated answer values. Use fixed validated instance names and actual `$AdminName = [Security.Principal.WindowsIdentity]::GetCurrent().Name`; assert the current name **and SID** identify the intended lab domain administrator before proceeding. Omit the answer-file `Administrator` key so setup follows its documented current-user branch; see the observed 20085 failure below.

The Unique skeleton, after substituting validated literal values, is:

```ini
[ADAMInstall]
InstallType=Unique
InstanceName=ADSDK11A
InstanceDescription=ADSDKLab:<run-guid>
ConfigurationSetLevel=10
LocalLDAPPortToListenOn=51300
LocalSSLPortToListenOn=51301
NewApplicationPartitionToCreate=CN=SDK11,DC=lab
DataFilesPath=C:\ProgramData\ADSDKLab\LDS\<run-guid>\A\data
LogFilesPath=C:\ProgramData\ADSDKLab\LDS\<run-guid>\A\logs
ImportLDIFFiles="MS-User.LDF"
```

Omit `ServiceAccount`, `ServicePassword`, and `AddPermissionsToServiceAccount`: the installed help explicitly defaults the account to NetworkService, requires a password only for another account, and defines AddPermissions as granting logon-as-service to a specified account. Read back `StartName` after installation. The installed help supports `InstanceDescription` and `ConfigurationSetLevel=7|10` for Unique; default 10 means Server 2025, 7 means Server 2016, and 8/9 are invalid. Explicit 10 makes this disposable 2025-only configuration set reproducible. The installed help misspells the optional import as `md-User.ldf`; the actual file inventory and Microsoft's public example both establish **MS-User.LDF**. [Installed help/inventory](../../coverage/lab/server2025/lds/setup-help.json), [NetworkService contract](https://learn.microsoft.com/en-us/windows/win32/services/networkservice-account).

The installed replica contract requires `SourceServer` and `SourceLDAPPort`. `ApplicationPartitionsToReplicate` selects application DNs (or `*` for all); select the exact owned partition. Omission of `SourceUserName`/`SourcePassword` explicitly uses the logged-on user's credentials, so no source password belongs in this answer file. Run it under the same verified domain administrator that owns A. The replica obtains schema from the configuration set; omit schema imports and `ConfigurationSetLevel`, which the help explicitly prohibits for replicas. Two `Unique` installations are **not** replicas. [Installed ADAMInstall help](../../coverage/lab/server2025/lds/setup-help.json).

```ini
[ADAMInstall]
InstallType=Replica
InstanceName=ADSDK11B
InstanceDescription=ADSDKLab:<run-guid>
LocalLDAPPortToListenOn=51400
LocalSSLPortToListenOn=51401
SourceServer=<member-FQDN>
SourceLDAPPort=51300
ApplicationPartitionsToReplicate="CN=SDK11,DC=lab"
DataFilesPath=C:\ProgramData\ADSDKLab\LDS\<run-guid>\B\data
LogFilesPath=C:\ProgramData\ADSDKLab\LDS\<run-guid>\B\logs
```

Do not put passwords in logs, the repository, process command lines or the public ownership manifest. These answer files contain no password, but keep them in the owned run directory and remove transient copies after verification.

Use a hidden child process with a bounded wait and an explicit absolute `/answer:` argument, then inspect its exit code, setup logs and actual service state. A timeout or disappeared remoting session is indeterminate: reconcile the recorded intent before retrying. A helper must not quietly replace a failed replica install with a Unique instance and claim replication coverage.

### Explicit Administrator and schema-import failure 20085

The owned 10.0.26100.1 run failed before service creation when a Unique answer contained `Administrator=ADSDK\Administrator` and `ImportLDIFFiles=MS-User.LDF`, but omitted `SourceUserName`/`SourcePassword`. The captured `adamsetup.log` first marks `SetCurrentUserADAMAdmin false` when the Administrator key is present. Account-name lookup then succeeds (`HRESULT=0`, `ADAMERR_OK`). Later, schema-import validation sees `IsCurrentUserADAMAdmin false` and `UseRemoteCreds false`, producing `ADAMERR_LDIF_USER_NOT_ENTERED` (20085). The captured service list is empty. This is evidence about setup's internal branch, **not** evidence that the Windows account lacks domain-administrator membership. [Owned installer observation](H:/ad-sdk-lab/lds-install-inspection-20085.json).

The narrow correction is to **omit Administrator**, keep `ImportLDIFFiles=MS-User.LDF`, and continue omitting source credentials, after verifying the installer process inherits the intended administrator token. Installed help explicitly grants administration to the current user when Administrator is omitted; the observed failure shows why explicitly spelling the same user is not equivalent for this import-validation branch. The corrected run passed on 2026-11-12: both instances expose the application partition, share one configuration naming context, and have distinct DSA names. Both initially omit a default naming context. This proves instance provisioning, not TLS or native-user qualification. No documented SID literal or special "current token" value was needed. [Installed Administrator default](../../coverage/lab/server2025/lds/setup-help.json), [successful instance evidence](../../coverage/lab/server2025/lds/instances.json), [retained failure](../../coverage/lab/server2025/lds/installer-20085.json).

### Password-free schema import after installation

If the current-user setup branch still cannot import, install A without `ImportLDIFFiles`, retain the verified administrator token, verify the owned service/RootDSE first, and import before seeding or creating B. Microsoft explicitly documents importing the installed `MS-User.LDF` afterward with LDIFDE, and says omission of `-b` uses the logged-on identity. Do not substitute the old documentation's `%windir%\AD LDS` directory for the observed 2025 `C:\Windows\ADAM` schema location. [Adding User Classes](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/adam/adding-user-classes).

Use LDAP with SASL encryption for this administrative schema operation; Microsoft's supported-Windows guidance documents `-h` for that protection. It is separate from the SDK's SIMPLE-over-TLS tests. The following skeleton uses no supplied password, `-a`, or `-b`; `$LdifdeExe` must be the absolute installed Microsoft executable path, and the existing helper must apply its bounded hidden-process execution wrapper. [LDIFDE SASL encryption](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/set-user-password-with-ldifde).

```powershell
$schemaFile = 'C:\Windows\ADAM\MS-User.LDF'
$schemaLogs = Join-Path $OwnedGuestRoot 'schema-import'
# Verify schemaFile hash against installed inventory and create the owned log dir.
& $LdifdeExe -i -f $schemaFile -s $MemberFqdn -t 51300 -h -k -j $schemaLogs `
    -c 'CN=Schema,CN=Configuration,DC=X' '#schemaNamingContext'
if ($LASTEXITCODE -ne 0) { throw "LDS schema import failed: $LASTEXITCODE" }
$schemaRoot = Get-ADRootDSE -Server ($MemberFqdn + ':51300')
Get-ADObject -Server ($MemberFqdn + ':51300') -SearchBase $schemaRoot.schemaNamingContext `
    -SearchScope OneLevel -LDAPFilter '(&(objectClass=classSchema)(lDAPDisplayName=user))' `
    -Properties lDAPDisplayName,subClassOf,objectClassCategory,mustContain,mayContain
```

The `-c` source DN is the literal placeholder from Microsoft's schema file, not the lab partition DN. Quote `'#schemaNamingContext'` in PowerShell: otherwise `#` starts a comment and LDIFDE receives only one replacement argument. An alternative is to pass the previously verified literal RootDSE schema DN as the second `-c` argument. The command above follows the Microsoft schema recipe's `-k`, but that option also suppresses constraint violations, missing objects and other errors; an exit code of zero alone does not establish a complete import. Review the retained import/error logs, reject unexpected errors, verify the intended class definition and required attributes against the installed file, and prove native-user creation/enable/bind before accepting the fixture. Do not blindly rerun a partially applied schema import. [LDIFDE replacement and error options](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731033(v=ws.11)), [PowerShell comment syntax](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comments?view=powershell-5.1).

Verify actual service identity before certificate import, restarts or removal:

```powershell
$ServiceName = 'ADAM_' + $InstanceName # validated letters/digits only
$svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($null -eq $svc) { throw 'Expected LDS service is absent' }
$svc | Select-Object Name, PathName, StartName, State, ProcessId
# Compare Name, PathName and StartName to the owned manifest/installed layout.
# Assert expected Microsoft AD LDS executable and instance argument, not just a prefix.
$listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
    Where-Object LocalPort -In @($LdapPort, $LdapsPort)
# Each listener must belong to this service's current ProcessId.
```

`Win32_Service` supplies the executable command line, service account and PID; PID is runtime evidence, not a durable ownership ID. Record `objectGUID` of the DSA, configuration partition and application partition, plus `dsServiceName`, `msDS-PortLDAP`, `msDS-PortSSL`, and `msDS-ServiceAccount`. The latter three are explicit AD LDS DSA attributes. [Win32_Service](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service), [DSA attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ebf2419-1169-4413-88e2-12a5ad499cf5).

## Test root and leaf preparation

Create certificates **in the member guest**. Use an owned administrative CurrentUser My staging store entry so the staging leaf does not become an eligible LocalMachine My fallback. Generate one root per run and one leaf per instance; record every staging thumbprint and imported machine key identity. The following is a proposed fixture recipe using documented certificate cmdlet parameters; its successful execution and presented certificate must be verified on the target build. It does not install a CA role or CRL server. `New-SelfSignedCertificate` is intended for testing; its `-Signer`, extensions, validity dates and explicit provider allow this controlled test chain. [New-SelfSignedCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2025-ps).

```powershell
# Inputs: $RunId, $MemberFqdn, $OwnedGuestRoot, $PfxPassword (SecureString).
$now = Get-Date
$rootArgs = @{
    Type = 'Custom'; Subject = "CN=AD SDK LDS test root $RunId"
    CertStoreLocation = 'Cert:\CurrentUser\My'
    Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
    KeyAlgorithm = 'RSA'; KeyLength = 3072; KeySpec = 'Signature'; HashAlgorithm = 'SHA256'
    KeyExportPolicy = 'NonExportable'; KeyUsage = @('CertSign', 'CRLSign')
    Extension = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
        $true, $true, 0, $true)
    NotBefore = $now.AddMinutes(-10); NotAfter = $now.AddDays(90)
}
$root = New-SelfSignedCertificate @rootArgs
$leafArgs = @{
    Type = 'Custom'; Subject = "CN=$MemberFqdn"; DnsName = @($MemberFqdn)
    CertStoreLocation = 'Cert:\CurrentUser\My'; Signer = $root
    Provider = 'Microsoft RSA SChannel Cryptographic Provider'
    KeyAlgorithm = 'RSA'; KeyLength = 2048; KeySpec = 'KeyExchange'
    HashAlgorithm = 'SHA256'; KeyExportPolicy = 'Exportable'
    KeyUsage = @('DigitalSignature', 'KeyEncipherment')
    TextExtension = @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')
    NotBefore = $now.AddMinutes(-5); NotAfter = $now.AddDays(30)
}
$leaf = New-SelfSignedCertificate @leafArgs
$rootCer = Join-Path $OwnedGuestRoot 'root.cer'
$leafPfx = Join-Path $OwnedGuestRoot ($InstanceName + '.pfx')
Export-Certificate -Cert $root -FilePath $rootCer -Type CERT | Out-Null
Export-PfxCertificate -Cert $leaf -FilePath $leafPfx -Password $PfxPassword `
    -ChainOption EndEntityCertOnly -NoClobber | Out-Null
```

The root provider explicitly supports RSA signing; its critical BasicConstraints marks a CA with no subordinate CA levels. The leaf uses the provider and exchange-key contract shown by Microsoft's LDAP certificate guidance. The certificate must have Server Authentication EKU, the actual server FQDN, and an accessible associated private key. Keep client private keys and unrelated machine certificates out of this fixture. `EndEntityCertOnly` prevents importing a PFX chain into unintended stores; use a separately exported public root. [RSA/AES provider](https://learn.microsoft.com/en-us/windows/win32/seccrypto/microsoft-aes-cryptographic-provider), [BasicConstraints constructor](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509basicconstraintsextension.-ctor?view=net-9.0), [LDAP certificate requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-certification-authority), [Export-PfxCertificate](https://learn.microsoft.com/en-us/powershell/module/pki/export-pfxcertificate?view=windowsserver2025-ps).

Copy only `root.cer` to DC2 using the owned PowerShell Direct session. On **each guest**, verify the file's SHA-256 and certificate thumbprint against the manifest, reject an unrelated pre-existing match, and import the one root:

```powershell
Import-Certificate -FilePath $rootCer -CertStoreLocation 'Cert:\LocalMachine\Root'
```

Record whether this run actually added the root on that guest; cleanup must remove only roots it added. The root private key remains on the member. Microsoft's LDS guide requires client trust; `Import-Certificate` explicitly supports LocalMachine Root. No host-side invocation of the import belongs in this workflow. [LDS client trust](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc725767(v=ws.10)), [Import-Certificate](https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2025-ps).

## Native service Personal store and machine private key

The PowerShell certificate provider exposes CurrentUser and LocalMachine locations; do not invent `Cert:\Service`. CryptoAPI documents `CERT_SYSTEM_STORE_SERVICES` and the name `ServiceName\My`, backed by `HKLM\Software\Microsoft\Cryptography\Services\ServiceName\SystemCertificates`. The correct service name is `ADAM_<instance>`. [Certificate provider](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-5.1), [system-store locations](https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations), [LDS store naming](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc725767(v=ws.10)).

A small provisioning-only C# helper can open the service store. The code below deliberately uses `CERT_STORE_ADD_NEW` rather than replacing an existing certificate. Creation is permitted only after service ownership was established; inspection/removal uses `OPEN_EXISTING` so a misspelled name cannot create a store. Numeric constants are the ABI values in [Microsoft Wincrypt.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/wincrypt.h). [CertOpenStore](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore), [CertAddCertificateContextToStore](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcertificatecontexttostore).

```csharp
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
public static class OwnedLdsStore {
    [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CertOpenStore(IntPtr provider, uint encoding,
        IntPtr cryptProvider, uint flags, string name);
    [DllImport("crypt32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CertCloseStore(IntPtr store, uint flags);
    [DllImport("crypt32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CertAddCertificateContextToStore(IntPtr store,
        IntPtr cert, uint disposition, IntPtr outputContext);
    public static X509Store Open(string service, bool create, bool readOnly) {
        if (!System.Text.RegularExpressions.Regex.IsMatch(service,
            @"\AADAM_[A-Za-z0-9]+\z")) throw new ArgumentException("service");
        uint flags = 0x00050000u; // CERT_SYSTEM_STORE_SERVICES
        if (!create) flags |= 0x00004000u; // OPEN_EXISTING
        if (readOnly) flags |= 0x00008000u; // READONLY
        IntPtr h = CertOpenStore(new IntPtr(10), 0, IntPtr.Zero,
            flags, service + @"\My"); // CERT_STORE_PROV_SYSTEM_W
        if (h == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return new X509Store(h); }
        finally { CertCloseStore(h, 0); }
    }
    public static void AddNew(X509Store store, X509Certificate2 cert) {
        bool ok = CertAddCertificateContextToStore(store.StoreHandle,
            cert.Handle, 1, IntPtr.Zero); // CERT_STORE_ADD_NEW
        int error = Marshal.GetLastWin32Error();
        GC.KeepAlive(cert); GC.KeepAlive(store);
        if (!ok) throw new Win32Exception(error);
    }
}
```

`X509Store(IntPtr)` duplicates the store handle in .NET Framework source, so closing the original handle is correct. Do **not** call `Open()` on the returned wrapper: that method opens a CurrentUser/LocalMachine store rather than preserving this service handle. Dispose each wrapper and enumerated certificate. The native add copies certificate properties except certain transient handle properties; passing null output avoids another owned certificate context. [Microsoft .NET Framework X509Store source](https://raw.githubusercontent.com/microsoft/referencesource/main/System/security/system/security/cryptography/x509/x509store.cs), [certificate-context copy contract](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcertificatecontexttostore).

Import the leaf-only PFX into a persisted machine key, derive its **exact** key file, grant read access, then add to the verified empty service store. `MachineKeySet` selects the computer key location; `PersistKeySet` keeps the key after the importing object is disposed. [X509KeyStorageFlags](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509keystorageflags).

```powershell
$flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
    [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
$machineLeaf = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $leafPfx, $PfxPassword, $flags)
if ($machineLeaf.Thumbprint -ne $leaf.Thumbprint -or !$machineLeaf.HasPrivateKey) {
    throw 'Wrong leaf or missing private key'
}
$rsa = $machineLeaf.PrivateKey # WinPS 5.1 / .NET Framework CSP metadata accessor
if ($rsa -isnot [Security.Cryptography.RSACryptoServiceProvider]) {
    throw 'Unexpected provider; do not guess the key location'
}
$info = $rsa.CspKeyContainerInfo
if (!$info.MachineKeyStore -or $info.ProviderName -ne 'Microsoft RSA SChannel Cryptographic Provider') {
    throw 'Unexpected key scope/provider'
}
$keyName = $info.UniqueKeyContainerName
if ([IO.Path]::GetFileName($keyName) -ne $keyName) { throw 'Invalid key filename' }
$keyPath = Join-Path (Join-Path $env:ProgramData 'Microsoft\Crypto\RSA\MachineKeys') $keyName
$keyFile = Get-Item -LiteralPath $keyPath -ErrorAction Stop
if ($keyFile.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected key reparse point' }
# Persist thumbprint, ProviderName, ProviderType, KeyContainerName,
# UniqueKeyContainerName, KeyNumber and keyPath in the owned manifest now.
$acl = Get-Acl -LiteralPath $keyPath
$networkServiceSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-20')
$rule = [Security.AccessControl.FileSystemAccessRule]::new(
    $networkServiceSid, [Security.AccessControl.FileSystemRights]::Read,
    [Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $keyPath -AclObject $acl
$store = [OwnedLdsStore]::Open($ServiceName, $true, $false)
try {
    $existing = $store.Certificates
    try {
        if ($existing.Count -ne 0) { throw 'Service store is not empty' }
    } finally { foreach ($certificate in $existing) { $certificate.Dispose() } }
    [OwnedLdsStore]::AddNew($store, $machineLeaf)
} finally { $store.Dispose(); $rsa.Dispose(); $machineLeaf.Dispose() }
```

For the explicit Microsoft software CSP, shared machine keys are under `ProgramData\Microsoft\Crypto\RSA\MachineKeys`; `UniqueKeyContainerName` selects the specific key. NetworkService's well-known SID is `S-1-5-20`. Do not grant permissions to every file, choose the newest GUID, or apply the ACL to the certificate registry blob instead of its private key. If switching to CNG later, implement and validate its distinct key-provider/path contract rather than reusing this CSP path. [Key storage locations](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval), [unique container name](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cspkeycontainerinfo.uniquekeycontainername), [NetworkService SID](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts).

The observed Server 2025 Framework extension accessor returned an `RSACng`
wrapper even though its provider was the requested Microsoft RSA SChannel CSP.
The legacy `PrivateKey` accessor returned `RSACryptoServiceProvider`, with the
same machine key's provider and unique container name. The provisioning script
uses that accessor and still requires the exact CSP, machine scope, key path,
and absence of reparse points before granting access. It does not treat an
arbitrary CNG key as a CSP key. The subsequent validating client observed the
expected leaf on both services using TLS 1.3 and AES-256.

Reopen the store read-only and verify exactly one certificate, expected thumbprint/SAN/EKU/dates, `HasPrivateKey`, and persisted machine key association. Restart only the verified owned service if needed to force reselection, then perform a validating TLS connection from DC2 and record the **presented** certificate thumbprint. Store contents alone are not proof of selection. Do not mix negative-test certificates into the positive instance store.

## Seed an enabled native LDS reader

Seed on instance A using the current Windows administrator, with a generated nonempty policy-compliant `$SeedPassword` SecureString held outside public artifacts. The current Microsoft LDS example uses `New-ADUser`, `Enable-ADAccount` and an imported `MS-User.LDF`; it grants Administrators for its connector, which is unnecessary for this SDK read fixture. Keep password complexity intact. [Microsoft LDS population example](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-ldap-connector-prepare-directory).

```powershell
$EndpointA = $MemberFqdn + ':51300'
$Partition = 'CN=SDK11,DC=lab'
$UsersDn = 'CN=SDKUsers,' + $Partition
$ReaderDn = 'CN=SDKReader,' + $UsersDn
$ReadersRole = 'CN=Readers,CN=Roles,' + $Partition
New-ADObject -Name SDKUsers -Type container -Path $Partition -Server $EndpointA `
    -OtherAttributes @{description = "ADSDKLab:$RunId"} -ErrorAction Stop
New-ADUser -Name SDKReader -Path $UsersDn -Server $EndpointA `
    -AccountPassword $SeedPassword -Description "ADSDKLab:$RunId" -ErrorAction Stop
Enable-ADAccount -Identity $ReaderDn -Partition $Partition -Server $EndpointA -ErrorAction Stop
$reader = Get-ADObject -Identity $ReaderDn -Partition $Partition -Server $EndpointA `
    -Properties objectGUID,'msDS-UserAccountDisabled',description
# Verify reader GUID/marker and msDS-UserAccountDisabled is explicitly FALSE.
Get-ADGroup -Identity $ReadersRole -Partition $Partition -Server $EndpointA
Add-ADGroupMember -Identity $ReadersRole -Members $ReaderDn -Partition $Partition `
    -Server $EndpointA -ErrorAction Stop
Get-ADGroup -Identity $ReadersRole -Partition $Partition -Server $EndpointA -Properties member
```

The skeleton assumes the installed application's default Readers role exists; verify its object and ACL before adding the owned user. Capture the application's ACL and prove the seeded DN can read the partition and fixture object through a validated SIMPLE TLS bind. This live permission result, not the role's English name, is the acceptance criterion. Use the full `$ReaderDn` as the LDAP bind name. Do not set a Windows domain or fabricate an sAMAccountName. Microsoft's New-ADUser page has a general sAMAccountName sentence but its LDS example and current LDS tutorial omit it; the LDS-specific recipe is the appropriate starting point. A failed password operation can leave a disabled object, so readback and authenticated bind are required. [New-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2025-ps), [explicit LDS partition for membership](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember?view=windowsserver2025-ps).

## Set the default on A; clear it on B

Use explicit configuration partitions for these mutations; application partition defaults cannot resolve the DSA object. `Set-ADObject` supports LDAP-named `-Replace` and `-Clear`. [Set-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adobject?view=windowsserver2025-ps).

```powershell
$EndpointB = $MemberFqdn + ':51400'
$a = Get-ADRootDSE -Server $EndpointA
$b = Get-ADRootDSE -Server $EndpointB
if ($a.dsServiceName -eq $b.dsServiceName) { throw 'Both endpoints reached the same DSA' }
if ($a.configurationNamingContext -ne $b.configurationNamingContext) {
    throw 'Instances are not in the same configuration set'
}
Set-ADObject -Identity $a.dsServiceName -Partition $a.configurationNamingContext `
    -Server $EndpointA -Replace @{'msDS-DefaultNamingContext' = $Partition}
$bDsa = Get-ADObject -Identity $b.dsServiceName -Partition $b.configurationNamingContext `
    -Server $EndpointB -Properties 'msDS-DefaultNamingContext'
if (@($bDsa.'msDS-DefaultNamingContext').Count -gt 0 -and $null -ne $bDsa.'msDS-DefaultNamingContext') {
    Set-ADObject -Identity $b.dsServiceName -Partition $b.configurationNamingContext `
        -Server $EndpointB -Clear 'msDS-DefaultNamingContext'
}
# Re-read both RootDSEs with fresh connections, then after replication convergence.
Get-ADRootDSE -Server $EndpointA | Select-Object dsServiceName,defaultNamingContext,namingContexts
Get-ADRootDSE -Server $EndpointB | Select-Object dsServiceName,defaultNamingContext,namingContexts
```

Acceptance requires A's default equal the fixture DN, B's **LDAP attribute absent**, both advertising the application partition, distinct DSA GUIDs, and the same application/reader GUIDs on both replicas. A PowerShell display of an empty field cannot distinguish an absent attribute from an empty presentation: use the SDK/native base RootDSE query for that assertion. Check bounded replication convergence rather than sleeping a fixed interval; record replica status and read the same marked object through each endpoint. `repadmin /showreps <host>:<LDAP-port>` is the instance-specific diagnostic documented by the Directory Services team. [Microsoft AD LDS replication/decommissioning](https://techcommunity.microsoft.com/blog/askds/how-to-decommission-an-adamadlds-server-and-add-additional-servers/397218).

## Cleanup and recovery boundaries

Teardown is a manifest-driven reverse operation. Recheck VM identity, local marker, exact service command line/account, DSA GUID, owned paths, certificate thumbprints and key-container identity before destructive work. Fail on drift or an unowned instance. Never use `sc delete`, registry deletion, broad service wildcard removal or forced replica deletion as a normal substitute for AD LDS uninstall.

1. Stop test clients/listeners and remove only recorded guest firewall-rule names. Preserve diagnostic artifacts without secrets.
2. While both replicas are available, gracefully uninstall B first using `C:\Windows\ADAM\adamuninstall.exe /q /i:ADSDK11B`; after successful readback, uninstall A using `/q /i:ADSDK11A`. The installed 10.0.26100.1 help defines `/q` as quiet and `/i:instanceName` as the exact removal target. **Omit `/force`**: the help says it ignores uninstall warnings. Run bounded hidden child processes and inspect exit codes and exact service/listener absence. If a warning blocks removal, preserve the instance and diagnose it; do not silently force. Confirm role ownership/replication state before removing a replica from any configuration set that is not wholly owned. [Installed ADAMUninstall help](../../coverage/lab/server2025/lds/setup-help.json).
3. Remove the owned leaf from each exact service store, if uninstall left it behind, and delete its machine key only after confirming no remaining owned instance uses it. If uninstall removed the store, do not recreate it merely to clean up. `X509Store.Remove` removes the certificate; it does not constitute private-key deletion. The wrapper uses OPEN_EXISTING for this step. [X509Store source](https://raw.githubusercontent.com/microsoft/referencesource/main/System/security/system/security/cryptography/x509/x509store.cs).
4. For each recorded software-CSP key, reopen with provider name/type, **KeyContainerName** (not UniqueKeyContainerName), recorded KeyNumber and `UseMachineKeyStore | UseExistingKey`; verify its UniqueKeyContainerName against the manifest, then set `PersistKeyInCsp=false` and call `Clear()`. `UseExistingKey` requests an existing key rather than creating one. Never delete arbitrary files from MachineKeys. [CspProviderFlags](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cspproviderflags?view=net-9.0), [PersistKeyInCsp deletion example](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider.persistkeyincsp).
5. Remove only run-added public roots on member/DC2 and owned staging certificates/private keys. Thumbprint syntax is hex only, so an exact provider `-Path` is safe. The certificate provider documents `-DeleteKey` for key deletion; do not use it for a staging certificate if it still shares a needed key. [Certificate-provider deletion](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-5.1).

```powershell
# Inside the exact guest, after ownership/thumbprint checks:
Remove-Item -Path ('Cert:\LocalMachine\Root\' + $OwnedRootThumbprint)
Remove-Item -Path ('Cert:\CurrentUser\My\' + $OwnedStagingLeafThumbprint) -DeleteKey
# Remove the staging root last, after all certificate generation is finished.
Remove-Item -Path ('Cert:\CurrentUser\My\' + $OwnedStagingRootThumbprint) -DeleteKey

# Exact persisted machine-CSP key, after all cert/service references are removed:
$cp = [Security.Cryptography.CspParameters]::new(
    $OwnedProviderType, $OwnedProviderName, $OwnedKeyContainerName)
$cp.KeyNumber = $OwnedKeyNumber
$cp.Flags = [Security.Cryptography.CspProviderFlags]::UseMachineKeyStore -bor
    [Security.Cryptography.CspProviderFlags]::UseExistingKey
$key = [Security.Cryptography.RSACryptoServiceProvider]::new($cp)
try {
    if ($key.CspKeyContainerInfo.UniqueKeyContainerName -ne $OwnedUniqueKeyName) {
        throw 'Key identity changed'
    }
    $key.PersistKeyInCsp = $false
} finally { $key.Clear() }
```

6. Remove owned PFX/answer files and residual data/log directories only after resolving absolute paths below the recorded guest run directory, rejecting reparse points and verifying uninstall completion. Do not uninstall the ADLDS feature if another instance exists or if the feature predates this fixture. Preserve a completed cleanup manifest and verify the intended root/leaf/key/service entries are absent. Rebuild failed disposable instances from recorded inputs; do not restore a running LDS replica snapshot as an ordinary reset, because LDS lacks VM-Generation-ID rollback protection. [AD LDS virtualization caveat](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831734(v=ws.11)).

For deterministic wrong-host, unknown-root and expired certificate tests, keep the positive LDS stores unchanged and use the controlled TLS peer described in the companion note. An expired certificate that LDS refuses to select does not prove the client rejects an expired certificate. Every negative case must record the certificate actually presented and prove no credentials were sent before TLS validation succeeded.
