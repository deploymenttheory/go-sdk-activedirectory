#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Specification)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$spec=$Specification | ConvertFrom-Json
$id=[guid]::ParseExact($spec.id,'D').ToString('D')
$root="C:\ad-sdk-lds\$id"
if($spec.member -ine $env:COMPUTERNAME -or $spec.server -ine "$env:COMPUTERNAME.ad.sdk.test" -or $spec.marker -cne "ad-sdk-lds:$id"){throw 'Unexpected LDS TLS fixture.'}
$suffix=$id.Replace('-','').Substring(0,8).ToUpperInvariant()
if($spec.primary -cne "ADSDKLDS-${suffix}-A" -or $spec.replica -cne "ADSDKLDS-${suffix}-B"){throw 'Unexpected LDS service names.'}
foreach($path in @('C:\ad-sdk-lds',$root)) {
    if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point in owned LDS directory.'}
}
$owned=Get-Content -LiteralPath (Join-Path $root 'ownership.json') -Raw | ConvertFrom-Json
if($owned.id -ne $id -or $owned.lab_id -ne $spec.lab_id -or $owned.marker -cne $spec.marker){throw 'LDS TLS ownership differs.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if($spec.administrator -ine 'ADSDK\Administrator' -or $identity.User -ne [Security.Principal.NTAccount]::new($spec.administrator).Translate([Security.Principal.SecurityIdentifier])){throw 'Unexpected certificate provisioning identity.'}
} finally {$identity.Dispose()}
foreach($name in @($spec.primary,$spec.replica)) {
    $service=Get-CimInstance Win32_Service -Filter "Name='ADAM_$name'"
    if(-not $service -or $service.Description -cne $spec.marker -or [Security.Principal.NTAccount]::new($service.StartName).Translate([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-20'){throw 'LDS service ownership or identity differs.'}
    $parameters=Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\ADAM_$name\Parameters"
    if(-not [IO.Path]::GetFullPath($parameters.'DSA Database file').StartsWith((Join-Path $root $name)+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'LDS service database is outside the fixture.'}
}
$statePath=Join-Path $root 'tls.json'
if(Test-Path -LiteralPath $statePath) {
    if((Get-Item -LiteralPath $statePath).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'TLS state is a reparse point.'}
    $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if($state.id -ne $id -or $state.lab_id -ne $spec.lab_id){throw 'TLS state ownership differs.'}
} else {
    $state=[pscustomobject][ordered]@{schema_version=1;id=$id;lab_id=$spec.lab_id;root_thumbprint='';leaf_thumbprint='';machine_store="ADSDK-LDS-$id";key=$null;phase='reserved'}
}
if($state.machine_store -cne "ADSDK-LDS-$id"){throw 'Unexpected machine certificate staging store.'}
function Save-TLSState {
    $temporary=Join-Path $root 'tls.tmp'
    if((Test-Path -LiteralPath $temporary) -and ((Get-Item -LiteralPath $temporary).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'TLS temporary state is a reparse point.'}
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $statePath -Force
}
Save-TLSState
if(-not ('ADSDKLdsCertificateStore' -as [type])) { Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
public static class ADSDKLdsCertificateStore {
    [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CertOpenStore(IntPtr provider, uint encoding, IntPtr cryptProvider, uint flags, string name);
    [DllImport("crypt32.dll", SetLastError=true)]
    private static extern bool CertCloseStore(IntPtr store, uint flags);
    [DllImport("crypt32.dll", SetLastError=true)]
    private static extern bool CertAddCertificateContextToStore(IntPtr store, IntPtr cert, uint disposition, IntPtr output);
    public static X509Store Open(string service) {
        IntPtr handle=CertOpenStore(new IntPtr(10),0,IntPtr.Zero,0x00050000,service+@"\My");
        if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return new X509Store(handle); } finally { CertCloseStore(handle,0); }
    }
    public static void AddNew(X509Store store, X509Certificate2 cert) {
        bool added=CertAddCertificateContextToStore(store.StoreHandle,cert.Handle,1,IntPtr.Zero);
        int error=Marshal.GetLastWin32Error();
        GC.KeepAlive(cert); GC.KeepAlive(store);
        if(!added) throw new Win32Exception(error);
    }
}
'@
}

function Get-StagedCertificate([string]$Thumbprint,[string]$FriendlyName,[string]$Subject) {
    $certificates=@(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.FriendlyName -ceq $FriendlyName -and $_.Subject -ceq $Subject})
    if($certificates.Count -gt 1){throw 'Ambiguous owned staging certificate.'}
    if($Thumbprint -and ($certificates.Count -ne 1 -or $certificates[0].Thumbprint -ne $Thumbprint)){throw 'Recorded staging certificate is absent or different.'}
    if($certificates.Count){
        if(-not $certificates[0].HasPrivateKey){throw 'Owned staging certificate has no private key.'}
        return $certificates[0]
    }
    return $null
}
$now=Get-Date
$caName="AD SDK LDS root $id"
$ca=Get-StagedCertificate $state.root_thumbprint $caName "CN=$caName"
if(-not $ca) {
    $ca=New-SelfSignedCertificate -Type Custom -Subject "CN=$caName" -FriendlyName $caName -CertStoreLocation Cert:\CurrentUser\My -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -KeyAlgorithm RSA -KeyLength 3072 -KeySpec Signature -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -KeyUsage CertSign,CRLSign -Extension ([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$true,0,$true)) -NotBefore $now.AddDays(-1) -NotAfter $now.AddDays(90)
}
$state.root_thumbprint=$ca.Thumbprint
Save-TLSState
$leafName="AD SDK LDS leaf $id"
$leaf=Get-StagedCertificate $state.leaf_thumbprint $leafName "CN=$($spec.server)"
if(-not $leaf) {
    $leaf=New-SelfSignedCertificate -Type Custom -Subject "CN=$($spec.server)" -DnsName $spec.server -FriendlyName $leafName -CertStoreLocation Cert:\CurrentUser\My -Signer $ca -Provider 'Microsoft RSA SChannel Cryptographic Provider' -KeyAlgorithm RSA -KeyLength 2048 -KeySpec KeyExchange -HashAlgorithm SHA256 -KeyExportPolicy Exportable -KeyUsage DigitalSignature,KeyEncipherment -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') -NotBefore $now.AddMinutes(-10) -NotAfter $now.AddDays(30)
}
$state.leaf_thumbprint=$leaf.Thumbprint
Save-TLSState
$machineStore=[Security.Cryptography.X509Certificates.X509Store]::new($state.machine_store,[Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$machineLeaf=$null
$rsa=$null
try {
    $machineStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $existing=$machineStore.Certificates
    if($existing.Count -gt 1 -or ($existing.Count -eq 1 -and $existing[0].Thumbprint -ne $leaf.Thumbprint)){throw 'Unexpected certificate in owned machine staging store.'}
    if($existing.Count -eq 1) {$machineLeaf=$existing[0]} else {
        $random=New-Object byte[] 32
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try {$rng.GetBytes($random);$password=[Convert]::ToBase64String($random)} finally {$rng.Dispose();[Array]::Clear($random,0,$random.Length)}
        $pfx=$null
        try {
            $pfx=$leaf.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,$password)
            $flags=[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
            $machineLeaf=[Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx,$password,$flags)
            $machineStore.Add($machineLeaf)
        } finally {if($pfx){[Array]::Clear($pfx,0,$pfx.Length)};$password=$null}
    }
    if($machineLeaf.Thumbprint -ne $state.leaf_thumbprint -or -not $machineLeaf.HasPrivateKey){throw 'Wrong machine leaf or missing private key.'}
    # Framework's extension accessor can wrap this legacy CSP in RSACng. The
    # legacy property exposes the verified CSP metadata needed for its key ACL.
    $rsa=$machineLeaf.PrivateKey
    if($rsa -isnot [Security.Cryptography.RSACryptoServiceProvider]){throw 'Unexpected private-key provider type.'}
    $info=$rsa.CspKeyContainerInfo
    if(-not $info.MachineKeyStore -or $info.ProviderName -ne 'Microsoft RSA SChannel Cryptographic Provider'){throw 'Unexpected machine key provider/scope.'}
    $keyName=$info.UniqueKeyContainerName
    if([IO.Path]::GetFileName($keyName) -ne $keyName){throw 'Invalid machine key filename.'}
    $keyPath=Join-Path (Join-Path $env:ProgramData 'Microsoft\Crypto\RSA\MachineKeys') $keyName
    $parent=$keyPath
    while($parent){if((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point in machine key path.'};$parent=[IO.Path]::GetDirectoryName($parent)}
    if($state.key -and $state.key.path -ne $keyPath){throw 'Recorded machine key changed.'}
    $state.key=[pscustomobject]@{path=$keyPath;provider=$info.ProviderName;container=$info.KeyContainerName;unique_name=$keyName;key_number=[int]$info.KeyNumber}
    Save-TLSState
    $acl=Get-Acl -LiteralPath $keyPath
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-20'),[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $keyPath -AclObject $acl
    foreach($name in @($spec.primary,$spec.replica)) {
        $store=[ADSDKLdsCertificateStore]::Open("ADAM_$name")
        try {
            $certificates=$store.Certificates
            try {
                if($certificates.Count -gt 1 -or ($certificates.Count -eq 1 -and $certificates[0].Thumbprint -ne $machineLeaf.Thumbprint)){throw 'Unexpected certificate in owned LDS service store.'}
                if($certificates.Count -eq 0){[ADSDKLdsCertificateStore]::AddNew($store,$machineLeaf)}
            } finally {foreach($certificate in $certificates){$certificate.Dispose()}}
            $certificates=$store.Certificates
            try {if($certificates.Count -ne 1 -or $certificates[0].Thumbprint -ne $machineLeaf.Thumbprint -or -not $certificates[0].HasPrivateKey){throw 'LDS service certificate association did not persist.'}} finally {foreach($certificate in $certificates){$certificate.Dispose()}}
        } finally {$store.Dispose()}
    }
    $trusted=[Security.Cryptography.X509Certificates.X509Store]::new('Root',[Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $publicRoot=[Security.Cryptography.X509Certificates.X509Certificate2]::new($ca.RawData)
    try {$trusted.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$trusted.Add($publicRoot)} finally {$trusted.Dispose();$publicRoot.Dispose()}
    foreach($name in @($spec.primary,$spec.replica)){Restart-Service -Name "ADAM_$name" -ErrorAction Stop}
    $ruleName="ADSDK-LDS-$id"
    $rules=@(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)
    if($rules.Count -eq 0){New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Description $spec.marker -Direction Inbound -Action Allow -Protocol TCP -LocalPort 51300,51301,51400,51401 -RemoteAddress 10.77.23.11 -Profile Any | Out-Null}
    else {
        $ports=$rules | Get-NetFirewallPortFilter
        $addresses=$rules | Get-NetFirewallAddressFilter
        if($rules.Count -ne 1 -or $rules[0].Description -cne $spec.marker -or $rules[0].Direction -ne 'Inbound' -or $rules[0].Action -ne 'Allow' -or $ports.Protocol -ne 'TCP' -or (@($ports.LocalPort) -join ',') -ne '51300,51301,51400,51401' -or (@($addresses.RemoteAddress) -join ',') -ne '10.77.23.11'){throw 'Existing LDS firewall rule differs.'}
    }
    $state.phase='service-certificates-installed'
    Save-TLSState
    [ordered]@{phase=$state.phase;id=$id;root_thumbprint=$ca.Thumbprint;root_certificate=[Convert]::ToBase64String($ca.RawData);leaf_thumbprint=$leaf.Thumbprint;leaf_subject=$leaf.Subject;leaf_not_before=$leaf.NotBefore.ToUniversalTime().ToString('o');leaf_not_after=$leaf.NotAfter.ToUniversalTime().ToString('o');key=$state.key;machine_store=$state.machine_store;time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 6
} finally {
    if($rsa){$rsa.Dispose()};if($machineLeaf){$machineLeaf.Dispose()};$machineStore.Dispose();$leaf.Dispose();$ca.Dispose()
}
