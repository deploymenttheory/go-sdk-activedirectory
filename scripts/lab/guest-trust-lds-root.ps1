#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Specification,[Parameter(Mandatory)][string]$TLSJSON)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$spec=$Specification | ConvertFrom-Json
$tls=$TLSJSON | ConvertFrom-Json
$id=[guid]::ParseExact($spec.id,'D').ToString('D')
if($spec.client -ine $env:COMPUTERNAME -or $spec.client -cne 'ADSDK25DC2' -or $tls.id -ne $id -or $spec.marker -cne "ad-sdk-lds:$id"){throw 'Unexpected LDS trust fixture/client.'}
$directory="C:\ad-sdk-lds\$id"
foreach($path in @('C:\ad-sdk-lds',$directory)) {
    if((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse point in client trust directory.'}
}
function Assert-LDSClientTrustPath([string]$Path,[string]$Root) {
    $resolved=[IO.Path]::GetFullPath($Path)
    $boundary=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    if(-not $resolved.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase)){throw 'Client trust state is outside its fixture.'}
    $ancestor=$resolved
    while($ancestor) {
        if((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse point in client trust state path.'}
        $ancestor=[IO.Path]::GetDirectoryName($ancestor)
    }
    return $resolved
}
function Read-LDSClientTrustState([string]$Path,[string]$Root) {
    $safe=Assert-LDSClientTrustPath $Path $Root
    return Get-Content -LiteralPath $safe -Raw | ConvertFrom-Json
}
function Write-LDSClientTrustState($State,[string]$Path,[string]$Root) {
    $safe=Assert-LDSClientTrustPath $Path $Root
    $State | ConvertTo-Json | Set-Content -LiteralPath $safe -Encoding UTF8
}
$statePath=Assert-LDSClientTrustPath (Join-Path $directory 'client-trust.json') $directory
if(Test-Path -LiteralPath $directory) {
    $state=Read-LDSClientTrustState $statePath $directory
    if($state.id -ne $id -or $state.lab_id -ne $spec.lab_id -or $state.root_thumbprint -ne $tls.root_thumbprint){throw 'Client trust ownership differs.'}
} else {
    $null=New-Item -ItemType Directory -Path $directory
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')) {$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl -LiteralPath $directory -AclObject $acl
    $state=[ordered]@{id=$id;lab_id=$spec.lab_id;root_thumbprint=$tls.root_thumbprint;phase='reserved'}
    Write-LDSClientTrustState $state $statePath $directory
}
$certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($tls.root_certificate))
$store=[Security.Cryptography.X509Certificates.X509Store]::new('Root',[Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
try {
    if($certificate.Thumbprint -ne $tls.root_thumbprint -or $certificate.Subject -cne "CN=AD SDK LDS root $id" -or $certificate.Issuer -cne $certificate.Subject -or $certificate.HasPrivateKey){throw 'Unexpected public LDS root certificate.'}
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($certificate)
} finally {$store.Dispose();$certificate.Dispose()}
$observations=@()
foreach($port in @($spec.ssl_port,$spec.replica_ssl_port)) {
    $tcp=[Net.Sockets.TcpClient]::new()
    $stream=$null
    $remote=$null
    try {
        $connect=$tcp.ConnectAsync($spec.server,[int]$port)
        if(-not $connect.Wait(15000)){throw 'LDS TLS socket connection timed out.'}
        # No validation callback: .NET performs chain and hostname validation.
        $stream=[Net.Security.SslStream]::new($tcp.GetStream(),$false)
        $authenticate=$stream.AuthenticateAsClientAsync($spec.server)
        if(-not $authenticate.Wait(15000)){throw 'LDS TLS handshake timed out.'}
        $remote=[Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)
        if($remote.Thumbprint -ne $tls.leaf_thumbprint -or -not $stream.IsAuthenticated -or -not $stream.IsEncrypted){throw 'LDS presented certificate or TLS protection differs.'}
        $observations += [ordered]@{server=$spec.server;port=$port;presented_thumbprint=$remote.Thumbprint;protocol=[string]$stream.SslProtocol;cipher=[string]$stream.CipherAlgorithm;cipher_strength=$stream.CipherStrength;validated=$true}
    } finally {if($remote){$remote.Dispose()};if($stream){$stream.Dispose()};$tcp.Dispose()}
}
$state.phase='tls-listeners-validated'
Write-LDSClientTrustState $state $statePath $directory
[ordered]@{phase=$state.phase;id=$id;client=$env:COMPUTERNAME;root_thumbprint=$tls.root_thumbprint;listeners=$observations;time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 6
