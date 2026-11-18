#Requires -Version 7.0
<#
.SYNOPSIS
Collects fresh portable LDAP and public TLS evidence in one owned AD DS fixture.
.DESCRIPTION
Run on the Hyper-V host using approved direct access. All three Windows VMs in
one configured private profile must already be running. This script never
changes their power state or networking. The Linux helper must already be on
that same profile. Passwords travel only through process/SSH stdin, never shell
arguments, files or captured evidence. Public roots and binaries are copied with
SHA256 provenance. Only exact fresh markers/GUIDs authorize directory cleanup.
#>
[CmdletBinding()]
param(
    [ValidateSet('2016','2019','2022','2025')][string]$ServerVersion='2025',
    [Parameter(Mandatory)][string]$WindowsTests,
    [Parameter(Mandatory)][string]$LinuxTests,
    [Parameter(Mandatory)][string]$WindowsTlsClient,
    [Parameter(Mandatory)][string]$LinuxTlsClient,
    [Parameter(Mandatory)][string]$WindowsTlsPeer,
    [Parameter(Mandatory)][string]$SourceProvenance,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceRevision,
    [string]$LabRoot='H:\ad-sdk-lab',
    [string]$RunId=('sdk03-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')).ToLowerInvariant()
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V
if ($RunId -cnotmatch '\A[a-z0-9][a-z0-9-]{5,39}\z') {throw 'Invalid qualification identity.'}
$profileRoot=[IO.Path]::GetFullPath((Join-Path $LabRoot "server$ServerVersion"))
$profile=Get-Content -LiteralPath (Join-Path $profileRoot 'state.json') -Raw | ConvertFrom-Json
if (-not $profile.configured -or $profile.domain -cne 'ad.sdk.test') {throw 'Expected configured isolated AD DS profile.'}
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if ($switch.Name -cne $profile.switch_name -or $switch.SwitchType -ne 'Private' -or $switch.Notes -cne "ad-sdk-lab:$($profile.id)") {throw 'Private lab switch ownership mismatch.'}
$machines=@{}
foreach ($machine in @($profile.machines)) {
    $vm=Get-VM -Id ([guid]$machine.id)
    if ($vm.Name -cne $machine.name -or $vm.Notes -cne "ad-sdk-lab:$($profile.id)" -or $vm.State -ne 'Running') {throw 'Expected verified running owned Windows VMs.'}
    $nics=@(Get-VMNetworkAdapter -VM $vm)
    if ($nics.Count -ne 1 -or $nics[0].SwitchId.ToString() -cne $profile.switch_id) {throw 'Windows VM private switch mismatch.'}
    $machines[$machine.role]=$machine
}
foreach ($role in @('dc1','dc2','member')) {if (-not $machines.ContainsKey($role)) {throw 'Profile lacks a required machine.'}}
$linuxScript=Join-Path $PSScriptRoot 'portable-linux.ps1'
$linuxState=(& $linuxScript Status).manifest
if ($linuxState.server_version -cne $ServerVersion -or $linuxState.switch_id -cne $profile.switch_id) {throw 'Linux client must be on the selected private profile.'}
$capture=[IO.Path]::GetFullPath((Join-Path (Join-Path $LabRoot 'captures') $RunId))
$captureRoot=[IO.Path]::GetFullPath((Join-Path $LabRoot 'captures')).TrimEnd('\')+'\'
if (-not $capture.StartsWith($captureRoot,[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $capture)) {throw 'Evidence directory must be fresh and within captures.'}
$null=New-Item -ItemType Directory -Path $capture
$proof=Get-Content -LiteralPath $SourceProvenance -Raw | ConvertFrom-Json
if($proof.source_revision -cne $SourceRevision -or -not $proof.runtime_byte_identical -or $proof.go_version -cne 'go1.27.4'){throw 'Source provenance must prove this exact Go1.27.4 build revision.'}
Copy-Item -LiteralPath $SourceProvenance -Destination (Join-Path $capture 'source-provenance.json')
$inputs=[ordered]@{}
foreach ($entry in @(@('windows-tests',$WindowsTests),@('linux-tests',$LinuxTests),@('windows-tls',$WindowsTlsClient),@('linux-tls',$LinuxTlsClient),@('windows-peer',$WindowsTlsPeer))) {
    $file=Get-Item -LiteralPath $entry[1]
    if ($file.PSIsContainer -or $file.Length -gt 32MB) {throw 'Expected bounded compiled binaries.'}
    $inputs[$entry[0]]=@{source=$file.FullName;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$manifest=[ordered]@{schema_version=1;run_id=$RunId;source_revision=$SourceRevision;sdk_base_revision=$proof.sdk_base_revision;runtime_byte_identical=$proof.runtime_byte_identical;source_provenance_sha256=(Get-FileHash -LiteralPath $SourceProvenance -Algorithm SHA256).Hash.ToLowerInvariant();server_version=$ServerVersion;profile_id=$profile.id;started_utc=[DateTime]::UtcNow.ToString('o');binaries=$inputs;passed=$false;cleanup_verified=$false}
$dc=$machines.dc1;$member=$machines.member
$saved=Import-Clixml -LiteralPath (Join-Path $profileRoot 'credential.clixml')
$credential=[PSCredential]::new("$($profile.netbios)\Administrator",$saved.Password)
$dcSession=$null;$memberSession=$null;$directoryFixture=$null;$tlsPrepared=$false
$guestCode="C:\adsdk-qualification\$RunId"
$server="$($dc.name).$($profile.domain)".ToLowerInvariant()
$fixtureSource=Join-Path $PSScriptRoot 'portable-tls-fixture.ps1'
$directorySource=Join-Path $PSScriptRoot 'portable-directory-fixture.ps1'
$negativeSource=Join-Path $PSScriptRoot 'portable-tls-negative-fixture.ps1'
function Save-PortableQualificationJson($Value,[string]$Name) {
    [IO.File]::WriteAllText((Join-Path $capture $Name),($Value|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
}
function Invoke-PortableWindowsProcess([string]$Binary,[string]$Arguments,[byte[]]$InputBytes) {
    Invoke-Command -Session $memberSession -ArgumentList $Binary,$Arguments,$InputBytes -ScriptBlock {
        param($binary,$arguments,[byte[]]$inputBytes)
        $info=[Diagnostics.ProcessStartInfo]::new()
        $info.FileName=$binary;$info.Arguments=$arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $info.EnvironmentVariables['ADSDK_PORTABLE_LAB_INPUT']='stdin'
        $process=[Diagnostics.Process]::new();$process.StartInfo=$info
        try {
            $null=$process.Start()
            $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
            $process.StandardInput.BaseStream.Write($inputBytes,0,$inputBytes.Length);$process.StandardInput.Close()
            if (-not $process.WaitForExit(180000)) {$process.Kill();throw 'Owned qualification client timed out.'}
            return [pscustomobject]@{exit_code=$process.ExitCode;stdout=$stdout.GetAwaiter().GetResult();stderr=$stderr.GetAwaiter().GetResult()}
        } finally {$process.Dispose();if($inputBytes){[Array]::Clear($inputBytes,0,$inputBytes.Length)}}
    }
}
try {
    $dcSession=New-PSSession -VMId ([guid]$dc.id) -Credential $credential
    $memberSession=New-PSSession -VMId ([guid]$member.id) -Credential $credential
    foreach ($session in @($dcSession,$memberSession)) {
        Invoke-Command -Session $session -ArgumentList $guestCode -ScriptBlock {
            param($directory)
            if(Test-Path -LiteralPath $directory){throw 'Guest fixture path must be fresh.'}
            $parent=[IO.Path]::GetDirectoryName($directory)
            while($parent){
                if((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Guest qualification path cannot cross a reparse point.'}
                $parent=[IO.Path]::GetDirectoryName($parent)
            }
            $null=New-Item -ItemType Directory -Path $directory
            $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
            foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
                $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $directory -AclObject $acl
        }
    }
    Copy-Item -LiteralPath $fixtureSource -Destination "$guestCode\portable-tls-fixture.ps1" -ToSession $dcSession
    Copy-Item -LiteralPath $directorySource -Destination "$guestCode\portable-directory-fixture.ps1" -ToSession $dcSession
    $prepared=Invoke-Command -Session $dcSession -ArgumentList $guestCode,$RunId,$server -ScriptBlock {
        param($code,$run,$server)
        . "$code\portable-tls-fixture.ps1"
        . "$code\portable-directory-fixture.ps1"
        $tls=New-PortableTlsFixture $run $server ('server'+$using:ServerVersion)
        $directory=New-PortableDirectoryFixture $run $server
        return [pscustomobject]@{tls=$tls;directory=$directory}
    }
    $tlsPrepared=$true;$directoryFixture=$prepared.directory
    Save-PortableQualificationJson $prepared 'prepare.json'
    foreach ($file in @('root.pem','root.cer','leaf.cer')) {Copy-Item -LiteralPath "C:\adsdk-portable-tls\$RunId\$file" -Destination (Join-Path $capture $file) -FromSession $dcSession}
    Copy-Item -LiteralPath (Join-Path $capture 'root.pem') -Destination "$guestCode\root.pem" -ToSession $memberSession
    Copy-Item -LiteralPath $WindowsTests -Destination "$guestCode\portable-tests.exe" -ToSession $memberSession
    Copy-Item -LiteralPath $WindowsTlsClient -Destination "$guestCode\portable-tls-client.exe" -ToSession $memberSession
    Copy-Item -LiteralPath $WindowsTlsPeer -Destination "$guestCode\tls-peer.exe" -ToSession $memberSession
    Copy-Item -LiteralPath $negativeSource -Destination "$guestCode\portable-tls-negative-fixture.ps1" -ToSession $memberSession
    $negativePrepared=Invoke-Command -Session $memberSession -ArgumentList $guestCode,$RunId,"$($member.name).$($profile.domain)" -ScriptBlock {
        param($code,$run,$member)
        . "$code\portable-tls-negative-fixture.ps1"
        New-PortableTlsNegativeFixture $run $code $member.ToLowerInvariant()
    }
    Save-PortableQualificationJson $negativePrepared 'negative-prepare.json'
    Copy-Item -LiteralPath "$guestCode\peer\trusted-root.pem" -Destination (Join-Path $capture 'peer-root.pem') -FromSession $memberSession
    Copy-Item -LiteralPath "$guestCode\peer\manifest.json" -Destination (Join-Path $capture 'peer-certificates.json') -FromSession $memberSession
    $remotePeerRoot=& $linuxScript Upload -LocalFile (Join-Path $capture 'peer-root.pem') -RemoteName "$RunId-peer-root.pem"
    $windowsCopies=Invoke-Command -Session $memberSession -ArgumentList $guestCode -ScriptBlock {
        param($code)
        $result=@{}
        foreach($name in @('portable-tests.exe','portable-tls-client.exe','tls-peer.exe','root.pem')){$result[$name]=(Get-FileHash -LiteralPath "$code\$name" -Algorithm SHA256).Hash.ToLowerInvariant()}
        return $result
    }
    if($windowsCopies['portable-tests.exe'] -cne $inputs['windows-tests'].sha256 -or $windowsCopies['portable-tls-client.exe'] -cne $inputs['windows-tls'].sha256 -or $windowsCopies['tls-peer.exe'] -cne $inputs['windows-peer'].sha256 -or $windowsCopies['root.pem'] -cne (Get-FileHash -LiteralPath (Join-Path $capture 'root.pem') -Algorithm SHA256).Hash.ToLowerInvariant()){throw 'Windows copy digest verification failed.'}
    Save-PortableQualificationJson $windowsCopies 'windows-copy-digests.json'
    $remoteTests=& $linuxScript Upload -LocalFile $LinuxTests -RemoteName "$RunId-tests"
    $remoteTls=& $linuxScript Upload -LocalFile $LinuxTlsClient -RemoteName "$RunId-tls"
    $remoteRoot=& $linuxScript Upload -LocalFile (Join-Path $capture 'root.pem') -RemoteName "$RunId-root.pem"
    $password=[Text.Encoding]::UTF8.GetBytes($credential.GetNetworkCredential().Password)
    try {
        foreach ($platform in @('windows','linux')) {
            foreach ($transport in @('ldaps','starttls')) {
                $port=if($transport -eq 'ldaps'){636}else{389}
                $base=@{run_id=$RunId;source_revision=$SourceRevision;username="Administrator@$($profile.domain)";password_base64=[Convert]::ToBase64String($password);transport=$transport}
                $rootPath=if($platform -eq 'windows'){"$guestCode\root.pem"}else{$remoteRoot.path}
                $tlsInput=$base.Clone();$tlsInput.endpoint=$server;$tlsInput.port=$port;$tlsInput.ca_file=$rootPath;$tlsInput.expect='valid'
                $tlsBytes=[Text.Encoding]::UTF8.GetBytes(($tlsInput|ConvertTo-Json -Compress))
                try {
                    if($platform -eq 'windows'){$result=Invoke-PortableWindowsProcess "$guestCode\portable-tls-client.exe" '' $tlsBytes}
                    else{$result=& $linuxScript Exec -Command $remoteTls.path -InputBytes $tlsBytes}
                } finally {[Array]::Clear($tlsBytes,0,$tlsBytes.Length);$tlsInput=$null}
                Save-PortableQualificationJson $result "$platform-$transport-public-process.json"
                if($result.exit_code -ne 0){throw "Public TLS qualification failed for $platform/$transport."}
                $public=$result.stdout|ConvertFrom-Json
                if(-not $public.passed -or $public.go_version -cne 'go1.27.4' -or $public.platform -cne "$platform/amd64"){throw 'Public TLS result identity or protection did not match.'}
                Save-PortableQualificationJson $public "$platform-$transport-public.json"
                $labInput=$base.Clone();$labInput.endpoint="$($server):$port";$labInput.ca_file=$rootPath;$labInput.allow_write=$true;$labInput.fixture_ou=$directoryFixture.dn
                $labInput.result=if($platform -eq 'windows'){"$guestCode\$transport-result.json"}else{"/home/adsdk/acceptance/$RunId-$transport-result.json"}
                $labBytes=[Text.Encoding]::UTF8.GetBytes(($labInput|ConvertTo-Json -Compress))
                try {
                    if($platform -eq 'windows'){$result=Invoke-PortableWindowsProcess "$guestCode\portable-tests.exe" '-test.run=^TestPortableLDAPLab$ -test.v' $labBytes}
                    else{$result=& $linuxScript Exec -Command "ADSDK_PORTABLE_LAB_INPUT=stdin $($remoteTests.path) -test.run='^TestPortableLDAPLab$' -test.v" -InputBytes $labBytes}
                } finally {[Array]::Clear($labBytes,0,$labBytes.Length);$labInput=$null;$base=$null}
                Save-PortableQualificationJson $result "$platform-$transport-sdk-process.json"
                if($result.exit_code -ne 0){throw "Portable LDAP qualification failed for $platform/$transport."}
                if($platform -eq 'windows'){
                    Copy-Item -LiteralPath "$guestCode\$transport-result.json" -Destination (Join-Path $capture "$platform-$transport-sdk.json") -FromSession $memberSession
                } else {
                    $read=& $linuxScript Exec -Command "cat /home/adsdk/acceptance/$RunId-$transport-result.json"
                    if($read.exit_code -ne 0){throw 'Linux SDK evidence read failed.'}
                    [IO.File]::WriteAllText((Join-Path $capture "$platform-$transport-sdk.json"),$read.stdout,[Text.UTF8Encoding]::new($false))
                }
                $sdk=Get-Content -LiteralPath (Join-Path $capture "$platform-$transport-sdk.json") -Raw | ConvertFrom-Json
                if(-not $sdk.passed -or $sdk.go_version -cne 'go1.27.4' -or $sdk.platform -cne "$platform/amd64" -or $sdk.source_revision -cne $SourceRevision){throw 'SDK evidence identity or result did not match.'}
            }
        }
        foreach($platform in @('windows','linux')){
            foreach($transport in @('ldaps','starttls')){
                $cases=@('valid','expired','wrong-host','untrusted')
                if($transport -eq 'starttls'){$cases+='refusal'}
                foreach($case in $cases){
                    $label="$platform-$transport-$case"
                    $peer=Invoke-Command -Session $memberSession -ArgumentList $guestCode,$RunId,$case,$transport,$label,$server -ScriptBlock {
                        param($code,$run,$case,$mode,$label,$server)
                        . "$code\portable-tls-negative-fixture.ps1"
                        Start-PortableTlsNegativePeer $run $code $case $mode $label $server
                    }
                    Save-PortableQualificationJson $peer "$label-peer-ready.json"
                    $port=[int]($peer.address -split ':')[-1]
                    $request=@{run_id=$RunId;source_revision=$SourceRevision;endpoint=$negativePrepared.member;port=$port;transport=$transport;username="Administrator@$($profile.domain)";password_base64=[Convert]::ToBase64String($password);expect=if($case -eq 'valid'){'valid'}else{'reject'};ca_file=if($platform -eq 'windows'){"$guestCode\peer\trusted-root.pem"}else{$remotePeerRoot.path}}
                    $bytes=[Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Compress))
                    try{
                        if($platform -eq 'windows'){$result=Invoke-PortableWindowsProcess "$guestCode\portable-tls-client.exe" '' $bytes}
                        else{$result=& $linuxScript Exec -Command $remoteTls.path -InputBytes $bytes}
                    } finally {[Array]::Clear($bytes,0,$bytes.Length);$request=$null}
                    Save-PortableQualificationJson $result "$label-process.json"
                    $observed=Invoke-Command -Session $memberSession -ArgumentList $guestCode,$RunId,$peer -ScriptBlock {
                        param($code,$run,$peer)
                        . "$code\portable-tls-negative-fixture.ps1"
                        Get-PortableTlsNegativePeerResult $peer $run $code
                    }
                    Save-PortableQualificationJson $observed "$label-peer.json"
                    if($result.exit_code -ne 0){throw "Controlled TLS qualification failed for $label."}
                    $client=$result.stdout|ConvertFrom-Json
                    if(-not $client.passed -or $client.go_version -cne 'go1.27.4' -or $client.platform -cne "$platform/amd64"){throw 'Controlled client result identity mismatch.'}
                    if(@($observed.connections).Count -ne 1 -or $observed.outcome -cne 'connection_limit'){throw 'Controlled peer did not observe exactly one connection.'}
                    $connection=$observed.connections[0]
                    if($case -eq 'valid'){
                        if(-not $connection.handshake_complete -or -not $connection.upstream_handshake_complete -or $connection.bind_requests -ne 1 -or $connection.ldap_bytes_forwarded -le 0){throw 'Controlled private-CA positive did not reach the verified real AD DS upstream.'}
                    } else {
                        if($connection.handshake_complete -or $connection.upstream_handshake_complete -or $connection.bind_requests -ne 0 -or $connection.plaintext_bind_requests -ne 0 -or $connection.ldap_bytes_received -ne 0 -or $connection.ldap_bytes_forwarded -ne 0){throw 'Failed TLS protection allowed LDAP credentials or operations.'}
                        if($case -eq 'refusal' -and (-not $connection.starttls_refused -or -not $connection.post_refusal_eof -or $connection.post_refusal_bytes -ne 0)){throw 'StartTLS refusal did not observe closed client with zero subsequent bytes.'}
                    }
                }
            }
        }
    } finally {[Array]::Clear($password,0,$password.Length);$password=$null}
    $manifest.passed=$true
} finally {
    try {
        $negativeCleanup=$null
        if($memberSession){
            try {
            $negativeCleanup=Invoke-Command -Session $memberSession -ArgumentList $guestCode,$RunId -ScriptBlock {
                param($code,$run)
                if(Test-Path -LiteralPath "$code\portable-tls-negative-fixture.ps1"){
                    . "$code\portable-tls-negative-fixture.ps1"
                    Remove-PortableTlsNegativeFixture $run $code
                }
            }
            } catch {$negativeCleanup=[pscustomobject]@{verified=$false;failure_type=$_.Exception.GetType().FullName}}
            Save-PortableQualificationJson $negativeCleanup 'negative-cleanup.json'
        }
        if($dcSession){
            # Recover fresh marker-owned state even if preparation or a client failed.
            $cleanup=Invoke-Command -Session $dcSession -ArgumentList $guestCode,$RunId,$server,$directoryFixture -ScriptBlock {
                param($code,$run,$server,$directory)
                . "$code\portable-tls-fixture.ps1"
                . "$code\portable-directory-fixture.ps1"
                $directoryCleanup=$null;$tlsCleanup=$null;$failures=@()
                try {
                    $guid=if($directory){$directory.guid}else{''}
                    $directoryCleanup=Remove-PortableDirectoryFixture $run $server $guid
                } catch {$failures+='directory-cleanup-failed:'+ $_.Exception.GetType().Name}
                finally {
                    try {
                        if(Test-Path -LiteralPath "C:\adsdk-portable-tls\$run\fixture.json"){$tlsCleanup=Remove-PortableTlsFixture $run $server}
                    } catch {$failures+='tls-cleanup-failed:'+ $_.Exception.GetType().Name}
                }
                return [pscustomobject]@{directory=$directoryCleanup;tls=$tlsCleanup;failures=$failures}
            }
            Save-PortableQualificationJson $cleanup 'cleanup.json'
            $manifest.cleanup_verified=($cleanup.tls -and $cleanup.directory -and $cleanup.tls.cleanup.verified -and $cleanup.directory.verified -and @($cleanup.failures).Count -eq 0 -and $negativeCleanup -and $negativeCleanup.verified)
        }
    } finally {
        $manifest.passed=($manifest.passed -and $manifest.cleanup_verified)
        $manifest.finished_utc=[DateTime]::UtcNow.ToString('o')
        Save-PortableQualificationJson $manifest 'manifest.json'
        foreach($session in @($memberSession,$dcSession)){if($session){Remove-PSSession $session}}
    }
}
if(-not $manifest.cleanup_verified){throw 'Independent qualification fixture cleanup was not verified.'}
[pscustomobject]@{run_id=$RunId;capture=$capture;passed=$manifest.passed;cleanup_verified=$manifest.cleanup_verified}
