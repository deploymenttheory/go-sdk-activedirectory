#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Specification,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$CaseSpecification,
    [Parameter(Mandatory)][PSCredential]$Reader,
    [Parameter(Mandatory)][string]$BinaryHash,
    [Parameter(Mandatory)][string]$PolicyHelperHash
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.DirectoryServices.Protocols
$spec=$Specification | ConvertFrom-Json
$case=$CaseSpecification | ConvertFrom-Json
$fixtureId=[guid]::ParseExact($spec.id,'D').ToString('D')
if($RunId -cnotmatch '^lds-tls-\d{8}T\d{6}Z-[a-f0-9]{8}$' -or $case.name -cnotmatch '^(valid|expired|wrong-host|untrusted)-(ldaps|starttls)$'){throw 'Unexpected TLS matrix case identity.'}
if($spec.phase -ne 'fixture-ready' -or $spec.client -ine $env:COMPUTERNAME -or $spec.client -cne 'ADSDK25DC2' -or $spec.server -ine 'ADSDK25MEM.ad.sdk.test' -or $spec.marker -cne "ad-sdk-lds:$fixtureId" -or $Reader.UserName -cne $spec.reader.dn -or $case.transport -cnotin @('ldaps','starttls') -or [int]$case.port -lt 1 -or [int]$case.port -gt 65535){throw 'Unexpected TLS matrix client or fixture.'}
$directory="C:\ad-sdk-lds\$fixtureId\tls-peers\$RunId"
$marker="ad-sdk-lds-tls:${fixtureId}:$RunId"
$binary=Join-Path $directory 'lds-tls.test.exe'
$policyHelper=Join-Path $directory 'lds-certificate-policy.ps1'
$resultPath=Join-Path $directory "$($case.name)-native.json"
foreach($path in @('C:\ad-sdk-lds',"C:\ad-sdk-lds\$fixtureId","C:\ad-sdk-lds\$fixtureId\tls-peers",$directory,$binary,$policyHelper,(Join-Path $directory 'ownership.json'))) {
    if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point in TLS reference path.'}
}
$owner=Get-Content -LiteralPath (Join-Path $directory 'ownership.json') -Raw | ConvertFrom-Json
if($owner.fixture_id -ne $fixtureId -or $owner.lab_id -ne $spec.lab_id -or $owner.run -cne $RunId -or $owner.marker -cne $marker -or $owner.role -ne 'client' -or $owner.native_sha256 -ne $BinaryHash -or (Get-FileHash -LiteralPath $binary).Hash -ne $BinaryHash -or (Test-Path -LiteralPath $resultPath)){throw 'TLS reference executable or artifact ownership differs.'}
if($PolicyHelperHash -notmatch '^[0-9a-f]{64}$' -or (Get-FileHash -LiteralPath $policyHelper).Hash -ne $PolicyHelperHash){throw 'TLS policy helper differs from its snapshot.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {if($identity.User.Value -ne $owner.owner_sid){throw 'TLS reference process identity differs.'}} finally {$identity.Dispose()}
. $policyHelper

function Get-TLSReferenceError($Record) {
    $exception=$Record.Exception
    while($exception) {
        $entry=[ordered]@{type=$exception.GetType().FullName;hresult=$exception.HResult;ldap_code=$null}
        if($exception -is [DirectoryServices.Protocols.LdapException]){$entry.ldap_code=$exception.ErrorCode}
        if($exception -is [DirectoryServices.Protocols.DirectoryOperationException] -and $exception.Response){$entry.ldap_code=[int]$exception.Response.ResultCode}
        [pscustomobject]$entry
        $exception=$exception.InnerException
    }
}
function Assert-TLSOutputSafe([string]$Text,[PSCredential]$Account,[byte[]]$PasswordBytes) {
    if($Text.Contains($Account.GetNetworkCredential().Password) -or $Text.Contains([Convert]::ToBase64String($PasswordBytes))){throw 'Credential material detected; output suppressed.'}
}

$process=$null;$passwordBytes=$null;$wireBytes=$null;$wire=$null
$native=$null;$nativeFailure=$null;$nativeExit=-1;$nativeOutput=@();$outputChecked=$false;$processStopped=$false
$connection=$null;$referenceErrors=@();$referenceFailure=$null
$reference=[ordered]@{passed=$false;stage='initialize';bind_succeeded=$false;partition_read=$false;partition=$null;instance_type=$null;errors=@()}
$capture=$null
$certificatePolicy=[ordered]@{passed=$false;logging_restored=$false;native=$null;reference=$null;errors=@()}
try {
    $capture=New-LDSCertificatePolicyCapture $owner.owner_sid
    Enable-LDSCertificatePolicyCapture $capture
    $nativeWindow=Start-LDSCertificatePolicyWindow
try {
    $passwordBytes=[Text.Encoding]::UTF8.GetBytes($Reader.GetNetworkCredential().Password)
    $wire=[ordered]@{Server=$spec.server;Port=[int]$case.port;Transport=$case.transport;Partition=$spec.partition;BindDN=$Reader.UserName;Password=[Convert]::ToBase64String($passwordBytes);Marker=$spec.marker;ExpectFailure=[bool]$case.expect_failure} | ConvertTo-Json -Compress
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$binary;$start.Arguments='-test.run ^TestADLDSTLSLab$ -test.v -test.timeout=100s'
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.StandardOutputEncoding=[Text.Encoding]::UTF8;$start.StandardErrorEncoding=[Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_LDS_TLS_LAB']='1';$start.EnvironmentVariables['ADSDK_LDS_TLS_RESULT']=$resultPath
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    if(-not $process.Start()){throw 'TLS native process did not start.'}
    $nativeWindow.RequestProcessID=$process.Id
    $nativeWindow.RequestProcessStartedUTC=$process.StartTime.ToUniversalTime().ToString('o')
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    $wireBytes=[Text.Encoding]::UTF8.GetBytes($wire)
    $process.StandardInput.BaseStream.Write($wireBytes,0,$wireBytes.Length);$process.StandardInput.BaseStream.Flush();$process.StandardInput.Close()
    [Array]::Clear($wireBytes,0,$wireBytes.Length);$wireBytes=$null;$wire=$null
    if(-not $process.WaitForExit(110000)){$process.Kill();$null=$process.WaitForExit(5000);throw 'TLS native process exceeded its deadline.'}
    $nativeExit=$process.ExitCode
    $outputText=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
    Assert-TLSOutputSafe $outputText $Reader $passwordBytes
    if($outputText.Length -gt 65536){throw 'TLS native output exceeded its bound.'}
    $nativeOutput=@($outputText -split "`r?`n" | Where-Object {$_})
    if(Test-Path -LiteralPath $resultPath) {
        if((Get-Item -LiteralPath $resultPath).Attributes -band [IO.FileAttributes]::ReparsePoint -or (Get-Item -LiteralPath $resultPath).Length -gt 65536){throw 'Unexpected TLS native artifact.'}
        $nativeText=Get-Content -LiteralPath $resultPath -Raw
        Assert-TLSOutputSafe $nativeText $Reader $passwordBytes
        $native=$nativeText | ConvertFrom-Json
    }
    $outputChecked=$true
    if($nativeExit -ne 0 -or -not $native -or -not $native.passed){throw 'TLS native case failed.'}
    if($native.server -ine $spec.server -or $native.port -ne $case.port -or $native.transport -cne $case.transport -or $native.expect_failure -ne $case.expect_failure -or $native.context_expired){throw 'TLS native observation differs from the requested case.'}
    if($case.expect_failure) {
        if($native.dial_succeeded -or -not $native.tls_negotiation_error){throw 'TLS native failure is not a TLS-stage rejection.'}
    } elseif(-not $native.dial_succeeded -or -not $native.partition_read -or ($native.instance_type -band 1) -eq 0){throw 'TLS native valid control did not bind/read.'}
} catch {$nativeFailure=[ordered]@{line=$_.InvocationInfo.ScriptLineNumber;errors=@(Get-TLSReferenceError $_)}}
finally {
    if($process) {
        try {if(-not $process.HasExited){$process.Kill();$null=$process.WaitForExit(5000)};$processStopped=$process.HasExited} catch {$nativeFailure=[ordered]@{phase='process-cleanup';errors=@(Get-TLSReferenceError $_)}} finally {$process.Dispose()}
    }
    if($wireBytes){[Array]::Clear($wireBytes,0,$wireBytes.Length)}
    if($passwordBytes){[Array]::Clear($passwordBytes,0,$passwordBytes.Length)}
    $wire=$null
}
try {$certificatePolicy.native=Complete-LDSCertificatePolicyWindow $capture $nativeWindow $case $spec.server}
catch {$certificatePolicy.errors+=@([ordered]@{phase='native-policy';errors=@(Get-TLSReferenceError $_)})}

# Always attempt the independent reference second, even if the SDK case failed,
# so two complete peer observations can explain a disagreement.
$referenceWindow=Start-LDSCertificatePolicyWindow
$referenceProcess=[Diagnostics.Process]::GetCurrentProcess()
try {$referenceWindow.RequestProcessID=$referenceProcess.Id;$referenceWindow.RequestProcessStartedUTC=$referenceProcess.StartTime.ToUniversalTime().ToString('o')}
finally {$referenceProcess.Dispose()}
try {
    $identifier=[DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($spec.server,[int]$case.port,$true,$false)
    $connection=[DirectoryServices.Protocols.LdapConnection]::new($identifier)
    $connection.AutoBind=$false
    $connection.Timeout=[TimeSpan]::FromSeconds(10)
    $connection.SessionOptions.ProtocolVersion=3
    $connection.SessionOptions.AutoReconnect=$false
    $connection.SessionOptions.ReferralChasing=[DirectoryServices.Protocols.ReferralChasingOptions]::None
    # Leave certificate validation callbacks unset. Both transports use the
    # Windows trust store and configured server hostname without bypasses.
    if($case.transport -eq 'ldaps'){$connection.SessionOptions.SecureSocketLayer=$true}else{$reference.stage='starttls';$connection.SessionOptions.StartTransportLayerSecurity($null)}
    $connection.AuthType=[DirectoryServices.Protocols.AuthType]::Basic
    $connection.Credential=$Reader.GetNetworkCredential()
    $reference.stage='bind';$connection.Bind();$reference.bind_succeeded=$true
    if($case.expect_failure){throw 'Reference unexpectedly bound through an invalid certificate.'}
    $reference.stage='partition'
    $request=[DirectoryServices.Protocols.SearchRequest]::new($spec.partition,'(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,[string[]]@('distinguishedName','instanceType'))
    $response=[DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
    if($response.Entries.Count -ne 1){throw 'Reference partition result count differs.'}
    $entry=$response.Entries[0]
    $reference.partition=[string]$entry.Attributes['distinguishedName'][0]
    $reference.instance_type=[int]$entry.Attributes['instanceType'][0]
    $reference.partition_read=($reference.partition -ne '' -and ($reference.instance_type -band 1) -ne 0)
    if(-not $reference.partition_read){throw 'Reference result is not a naming-context root.'}
    $reference.passed=$true
} catch {
    $referenceErrors=@(Get-TLSReferenceError $_)
    $reference.errors=$referenceErrors
    $nativeLDAP=@($referenceErrors | Where-Object {$null -ne $_.ldap_code})
    $reference.passed=([bool]$case.expect_failure -and -not $reference.bind_succeeded -and $reference.stage -in @('starttls','bind') -and $nativeLDAP.Count -gt 0 -and @($nativeLDAP | Where-Object ldap_code -eq 85).Count -eq 0)
    if(-not $reference.passed){$referenceFailure=[ordered]@{line=$_.InvocationInfo.ScriptLineNumber;errors=$referenceErrors}}
} finally {
    if($connection) {
        try {$connection.Dispose()}
        catch {$reference.passed=$false;$referenceFailure=[ordered]@{phase='connection-cleanup';errors=@(Get-TLSReferenceError $_)}}
    }
}
try {$certificatePolicy.reference=Complete-LDSCertificatePolicyWindow $capture $referenceWindow $case $spec.server}
catch {$certificatePolicy.errors+=@([ordered]@{phase='reference-policy';errors=@(Get-TLSReferenceError $_)})}
} catch {$certificatePolicy.errors+=@([ordered]@{phase='policy-capture';errors=@(Get-TLSReferenceError $_)})}
finally {
    if($capture) {
        try {$certificatePolicy.logging_restored=Restore-LDSCertificatePolicyCapture $capture}
        catch {$certificatePolicy.errors+=@([ordered]@{phase='policy-restore';errors=@(Get-TLSReferenceError $_)})}
    }
}
$certificatePolicy.passed=($certificatePolicy.logging_restored -and $certificatePolicy.errors.Count -eq 0 -and $null -ne $certificatePolicy.native -and $certificatePolicy.native.passed -and $null -ne $certificatePolicy.reference -and $certificatePolicy.reference.passed)
if(-not $case.expect_failure -and $native -and $native.partition_read -and $reference.partition_read) {
    if($native.partition -cne $reference.partition -or $native.instance_type -ne $reference.instance_type){$reference.passed=$false;$referenceFailure=[ordered]@{phase='partition-comparison';errors=@()}}
}
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$environment=[ordered]@{computer=$env:COMPUTERNAME;build="$($build.CurrentBuild).$($build.UBR)";architecture=$env:PROCESSOR_ARCHITECTURE;powershell=$PSVersionTable.PSVersion.ToString();dotnet=[Environment]::Version.ToString();ldap_assembly=[DirectoryServices.Protocols.LdapConnection].Assembly.GetName().Version.ToString();wldap32=(Get-Item "$env:windir\System32\wldap32.dll").VersionInfo.FileVersion;schannel=(Get-Item "$env:windir\System32\schannel.dll").VersionInfo.FileVersion}
[ordered]@{schema_version=1;case=$case.name;passed=($null -eq $nativeFailure -and $null -eq $referenceFailure -and $reference.passed -and $processStopped -and $outputChecked -and $certificatePolicy.passed);native=$native;native_exit_code=$nativeExit;native_error=$nativeFailure;native_output=$nativeOutput;output_secret_checked=$outputChecked;process_stopped=$processStopped;reference=$reference;reference_error=$referenceFailure;certificate_policy=$certificatePolicy;environment=$environment;time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 16
