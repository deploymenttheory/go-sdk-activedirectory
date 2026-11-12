#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$ExpectedHash
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Credential test binary hash mismatch.' }
$root=Get-ADRootDSE -Server $Source
$domain=Get-ADDomain -Server $Source
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'Credential fixtures require the isolated lab domain.' }
$nonce=[guid]::NewGuid().ToString('N').Substring(0,16)
$ouName='ADSDK-Credential-'+$nonce
$ouDN="OU=$ouName,$($domain.DistinguishedName)"
$marker='ad-sdk-credential:'+$RunId
$username='sdk'+[char]0x00e9+$nonce.Substring(0,8)
$upn="$username@$($domain.DNSRoot)"
$password=ConvertTo-SecureString ('Aa9!'+[char]0x0101+[char]::ConvertFromUtf32(0x1f511)+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
$ordinary=[PSCredential]::new("$($domain.NetBIOSName)\$username",$password)
$creationAttempted=$false; $ouGuid=$null; $process=$null
$passwordBytes=$null; $wire=$null; $wireBytes=$null
$failure=$null; $clean=$false; $exitCode=$null; $output=@(); $rows=@(); $denied=$false; $denial=@(); $phase='create-fixtures'

function Get-CredentialError($Record) {
    # Do not retain exception messages, commands, or credential input.
    $items=@(); $pending=[Collections.Generic.Queue[Exception]]::new()
    $pending.Enqueue($Record.Exception)
    while ($pending.Count) {
        $exception=$pending.Dequeue()
        $code=$null
        if ($exception.PSObject.Properties['ErrorCode']) {$code=[int]$exception.ErrorCode}
        $items+=[ordered]@{type=$exception.GetType().FullName;hresult=$exception.HResult;code=$code}
        if ($exception -is [AggregateException]) {
            foreach ($inner in $exception.InnerExceptions) {$pending.Enqueue($inner)}
        } elseif ($exception.InnerException) {$pending.Enqueue($exception.InnerException)}
    }
    return $items
}

function Test-CredentialPermissionDenial($Details) {
    return @($Details | Where-Object {
        $_.code -in @(5,8344) -or ($_.hresult -band 0xffff) -in @(5,8344) -or
        $_.type -in @('System.UnauthorizedAccessException','Microsoft.ActiveDirectory.Management.ADUnauthorizedAccessException')
    }).Count -gt 0
}

function Remove-CredentialFixtures([string]$Server,[string]$DomainDN,[string]$OUName,[string]$GUID,[string]$Marker,[string[]]$ExpectedNames) {
    $ErrorActionPreference='Stop'
    $owned=@(Get-ADOrganizationalUnit -LDAPFilter "(ou=$OUName)" -SearchBase $DomainDN -SearchScope OneLevel -Properties Description -Server $Server)
    if ($owned.Count -eq 0) { return }
    if ($owned.Count -ne 1 -or $owned[0].Description -cne $Marker -or ($GUID -and $owned[0].ObjectGUID.ToString() -ne $GUID)) { throw 'Credential fixture OU ownership mismatch.' }
    $cleanupErrors=[Collections.Generic.List[Exception]]::new()
    foreach ($child in @(Get-ADObject -Filter * -SearchBase $owned[0].DistinguishedName -SearchScope OneLevel -Properties Description -Server $Server)) {
        try {
            if ($child.Description -cne $Marker -or $child.Name -cnotin $ExpectedNames -or $child.ObjectClass -notin @('user','container')) { throw 'Unexpected child in credential fixture OU; refusing removal.' }
            Remove-ADObject -Identity $child.ObjectGUID -Server $Server -Confirm:$false
        } catch { $cleanupErrors.Add($_.Exception) }
    }
    try {
        # Nonrecursive deletion refuses any unexpected or surviving child.
        Remove-ADOrganizationalUnit -Identity $owned[0].ObjectGUID -Server $Server -Confirm:$false
    } catch { $cleanupErrors.Add($_.Exception) }
    if ($cleanupErrors.Count) { throw [AggregateException]::new('Credential fixture cleanup failed.',$cleanupErrors.ToArray()) }
}

try {
    if (@(Get-ADOrganizationalUnit -LDAPFilter "(ou=$ouName)" -SearchBase $domain.DistinguishedName -SearchScope OneLevel -Server $Source).Count) { throw 'Credential fixture name already exists.' }
    $creationAttempted=$true
    $ou=New-ADOrganizationalUnit -Name $ouName -Path $domain.DistinguishedName -Description $marker -ProtectedFromAccidentalDeletion:$false -Server $Source -PassThru
    $ouGuid=$ou.ObjectGUID.ToString()
    $user=New-ADUser -Name $username -SamAccountName $username -UserPrincipalName $upn -Path $ouDN -Description $marker -AccountPassword $password -Enabled:$true -ChangePasswordAtLogon:$false -Server $Source -PassThru
    Sync-ADObject -Object $ou.ObjectGUID -Source $Source -Destination $Destination
    Sync-ADObject -Object $user.ObjectGUID -Source $Source -Destination $Destination
    $null=Get-ADUser -Identity $user.ObjectGUID -Server $Destination

    # Use a private pipe to the test process: no secret command argument,
    # environment variable, transcript, or credential file is created.
    $phase='native-tests'
    $passwordBytes=[Text.Encoding]::UTF8.GetBytes($ordinary.GetNetworkCredential().Password)
    $wire=[ordered]@{Server=$Source;Domain=$domain.NetBIOSName;Username=$username;UPN=$upn;OU=$ouDN;Marker=$marker;Password=[Convert]::ToBase64String($passwordBytes)} | ConvertTo-Json -Compress
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$Executable
    $start.Arguments='-test.v -test.count=1 -test.timeout=120s'
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $start.StandardOutputEncoding=[Text.Encoding]::UTF8; $start.StandardErrorEncoding=[Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_EXPLICIT_LAB']='1'
    $start.EnvironmentVariables['ADSDK_CREDENTIAL_RESULT']=$ResultPath
    $start.EnvironmentVariables.Remove('ADSDK_LDAP_SERVER')
    $start.EnvironmentVariables.Remove('ADSDK_LDAP_DENIED')
    $process=[Diagnostics.Process]::new(); $process.StartInfo=$start
    if (-not $process.Start()) { throw 'Credential test process did not start.' }
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    # Bypass .NET Framework's console-codepage StreamWriter so Unicode survives
    # even when the host's active Windows code page is not UTF-8.
    $wireBytes=[Text.Encoding]::UTF8.GetBytes($wire)
    $process.StandardInput.BaseStream.Write($wireBytes,0,$wireBytes.Length)
    $process.StandardInput.BaseStream.Flush(); $process.StandardInput.Close()
    [Array]::Clear($wireBytes,0,$wireBytes.Length); $wireBytes=$null
    $wire=$null
    if (-not $process.WaitForExit(150000)) { $process.Kill(); $process.WaitForExit(); throw 'Credential test process exceeded its deadline.' }
    $exitCode=$process.ExitCode
    $text=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
    if ($text.Contains($ordinary.GetNetworkCredential().Password) -or $text.Contains([Convert]::ToBase64String($passwordBytes))) { throw 'Credential material detected in native output; output suppressed.' }
    $output=@($text -split "`r?`n" | Where-Object {$_})
    if ($exitCode -ne 0) { throw 'Native explicit credential tests failed.' }
    $native=Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    if (-not $native.passed -or $native.reads.Count -ne 2) { throw 'Native credential result is incomplete.' }
    $phase='reference-comparison'
    foreach ($row in $native.reads) {
        $credential=if ($row.form -eq 'upn') {[PSCredential]::new($upn,$password)} else {$ordinary}
        $reference=Get-ADRootDSE -Server $Source -Credential $credential
        if ($reference.dnsHostName -ine $row.server -or $reference.defaultNamingContext -cne $row.default_naming_context) { throw 'Explicit RootDSE differs from PowerShell.' }
        $rows+=[ordered]@{form=$row.form;matched=$true;server=$row.server;default_naming_context=$row.default_naming_context}
    }
    # Same valid object type/attributes as the native authorization probe.
    $phase='reference-permission'
    $null=New-ADObject -Name ReferenceAllowed -Type container -Path $ouDN -OtherAttributes @{description=$marker} -Server $Source -PassThru
    $denied=$false; $denial=@()
    try {
        $null=New-ADObject -Name ReferenceDenied -Type container -Path $ouDN -OtherAttributes @{description=$marker} -Server $Source -Credential $ordinary -PassThru
    } catch {
        $denial=@(Get-CredentialError $_)
        $denied=Test-CredentialPermissionDenial $denial
    }
    if (-not $denied) { throw 'PowerShell did not deny the alternate identity create request.' }
} catch { $failure=[ordered]@{phase=$phase;operation=@(Get-CredentialError $_);cleanup=@()} }
finally {
    if ($process) {
        try { if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() } } catch {
            if (-not $failure) {$failure=[ordered]@{phase='process-cleanup';operation=@();cleanup=@()}}
            $failure.cleanup+=@(Get-CredentialError $_)
        }
        $process.Dispose()
    }
    $wire=$null
    if ($wireBytes) {[Array]::Clear($wireBytes,0,$wireBytes.Length)}
    if ($passwordBytes) {[Array]::Clear($passwordBytes,0,$passwordBytes.Length)}
    $cleanupErrors=@()
    if ($creationAttempted) {
        try { Remove-CredentialFixtures $Source $domain.DistinguishedName $ouName $ouGuid $marker @($username,'NativeAllowed','NativeDenied','ReferenceAllowed','ReferenceDenied') } catch {$cleanupErrors+=@(Get-CredentialError $_)}
    }
    try {
        $deadline=[DateTime]::UtcNow.AddMinutes(3)
        do {
            $remaining=@()
            foreach ($server in @($Source,$Destination)) {$remaining+=@(Get-ADObject -LDAPFilter "(description=$marker)" -SearchBase $domain.DistinguishedName -Server $server)}
            if ($remaining.Count -eq 0) {$clean=$true;break}
            Start-Sleep -Seconds 3
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not $clean) {throw 'Credential fixture cleanup was not confirmed on both DCs.'}
    } catch {$cleanupErrors+=@(Get-CredentialError $_)}
    if ($cleanupErrors.Count) {
        if (-not $failure) {$failure=[ordered]@{phase='fixture-cleanup';operation=@();cleanup=@()}}
        $failure.cleanup+=$cleanupErrors
    }
    $ordinary=$null; $password.Dispose()
}
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[ordered]@{
    schema_version=1;run=$RunId;time=[DateTime]::UtcNow.ToString('o');passed=($null -eq $failure -and $clean)
    error=$failure;exit_code=$exitCode;output=$output;comparisons=$rows;cleanup_on_both_controllers=$clean
    permission=[ordered]@{authenticated=($rows.Count -eq 2);denied=$denied;error=$denial}
    environment=[ordered]@{build="$($build.CurrentBuild).$($build.UBR)";architecture=$env:PROCESSOR_ARCHITECTURE;powershell=$PSVersionTable.PSVersion.ToString();ad_module=(Get-Module ActiveDirectory).Version.ToString();schema_version=(Get-ADObject -Identity $root.schemaNamingContext -Properties objectVersion -Server $Source).objectVersion;domain_mode=$domain.DomainMode.ToString();forest_mode=(Get-ADForest -Server $Source).ForestMode.ToString()}
    scope='Explicit Unicode domain-account and UPN Negotiate; post-wipe RootDSE; invalid/empty password and create permission denial; current-identity baseline; PowerShell differential; owned fixture cleanup.'
} | ConvertTo-Json -Depth 10
