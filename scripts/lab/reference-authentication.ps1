#Requires -Version 5.1
# Creates one ordinary-user fixture in the owned disposable lab domain, runs the
# authentication-and-permissions qualification against it, and removes it again.
#
# This script mutates the directory, so it is gated behind -AllowWrites. It
# creates exactly one organizational unit and one user, both carrying the run's
# marker, and both inside the lab domain. The secret reaches the test process
# only through a private pipe: no command argument, environment variable,
# transcript, or credential file is created.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$ExpectedHash,
    [switch]$AllowWrites
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
if (-not $AllowWrites) { throw 'Refusing to create a credential fixture without -AllowWrites.' }
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Authentication test binary hash mismatch.' }
$domain = Get-ADDomain -Server $Source
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'Authentication fixtures require the isolated lab domain.' }

$nonce = [guid]::NewGuid().ToString('N').Substring(0, 16)
$ouName = 'ADSDK-Auth-' + $nonce
$ouDN = "OU=$ouName,$($domain.DistinguishedName)"
$marker = 'ad-sdk-auth:' + $RunId
# Non-ASCII account name and a password with non-ASCII and supplementary
# Unicode, so the native identity path is exercised rather than assumed.
$username = 'sdk' + [char]0x00e9 + $nonce.Substring(0, 8)
$upn = "$username@$($domain.DNSRoot)"
$secret = 'Aa9!' + [char]0x0101 + [char]::ConvertFromUtf32(0x1f511) + [guid]::NewGuid().ToString('N')
$password = ConvertTo-SecureString $secret -AsPlainText -Force

$creationAttempted = $false; $process = $null; $wireBytes = $null
$failure = $null; $removed = $false; $exitCode = $null; $output = @(); $phase = 'create-fixture'

function Get-AuthError($Record) {
    # Types and codes only. Exception messages can quote input.
    $items = @(); $pending = [Collections.Generic.Queue[Exception]]::new()
    $pending.Enqueue($Record.Exception)
    while ($pending.Count) {
        $exception = $pending.Dequeue()
        $code = $null
        if ($exception.PSObject.Properties['ErrorCode']) { $code = [int]$exception.ErrorCode }
        $items += [ordered]@{ type = $exception.GetType().FullName; hresult = $exception.HResult; code = $code }
        if ($exception -is [AggregateException]) {
            foreach ($inner in $exception.InnerExceptions) { $pending.Enqueue($inner) }
        }
        elseif ($exception.InnerException) { $pending.Enqueue($exception.InnerException) }
    }
    return $items
}

try {
    if (@(Get-ADOrganizationalUnit -LDAPFilter "(ou=$ouName)" -SearchBase $domain.DistinguishedName -SearchScope OneLevel -Server $Source).Count) {
        throw 'Authentication fixture name already exists.'
    }
    $creationAttempted = $true
    $ou = New-ADOrganizationalUnit -Name $ouName -Path $domain.DistinguishedName -Description $marker `
        -ProtectedFromAccidentalDeletion:$false -Server $Source -PassThru
    $user = New-ADUser -Name $username -SamAccountName $username -UserPrincipalName $upn -Path $ouDN `
        -Description $marker -AccountPassword $password -Enabled:$true -ChangePasswordAtLogon:$false `
        -Server $Source -PassThru
    # The qualification binds against the source, but replicate so the fixture
    # is not visible on one controller only.
    Sync-ADObject -Object $ou.ObjectGUID -Source $Source -Destination $Destination
    Sync-ADObject -Object $user.ObjectGUID -Source $Source -Destination $Destination
    $null = Get-ADUser -Identity $user.ObjectGUID -Server $Destination

    $phase = 'native-tests'
    $wire = [ordered]@{
        Server   = $Source
        Domain   = $domain.NetBIOSName
        Username = $username
        UPN      = $upn
        OU       = $ouDN
        Marker   = $marker
        Password = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($secret))
    } | ConvertTo-Json -Compress
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.Arguments = '-test.run ^TestDirectoryAuthenticationSweepLab$ -test.v -test.count=1 -test.timeout=600s'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8; $start.StandardErrorEncoding = [Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_AUTH_LAB'] = '1'
    $start.EnvironmentVariables['ADSDK_AUTH_RESULT'] = $ResultPath
    $start.EnvironmentVariables['ADSDK_AUTH_RUN_ID'] = $RunId
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Authentication test process did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
    # Bypass the console-codepage writer so Unicode survives whatever the host's
    # active code page is.
    $wireBytes = [Text.Encoding]::UTF8.GetBytes($wire)
    $process.StandardInput.BaseStream.Write($wireBytes, 0, $wireBytes.Length)
    $process.StandardInput.BaseStream.Flush(); $process.StandardInput.Close()
    [Array]::Clear($wireBytes, 0, $wireBytes.Length); $wireBytes = $null; $wire = $null
    if (-not $process.WaitForExit(600000)) { $process.Kill($true); throw 'Authentication test timed out.' }
    $exitCode = $process.ExitCode
    $output = @(($stdout.Result + $stderr.Result) -split "`r?`n" | Where-Object { $_ -ne '' })
}
catch { $failure = $_ }
finally {
    if ($process) { $process.Dispose() }
    if ($wireBytes) { [Array]::Clear($wireBytes, 0, $wireBytes.Length) }
    # Cleanup runs whatever happened, and removal is proved rather than assumed.
    $phase = 'cleanup'
    if ($creationAttempted) {
        try {
            Remove-ADOrganizationalUnit -Identity $ouDN -Recursive -Confirm:$false -Server $Source
        }
        catch {}
        try {
            $null = Get-ADOrganizationalUnit -Identity $ouDN -Server $Source
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $removed = $true
        }
        catch {}
    }
    $secret = $null; $password = $null
}

$record = [ordered]@{
    schema_version       = 1
    purpose              = 'go-sdk-activedirectory-authentication-reference'
    run_id               = $RunId
    source               = $Source
    destination          = $Destination
    marker               = $marker
    organizational_unit  = $ouDN
    account_non_ascii    = $true
    phase                = $phase
    exit_code            = $exitCode
    passed               = ($null -eq $failure -and $exitCode -eq 0 -and $removed)
    fixture_removed      = $removed
    full_ticket_complete = $false
    errors               = @(if ($failure) { Get-AuthError $failure })
    output               = $output
}
$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $ResultPath) 'run.json') -Encoding UTF8
if ($failure) { throw $failure }
Write-Output ('Authentication qualification ran; fixture removed: ' + $removed)
