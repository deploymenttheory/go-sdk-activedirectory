#Requires -Version 5.1
# Creates the fixture the write authentication-and-permissions qualification
# needs, runs it, and removes the fixture again.
#
# One ordinary identity and two containers. The identity is delegated full
# control on one of them and has no rights on the other, so the endpoint, the
# session, the credentials and the request are identical across both halves of
# the qualification and the only difference is the access check. A subject of
# each class is placed in the denied container by this collector's own
# identity, so the delegated identity can read it and must not be able to
# change it.
#
# The delegation is a single access rule on one organizational unit inside the
# owned disposable lab domain, and it is removed with that unit: the whole
# fixture root is deleted recursively and its removal is proved, not assumed.
# Nothing outside the fixture root is modified.
#
# This script mutates the directory, so it is gated behind -AllowWrites. The
# secret reaches the test process only through a private pipe: no command
# argument, environment variable, transcript, or credential file is created.
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
if (-not $AllowWrites) { throw 'Refusing to create a write-permission fixture without -AllowWrites.' }
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Write-authentication test binary hash mismatch.' }
$domain = Get-ADDomain -Server $Source
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'Write-authentication fixtures require the isolated lab domain.' }

$nonce = [guid]::NewGuid().ToString('N').Substring(0, 16)
$ouName = 'ADSDK-WriteAuth-' + $nonce
$ouDN = "OU=$ouName,$($domain.DistinguishedName)"
$marker = 'ad-sdk-writeauth:' + $RunId
# Non-ASCII account name and a password with non-ASCII and supplementary
# Unicode, so the native identity path is exercised rather than assumed.
$username = 'sdk' + [char]0x00e9 + $nonce.Substring(0, 8)
$upn = "$username@$($domain.DNSRoot)"
$secret = 'Aa9!' + [char]0x0101 + [char]::ConvertFromUtf32(0x1f511) + [guid]::NewGuid().ToString('N')
$password = ConvertTo-SecureString $secret -AsPlainText -Force

$creationAttempted = $false; $process = $null; $wireBytes = $null
$failure = $null; $removed = $false; $exitCode = $null; $output = @(); $phase = 'create-fixture'

function Get-WriteAuthError($Record) {
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
        throw 'Write-authentication fixture name already exists.'
    }
    $creationAttempted = $true
    $ou = New-ADOrganizationalUnit -Name $ouName -Path $domain.DistinguishedName -Description $marker `
        -ProtectedFromAccidentalDeletion:$false -Server $Source -PassThru
    $user = New-ADUser -Name $username -SamAccountName $username -UserPrincipalName $upn -Path $ouDN `
        -Description $marker -AccountPassword $password -Enabled:$true -ChangePasswordAtLogon:$false `
        -Server $Source -PassThru

    # Two containers under the fixture root. The identity is delegated rights
    # on one and none on the other, so the only difference between the two
    # halves of the qualification is the access check itself.
    $delegatedDN = "OU=Delegated,$ouDN"
    $deniedDN = "OU=Denied,$ouDN"
    $delegated = New-ADOrganizationalUnit -Name 'Delegated' -Path $ouDN -Description $marker `
        -ProtectedFromAccidentalDeletion:$false -Server $Source -PassThru
    $deniedOU = New-ADOrganizationalUnit -Name 'Denied' -Path $ouDN -Description $marker `
        -ProtectedFromAccidentalDeletion:$false -Server $Source -PassThru

    # Full control on the delegated container only. The lab is disposable and
    # the grant is removed with the fixture; nothing outside this OU is touched.
    # Bound explicitly to the source controller. The AD: provider drive picks
    # its own default server, which need not be the one the fixture was just
    # created on, and the object is then not found.
    $phase = 'delegate'
    $entry = [ADSI]"LDAP://$Source/$delegatedDN"
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $user.SID, 'GenericAll', 'Allow',
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    $entry.ObjectSecurity.AddAccessRule($rule)
    $entry.CommitChanges()
    $entry.Dispose()

    # A subject inside the denied container for the update and delete halves to
    # attempt. It is created by this collector's own identity, so the delegated
    # identity can read it and must not be able to change it.
    foreach ($victim in @(
            @{ n = 'sdkwa0v'; make = { New-ADUser -Name 'sdkwa0v' -SamAccountName 'sdkwa0v' -Path $deniedDN -Description $marker -Server $Source -PassThru } },
            @{ n = 'sdkwa1v'; make = { New-ADGroup -Name 'sdkwa1v' -Path $deniedDN -GroupScope Global -Description $marker -Server $Source -PassThru } },
            @{ n = 'SDKWA2v'; make = { New-ADComputer -Name 'SDKWA2v' -Path $deniedDN -Description $marker -Server $Source -PassThru } },
            @{ n = 'sdkwa3v'; make = { New-ADOrganizationalUnit -Name 'sdkwa3v' -Path $deniedDN -Description $marker -ProtectedFromAccidentalDeletion:$false -Server $Source -PassThru } },
            @{ n = 'sdkwa4v'; make = { New-ADObject -Name 'sdkwa4v' -Type container -Path $deniedDN -Description $marker -Server $Source -PassThru } })) {
        $null = & $victim.make
    }

    Sync-ADObject -Object $delegated.ObjectGUID -Source $Source -Destination $Destination
    Sync-ADObject -Object $deniedOU.ObjectGUID -Source $Source -Destination $Destination
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
        DelegatedOU = $delegatedDN
        DeniedOU    = $deniedDN
        Marker      = $marker
        Password = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($secret))
    } | ConvertTo-Json -Compress
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.Arguments = '-test.run ^TestDirectoryWriteAuthenticationSweepLab$ -test.v -test.count=1 -test.timeout=600s'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8; $start.StandardErrorEncoding = [Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_WRITEAUTH_LAB'] = '1'
    $start.EnvironmentVariables['ADSDK_WRITEAUTH_RESULT'] = $ResultPath
    $start.EnvironmentVariables['ADSDK_WRITEAUTH_RUN_ID'] = $RunId
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Write-authentication test process did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
    # Bypass the console-codepage writer so Unicode survives whatever the host's
    # active code page is.
    $wireBytes = [Text.Encoding]::UTF8.GetBytes($wire)
    $process.StandardInput.BaseStream.Write($wireBytes, 0, $wireBytes.Length)
    $process.StandardInput.BaseStream.Flush(); $process.StandardInput.Close()
    [Array]::Clear($wireBytes, 0, $wireBytes.Length); $wireBytes = $null; $wire = $null
    if (-not $process.WaitForExit(600000)) { $process.Kill($true); throw 'Write-authentication test timed out.' }
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
    purpose              = 'go-sdk-activedirectory-write-authentication-reference'
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
    errors               = @(if ($failure) { Get-WriteAuthError $failure })
    output               = $output
}
$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $ResultPath) 'run.json') -Encoding UTF8
if ($failure) { throw $failure }
Write-Output ('Authentication qualification ran; fixture removed: ' + $removed)
