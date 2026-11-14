#Requires -Version 5.1
# Creates the identity fixtures the identity-forms-and-scope qualification
# needs, runs it, and removes them again.
#
# Three objects are created in one organizational unit of the owned disposable
# lab domain: a user whose common name carries non-ASCII and supplementary
# Unicode, a user whose common name contains characters that must be escaped in
# a distinguished name, and a group with an escaped common name. Each records
# the identity forms that apply to it, so the qualification resolves observed
# values rather than constructed ones.
#
# This script mutates the directory and is gated behind -AllowWrites. No secret
# is recorded: the accounts' passwords are generated, used only for creation,
# and discarded.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$ExpectedHash,
    [switch]$AllowWrites
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
if (-not $AllowWrites) { throw 'Refusing to create identity fixtures without -AllowWrites.' }
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Identity test binary hash mismatch.' }
$domain = Get-ADDomain -Server $Source
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'Identity fixtures require the isolated lab domain.' }

$nonce = [guid]::NewGuid().ToString('N').Substring(0, 16)
$ouName = 'ADSDK-Identity-' + $nonce
$ouDN = "OU=$ouName,$($domain.DistinguishedName)"
$marker = 'ad-sdk-identity:' + $RunId
$short = $nonce.Substring(0, 8)
# A non-ASCII common name with a supplementary-plane character, and a name whose
# comma and plus must be escaped in a distinguished name.
$unicodeName = 'sdk' + [char]0x00e9 + [char]::ConvertFromUtf32(0x1f511) + $short
$escapedName = 'sdk,esc+' + $short
$groupName = 'sdkgrp,esc+' + $short
$creationAttempted = $false; $process = $null
$failure = $null; $removed = $false; $exitCode = $null; $output = @(); $phase = 'create-fixtures'

function Get-IdentityError($Record) {
    $items = @(); $pending = [Collections.Generic.Queue[Exception]]::new()
    $pending.Enqueue($Record.Exception)
    while ($pending.Count) {
        $exception = $pending.Dequeue()
        $code = $null
        if ($exception.PSObject.Properties['ErrorCode']) { $code = [int]$exception.ErrorCode }
        $items += [ordered]@{ type = $exception.GetType().FullName; hresult = $exception.HResult; code = $code }
        if ($exception -is [AggregateException]) { foreach ($i in $exception.InnerExceptions) { $pending.Enqueue($i) } }
        elseif ($exception.InnerException) { $pending.Enqueue($exception.InnerException) }
    }
    return $items
}

function Get-IdentityForms($Object) {
    # Only the forms the object actually carries. An organizational unit has no
    # security identifier and no account name, and the qualification must not be
    # handed a form the reference does not document for it.
    $forms = [ordered]@{ dn = $Object.DistinguishedName; guid = $Object.ObjectGUID.ToString() }
    if ($Object.PSObject.Properties['SID'] -and $Object.SID) { $forms['sid'] = $Object.SID.Value }
    if ($Object.PSObject.Properties['SamAccountName'] -and $Object.SamAccountName) { $forms['account'] = $Object.SamAccountName }
    return $forms
}

try {
    if (@(Get-ADOrganizationalUnit -LDAPFilter "(ou=$ouName)" -SearchBase $domain.DistinguishedName -SearchScope OneLevel -Server $Source).Count) {
        throw 'Identity fixture name already exists.'
    }
    $creationAttempted = $true
    $ou = New-ADOrganizationalUnit -Name $ouName -Path $domain.DistinguishedName -Description $marker `
        -ProtectedFromAccidentalDeletion:$false -Server $Source -PassThru
    $password = ConvertTo-SecureString ('Aa9!' + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
    # SamAccountName cannot carry a comma, so the escaped form is exercised by
    # the common name and therefore by the distinguished name.
    $unicodeUser = New-ADUser -Name $unicodeName -SamAccountName ('u' + $short) -Path $ouDN -Description $marker `
        -AccountPassword $password -Enabled:$true -Server $Source -PassThru
    $escapedUser = New-ADUser -Name $escapedName -SamAccountName ('e' + $short) -Path $ouDN -Description $marker `
        -AccountPassword $password -Enabled:$true -Server $Source -PassThru
    $escapedGroup = New-ADGroup -Name $groupName -SamAccountName ('g' + $short) -GroupScope Global `
        -Path $ouDN -Description $marker -Server $Source -PassThru
    $password = $null

    # An existing computer account, read rather than created: the controller's
    # own object carries every account form.
    $computer = Get-ADComputer -Identity ($Source.Split('.')[0]) -Server $Source

    $phase = 'native-tests'
    $fixture = [ordered]@{
        schema_version = 1
        run_id         = $RunId
        server         = $Source
        marker         = $marker
        ou             = Get-IdentityForms $ou
        unicode_user   = Get-IdentityForms $unicodeUser
        escaped_user   = Get-IdentityForms $escapedUser
        escaped_group  = Get-IdentityForms $escapedGroup
        computer       = Get-IdentityForms $computer
        # A syntactically valid identity that resolves to nothing.
        missing_guid   = [guid]::NewGuid().ToString()
    }
    $fixturePath = Join-Path (Split-Path -Parent $ResultPath) 'fixture.json'
    $fixture | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fixturePath -Encoding UTF8

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.Arguments = '-test.run ^TestDirectoryIdentitySweepLab$ -test.v -test.count=1 -test.timeout=600s'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8; $start.StandardErrorEncoding = [Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_IDENTITY_FIXTURE'] = $fixturePath
    $start.EnvironmentVariables['ADSDK_IDENTITY_RESULT'] = $ResultPath
    $start.EnvironmentVariables['ADSDK_IDENTITY_RUN_ID'] = $RunId
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Identity test process did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(600000)) { $process.Kill($true); throw 'Identity test timed out.' }
    $exitCode = $process.ExitCode
    $output = @(($stdout.Result + $stderr.Result) -split "`r?`n" | Where-Object { $_ -ne '' })
}
catch { $failure = $_ }
finally {
    if ($process) { $process.Dispose() }
    $phase = 'cleanup'
    if ($creationAttempted) {
        try { Remove-ADOrganizationalUnit -Identity $ouDN -Recursive -Confirm:$false -Server $Source } catch {}
        try { $null = Get-ADOrganizationalUnit -Identity $ouDN -Server $Source }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $removed = $true }
        catch {}
    }
}

[ordered]@{
    schema_version       = 1
    purpose              = 'go-sdk-activedirectory-identity-reference'
    run_id               = $RunId
    source               = $Source
    marker               = $marker
    organizational_unit  = $ouDN
    phase                = $phase
    exit_code            = $exitCode
    passed               = ($null -eq $failure -and $exitCode -eq 0 -and $removed)
    fixtures_removed     = $removed
    full_ticket_complete = $false
    errors               = @(if ($failure) { Get-IdentityError $failure })
    output               = $output
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $ResultPath) 'run.json') -Encoding UTF8
if ($failure) { throw $failure }
Write-Output ('Identity qualification ran; fixtures removed: ' + $removed)
