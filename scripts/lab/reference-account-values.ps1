#Requires -Version 5.1
# Runs the account value-property qualification and independently confirms that
# it left nothing behind.
#
# Four property families on the three account classes: account expiry, binary
# certificates, service principal names and the user-derived properties. The
# Go harness creates every fixture, because the fixtures are the subject: what
# is being qualified is what a *value* means after a round-trip, not that a
# write landed.
#
# This collector carries one check the other mutating collectors do not need.
# Service principal names are unique forest-wide, so a stray fixture SPN does
# not merely leave the directory dirty: it makes the next run's uniqueness
# probe fail for the wrong reason, and that failure would look like the SDK
# misbehaving. The cleanup search therefore looks for the harness's SPNs by
# value as well as for its objects by name.
#
# This script mutates the directory and is gated behind -AllowWrites.
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
if (-not $AllowWrites) { throw 'Refusing to run the account value qualification without -AllowWrites.' }
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Account value test binary hash mismatch.' }
$domain = Get-ADDomain -Server $Source
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'The account value qualification requires the isolated lab domain.' }

# The harness names its fixture root after the run, so a leftover is
# attributable to a specific run rather than merely to this script.
$fixturePrefix = 'sdk-accountvalue-'
# The objects the harness names, wherever they end up. A search for the
# fixture root alone cannot see a stray placed in a default container.
$objectPrefix = 'sdkav'
$expectedRoot = $fixturePrefix + $RunId
$failure = $null; $exitCode = $null; $output = @(); $process = $null
$phase = 'run-harness'
$leftovers = @(); $deletedLeftovers = @(); $recycleBinChecked = $false
$spnLeftovers = @()

function Get-AccountValueError($Record) {
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

try {
    # A fixture root from this run must not already exist. If it does, a previous
    # attempt failed to clean up and this run would read its leavings as its own.
    $existing = @(Get-ADObject -Server $Source -LDAPFilter "(ou=$expectedRoot)" `
            -SearchBase $domain.DistinguishedName -SearchScope OneLevel -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        throw "A fixture root for run $RunId already exists: $($existing[0].DistinguishedName)"
    }

    # A service principal name left by an earlier run would make this run's
    # forest-uniqueness probe fail against a stray rather than against the
    # object the harness created for it. That is a false pass of the wrong
    # observation, so it is refused up front rather than cleaned up silently.
    $staleSPN = @(Get-ADObject -Server $Source -LDAPFilter "(servicePrincipalName=$objectPrefix*)" `
            -SearchBase $domain.DistinguishedName -SearchScope Subtree -ErrorAction SilentlyContinue)
    if ($staleSPN.Count -gt 0) {
        throw ('Service principal names from an earlier run still exist: ' +
            (($staleSPN | ForEach-Object { $_.DistinguishedName }) -join '; '))
    }

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.Arguments = '-test.run ^TestDirectoryAccountValueSweepLab$ -test.v -test.count=1 -test.timeout=2700s'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8; $start.StandardErrorEncoding = [Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_ACCOUNTVALUE_ENDPOINT'] = $Source
    $start.EnvironmentVariables['ADSDK_ACCOUNTVALUE_RESULT'] = $ResultPath
    $start.EnvironmentVariables['ADSDK_ACCOUNTVALUE_RUN_ID'] = $RunId
    $start.EnvironmentVariables['ADSDK_ACCOUNTVALUE_ALLOW_WRITES'] = 'yes'
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Account value test process did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(2700000)) { $process.Kill($true); throw 'Account value test timed out.' }
    $exitCode = $process.ExitCode
    $output = @(($stdout.Result + $stderr.Result) -split "`r?`n" | Where-Object { $_ -ne '' })

    # The independent cleanup check. Any fixture from any run counts: a leftover
    # from an earlier attempt is still a dirty directory, and the lab is
    # disposable and owned, so nothing else may carry this naming.
    $phase = 'verify-cleanup'
    $leftovers = @(Get-ADObject -Server $Source -LDAPFilter "(|(ou=$fixturePrefix*)(cn=$fixturePrefix*)(ou=$objectPrefix*)(cn=$objectPrefix*)(sAMAccountName=$objectPrefix*)(cn=SDKAV*)(sAMAccountName=SDKAV*))" `
            -SearchBase $domain.DistinguishedName -SearchScope Subtree -ErrorAction SilentlyContinue |
        ForEach-Object { $_.DistinguishedName })

    # And again by service principal name, which is the value that outlives a
    # badly cleaned object in a way that breaks the next run.
    $spnLeftovers = @(Get-ADObject -Server $Source -LDAPFilter "(servicePrincipalName=$objectPrefix*)" `
            -SearchBase $domain.DistinguishedName -SearchScope Subtree -ErrorAction SilentlyContinue |
        ForEach-Object { $_.DistinguishedName })

    # A delete leaves a tombstone or a deleted object depending on whether the
    # Recycle Bin is enabled. Neither is a live object, so neither is a cleanup
    # failure, but both are recorded so the artifact says which the lab produces
    # rather than leaving it to be inferred.
    try {
        $deletedLeftovers = @(Get-ADObject -Server $Source -IncludeDeletedObjects `
                -LDAPFilter "(&(|(ou=$fixturePrefix*)(cn=$fixturePrefix*)(ou=$objectPrefix*)(cn=$objectPrefix*))(isDeleted=TRUE))" `
                -SearchBase $domain.DistinguishedName `
                -SearchScope Subtree -ErrorAction Stop |
            ForEach-Object { $_.DistinguishedName })
        $recycleBinChecked = $true
    }
    catch {
        # Reading deleted objects can be refused outright. That is not a
        # cleanup failure and must not be reported as one.
        $recycleBinChecked = $false
    }
}
catch { $failure = $_ }
finally {
    if ($process) { $process.Dispose() }
}

$clean = ($leftovers.Count -eq 0 -and $spnLeftovers.Count -eq 0)
[ordered]@{
    schema_version           = 1
    purpose                  = 'go-sdk-activedirectory-account-values-reference'
    run_id                   = $RunId
    source                   = $Source
    fixture_prefix           = $fixturePrefix
    expected_fixture_root    = $expectedRoot
    phase                    = $phase
    exit_code                = $exitCode
    # Independent of the harness's own claim: the module searched and found
    # nothing live under the fixture naming, by name or by service principal
    # name.
    live_leftovers           = $leftovers
    service_principal_leftovers = $spnLeftovers
    directory_clean          = $clean
    deleted_object_remnants  = $deletedLeftovers
    deleted_objects_readable = $recycleBinChecked
    passed                   = ($null -eq $failure -and $exitCode -eq 0 -and $clean)
    full_ticket_complete     = $false
    errors                   = @(if ($failure) { Get-AccountValueError $failure })
    output                   = $output
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $ResultPath) 'run.json') -Encoding UTF8
if ($failure) { throw $failure }
if (-not $clean) {
    throw ('The account value run left objects behind: ' +
        (($leftovers + $spnLeftovers) -join '; '))
}
Write-Output ('Account value qualification ran; directory clean: ' + $clean)
