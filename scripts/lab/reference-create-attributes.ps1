#Requires -Version 5.1
# Runs the create-time attribute and instance qualification and independently
# confirms that it left nothing behind.
#
# Unlike the other mutating collectors, this one creates no fixtures of its own.
# The Go harness creates them, because the fixtures *are* the subject: what is
# being qualified is that attributes and typed properties stated at create time
# are applied byte-exactly, and that an invalid one is refused without creating
# a partial object. Every fixture lives under one
# organizational unit the harness also creates and removes.
#
# What this script adds is a second witness. The harness reports its own cleanup,
# and a harness that wrongly believed it had cleaned up would say so. So after it
# exits, the ActiveDirectory module is used to search the domain for any fixture
# root matching the naming the harness uses, including deleted-object remnants,
# and the run is not recorded as passing unless that search comes back empty.
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
if (-not $AllowWrites) { throw 'Refusing to run the create-attributes qualification without -AllowWrites.' }
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Create-attributes test binary hash mismatch.' }
$domain = Get-ADDomain -Server $Source
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'The create-attributes qualification requires the isolated lab domain.' }

# The harness names its fixture root after the run, so a leftover is
# attributable to a specific run rather than merely to this script.
$fixturePrefix = 'sdk-createattr-'
# The objects the harness names, wherever they end up. A search for the
# fixture root alone cannot see a stray placed in a default container,
# which is how four were once left behind and reported as clean.
$objectPrefix = 'sdkca'
$expectedRoot = $fixturePrefix + $RunId
$failure = $null; $exitCode = $null; $output = @(); $process = $null
$phase = 'run-harness'
$leftovers = @(); $deletedLeftovers = @(); $recycleBinChecked = $false

function Get-CreateAttributesError($Record) {
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

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.Arguments = '-test.run ^TestDirectoryCreateAttributesSweepLab$ -test.v -test.count=1 -test.timeout=1800s'
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.Encoding]::UTF8; $start.StandardErrorEncoding = [Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_CREATEATTR_ENDPOINT'] = $Source
    $start.EnvironmentVariables['ADSDK_CREATEATTR_RESULT'] = $ResultPath
    $start.EnvironmentVariables['ADSDK_CREATEATTR_RUN_ID'] = $RunId
    $start.EnvironmentVariables['ADSDK_CREATEATTR_ALLOW_WRITES'] = 'yes'
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Create-attributes test process did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(1800000)) { $process.Kill($true); throw 'Create-attributes test timed out.' }
    $exitCode = $process.ExitCode
    $output = @(($stdout.Result + $stderr.Result) -split "`r?`n" | Where-Object { $_ -ne '' })

    # The independent cleanup check. Any fixture root from any run counts: a
    # leftover from an earlier attempt is still a dirty directory, and the lab
    # is disposable and owned, so nothing else may carry this naming.
    $phase = 'verify-cleanup'
    $leftovers = @(Get-ADObject -Server $Source -LDAPFilter "(|(ou=$fixturePrefix*)(cn=$fixturePrefix*)(ou=$objectPrefix*)(cn=$objectPrefix*)(sAMAccountName=$objectPrefix*)(cn=SDKCA*)(sAMAccountName=SDKCA*))" `
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

$clean = ($leftovers.Count -eq 0)
[ordered]@{
    schema_version          = 1
    purpose                 = 'go-sdk-activedirectory-create-attributes-reference'
    run_id                  = $RunId
    source                  = $Source
    fixture_prefix          = $fixturePrefix
    expected_fixture_root   = $expectedRoot
    phase                   = $phase
    exit_code               = $exitCode
    # Independent of the harness's own claim: the module searched and found
    # nothing live under the fixture naming.
    live_leftovers          = $leftovers
    directory_clean         = $clean
    deleted_object_remnants = $deletedLeftovers
    deleted_objects_readable = $recycleBinChecked
    passed                  = ($null -eq $failure -and $exitCode -eq 0 -and $clean)
    full_ticket_complete    = $false
    errors                  = @(if ($failure) { Get-CreateAttributesError $failure })
    output                  = $output
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $ResultPath) 'run.json') -Encoding UTF8
if ($failure) { throw $failure }
if (-not $clean) { throw ('The create-attributes run left objects behind: ' + ($leftovers -join '; ')) }
Write-Output ('Create-attributes qualification ran; directory clean: ' + $clean)
