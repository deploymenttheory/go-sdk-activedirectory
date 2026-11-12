#Requires -Version 5.1
# Run locally inside an owned disposable DC. This comparison does not modify
# services, registry values, inclusion lists, or VM configuration.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$NativeExecutable,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedExecutableSHA256,
    [Parameter(Mandatory)][string]$ExpectedComputer,
    [Parameter(Mandatory)][string]$OutputPath,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 60
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:COMPUTERNAME -cne $ExpectedComputer) { throw 'Reference computer identity differs.' }
if ((Get-CimInstance Win32_ComputerSystem -Property DomainRole).DomainRole -notin @(4, 5)) {
    throw 'Reference execution requires an AD DS domain controller.'
}
$executable = [IO.Path]::GetFullPath($NativeExecutable)
$output = [IO.Path]::GetFullPath($OutputPath)
if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -cne $ExpectedExecutableSHA256.ToUpperInvariant()) {
    throw 'Native executable digest differs.'
}
if (Test-Path -LiteralPath $output) { throw 'Reference output already exists and is preserved.' }
Import-Module ActiveDirectory
$command = Get-Command Get-ADDCCloningExcludedApplicationList
$assembly = $command.ImplementingType.Assembly.Location
$build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$record = [ordered]@{
    schema_version = 1
    computer = $env:COMPUTERNAME
    timestamp = [DateTime]::UtcNow.ToString('o')
    os_full_build = "$($build.CurrentBuildNumber).$($build.UBR)"
    powershell = $PSVersionTable.PSVersion.ToString()
    architecture = $env:PROCESSOR_ARCHITECTURE
    module_version = $command.Module.Version.ToString()
    module_file_version = [Diagnostics.FileVersionInfo]::GetVersionInfo($assembly).FileVersion
    module_file_sha256 = (Get-FileHash -LiteralPath $assembly).Hash
    native_executable_sha256 = $ExpectedExecutableSHA256.ToUpperInvariant()
    reference = @()
    native = $null
    native_exit_code = $null
    native_error = $null
    native_timed_out = $false
    process_error = $null
    stdout_error = $null
    reference_error = $null
    comparison_error = $null
    cleanup_error = $null
    passed = $false
}
function Error-Details($Failure) {
    return [ordered]@{type=$Failure.Exception.GetType().FullName; message=$Failure.Exception.Message}
}
try {
    $record.reference = @(Get-ADDCCloningExcludedApplicationList -ErrorAction Stop | ForEach-Object {
        [ordered]@{ name = [string]$_.Name; type = [string]$_.Type }
    })
} catch { $record.reference_error = Error-Details $_ }
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $executable
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
$start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
$process = [Diagnostics.Process]::new()
$process.StartInfo = $start
$started = $false
$terminationAttempted = $false
$stdout = $null
$stderr = $null
try {
    if (-not $process.Start()) { throw 'Native reference process did not start.' }
    $started = $true
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $exited = $false
    while ($elapsed.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ($process.WaitForExit(250)) { $exited = $true; break }
    }
    if (-not $exited) {
        $record.native_timed_out = $true
        $terminationAttempted = $true
        if (-not $process.HasExited) { $process.Kill() }
        $exited = $process.WaitForExit(2000)
        if (-not $exited) { $record.cleanup_error = 'Owned native process did not exit within two seconds after termination.' }
    }
    if ($exited) { $record.native_exit_code = $process.ExitCode }
    try {
        if (-not $stderr.Wait(1000)) { throw 'Native stderr collection exceeded one second after process wait.' }
        $record.native_error = $stderr.Result
    } catch { $record.process_error = Error-Details $_ }
    try {
        if (-not $stdout.Wait(1000)) { throw 'Native stdout collection exceeded one second after process wait.' }
        $record.native = $stdout.Result | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $record.native -or -not $record.native.PSObject.Properties['entries'] -or
            -not $record.native.PSObject.Properties['complete'] -or
            -not $record.native.PSObject.Properties['authorization_limited']) {
            throw 'Native stdout is not a cloning inspection result.'
        }
    } catch { $record.stdout_error = Error-Details $_ }
} catch {
    $record.process_error = Error-Details $_
} finally {
    if ($started -and -not $terminationAttempted) {
        try {
            if (-not $process.HasExited) {
                $terminationAttempted = $true
                $process.Kill()
                if (-not $process.WaitForExit(2000)) { throw 'Owned native process did not exit during cleanup.' }
            }
        } catch { $record.cleanup_error = Error-Details $_ }
    }
    # Dispose closes the owned redirected streams. Never call the parameterless
    # WaitForExit: a child retaining a pipe must not make this harness hang.
    $process.Dispose()
}
function Entry-Keys($Entries) {
    return @($Entries | ForEach-Object { @([string]$_.type, [string]$_.name) | ConvertTo-Json -Compress } | Sort-Object -CaseSensitive)
}
try {
    if ($null -eq $record.process_error -and $null -eq $record.stdout_error -and
        $null -eq $record.reference_error -and $null -eq $record.cleanup_error -and
        -not $record.native_timed_out) {
        $expected = @(Entry-Keys $record.reference)
        $actual = @(Entry-Keys $record.native.entries)
        $record.passed = $record.native_exit_code -eq 0 -and $record.native.complete -and
            $record.native.authorization_limited -and $expected.Count -eq $actual.Count -and
            (($expected -join "`n") -ceq ($actual -join "`n"))
    }
} catch { $record.comparison_error = Error-Details $_ }
try {
    if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -cne $record.native_executable_sha256) {
        throw 'Native executable changed during comparison.'
    }
} catch { $record.process_error = Error-Details $_; $record.passed = $false }
$stream = [IO.File]::Open($output, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 12))
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
} finally {
    $stream.Dispose()
}
if (-not $record.passed) { throw 'Native/reference cloning inventory differs; inspect the retained report.' }
