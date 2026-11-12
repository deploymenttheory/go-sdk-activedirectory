#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$ExpectedComputer,
    [Parameter(Mandatory)][string]$NativeExecutable,
    [Parameter(Mandatory)][string]$ExpectedExecutableSHA256
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:COMPUTERNAME -cne $ExpectedComputer -or $ExpectedComputer -cne 'ADSDK25DC1') { throw 'Resource fixture computer differs.' }
if((Get-CimInstance Win32_ComputerSystem -Property DomainRole).DomainRole -notin @(4,5)) { throw 'Resource fixture requires a DC.' }
if((Get-FileHash -LiteralPath $NativeExecutable).Hash -cne $ExpectedExecutableSHA256) { throw 'Resource test binary differs.' }
$directory=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($NativeExecutable))
if(-not $directory.StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Resource output is outside staging directory.' }
for($cursor=$directory;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Resource directory traverses a link.' } }
$reportPath=Join-Path $directory 'native-resources.json'
if(Test-Path -LiteralPath $reportPath) { throw 'Existing resource report is preserved.' }
Import-Module ActiveDirectory
$command=Get-Command Get-ADDCCloningExcludedApplicationList
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$record=[ordered]@{schema_version=1;computer=$env:COMPUTERNAME;os_full_build="$($build.CurrentBuildNumber).$($build.UBR)";module_file_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($command.ImplementingType.Assembly.Location).FileVersion;test_executable_sha256=$ExpectedExecutableSHA256;exit_code=$null;stdout=$null;stderr=$null;report=$null;error=$null;cleanup_error=$null;passed=$false}
$start=[Diagnostics.ProcessStartInfo]::new()
$start.FileName=$NativeExecutable;$start.Arguments='-test.run "^TestNativeResourceCycles$" -test.v -test.timeout 2m'
$start.UseShellExecute=$false;$start.CreateNoWindow=$true
$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
$start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false);$start.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
$start.EnvironmentVariables['ADSDK_CLONING_RESOURCE_REFERENCE']=$reportPath
$process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false
try {
    if(-not $process.Start()) { throw 'Resource test did not start.' }
    $started=$true;$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    $elapsed=[Diagnostics.Stopwatch]::StartNew();$exited=$false
    while($elapsed.Elapsed.TotalSeconds -lt 125) { if($process.WaitForExit(250)) { $exited=$true;break } }
    if(-not $exited) { throw 'Resource test exceeded its timeout; no retry.' }
    $record.exit_code=$process.ExitCode
    if(-not $stdout.Wait(1000) -or -not $stderr.Wait(1000)) { throw 'Resource test output collection timed out.' }
    $record.stdout=$stdout.Result;$record.stderr=$stderr.Result
    $record.report=[IO.File]::ReadAllText($reportPath) | ConvertFrom-Json
    $cycles=@($record.report.cycles)
    $invalid=@($cycles | Where-Object {
        -not $_.passed -or -not $_.complete -or
        $_.role_buffers.acquired -ne 1 -or $_.role_buffers.released -ne 1 -or $_.role_buffers.outstanding -ne 0 -or
        $_.registry_keys.acquired -lt 1 -or $_.registry_keys.acquired -ne $_.registry_keys.released -or $_.registry_keys.outstanding -ne 0 -or
        $_.scm_handles.acquired -ne 1 -or $_.scm_handles.released -ne 1 -or $_.scm_handles.outstanding -ne 0
    })
    $record.passed=($record.exit_code -eq 0 -and $record.report.passed -and $record.report.computer -ceq $ExpectedComputer -and
        $record.report.iterations_requested -eq 100 -and $record.report.iterations_completed -eq 100 -and $cycles.Count -eq 100 -and $invalid.Count -eq 0)
} catch { $record.error=$_.Exception.Message }
finally {
    if($started) {
        try { if(-not $process.HasExited) { $process.Kill();if(-not $process.WaitForExit(2000)) { throw 'Owned resource test still running.' } } }
        catch { $record.cleanup_error=$_.Exception.Message }
    }
    $process.Dispose()
}
$record.passed=$record.passed -and $null -eq $record.error -and $null -eq $record.cleanup_error
$record | ConvertTo-Json -Depth 12 -Compress
