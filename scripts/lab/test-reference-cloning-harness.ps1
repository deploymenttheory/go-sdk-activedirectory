#Requires -Version 5.1
# Local harness test: all AD/role/module probes are mocked. Only the explicitly
# supplied test helper is launched, and only its process may be terminated.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TestHelper,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$fixtureExe = [IO.Path]::GetFullPath($TestHelper)
$fixtureHash = (Get-FileHash -LiteralPath $fixtureExe).Hash
$fixtureDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $fixtureDirectory) { throw 'Test output directory already exists and is preserved.' }
$null = New-Item -ItemType Directory -Path $fixtureDirectory
function Get-CimInstance { param($ClassName, $Property) [pscustomobject]@{DomainRole=5} }
function Import-Module { param($Name) if ($Name -ne 'ActiveDirectory') { throw 'Unexpected mock module.' } }
function Get-ADDCCloningExcludedApplicationList {
    [CmdletBinding()]param()
    if ($env:ADSDK_HARNESS_TEST_MODE -ne 'empty') { [pscustomobject]@{Name='Fixture';Type='Service'} }
}
function Get-Command {
    param($Name)
    [pscustomobject]@{Module=[pscustomobject]@{Version=[version]'1.0.0'};ImplementingType=[pscustomobject]@{Assembly=[pscustomobject]@{Location=$fixtureExe}}}
}
function Get-ItemProperty { param($Path) [pscustomobject]@{CurrentBuildNumber='fixture';UBR=0} }
$originalMode = [Environment]::GetEnvironmentVariable('ADSDK_HARNESS_TEST_MODE', 'Process')
try {
    foreach ($mode in @('success', 'empty', 'invalid', 'failure', 'timeout')) {
        $env:ADSDK_HARNESS_TEST_MODE = $mode
        $output = Join-Path $fixtureDirectory ($mode+'.json')
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $failure = $null
        try {
            & (Join-Path $PSScriptRoot 'reference-cloning.ps1') -NativeExecutable $fixtureExe `
                -ExpectedExecutableSHA256 $fixtureHash -ExpectedComputer $env:COMPUTERNAME `
                -OutputPath $output -TimeoutSeconds 1
        } catch { $failure = $_.Exception.Message }
        $report = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
        if ($mode -in @('success','empty') -and (-not $report.passed -or $failure)) { throw "Positive harness fixture failed: $mode" }
        if ($mode -notin @('success','empty') -and ($report.passed -or -not $failure)) { throw "Failed fixture was reported as success: $mode" }
        if ($mode -eq 'invalid' -and -not $report.stdout_error) { throw 'Invalid JSON was not captured.' }
        if ($mode -eq 'failure' -and $report.native_exit_code -ne 7) { throw 'Failed exit code was lost.' }
        if ($mode -eq 'timeout' -and (-not $report.native_timed_out -or $report.cleanup_error -or $watch.Elapsed.TotalSeconds -gt 6)) {
            throw 'Timeout and cleanup were not bounded.'
        }
        [pscustomobject]@{mode=$mode;passed=$report.passed;native_exit=$report.native_exit_code;timed_out=$report.native_timed_out;elapsed_ms=$watch.ElapsedMilliseconds;structured_report=$true}
    }
} finally {
    [Environment]::SetEnvironmentVariable('ADSDK_HARNESS_TEST_MODE', $originalMode, 'Process')
}
