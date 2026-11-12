#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState, [Parameter(Mandatory)][PSCredential]$Credential, [Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
if (-not $LabState.configured) { throw 'Configure the lab before testing.' }
$member = $LabState.machines | Where-Object role -eq 'member'
$null = Get-OwnedVM $member $LabState
$runId = 'conditions-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$resultRoot = Join-Path $LabRoot "results\$runId"
$null = New-Item -ItemType Directory -Path $resultRoot
# Build from a retained snapshot, never label a caller-supplied executable with
# hashes from an unrelated working tree. Environment overrides are restored.
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$snapshot = Join-Path $resultRoot 'source'
$null = New-Item -ItemType Directory -Path (Join-Path $snapshot 'conditions')
Copy-Item -LiteralPath (Join-Path $sourceRoot 'go.mod'), (Join-Path $sourceRoot 'go.sum') -Destination $snapshot
Get-ChildItem -LiteralPath (Join-Path $sourceRoot 'conditions') -Filter '*.go' | Copy-Item -Destination (Join-Path $snapshot 'conditions')
function Get-SnapshotHashes {
    $hashes = [ordered]@{}
    foreach ($file in (Get-ChildItem -LiteralPath $snapshot -File -Recurse | Sort-Object FullName)) {
        $hashes[$file.FullName.Substring($snapshot.Length + 1).Replace('\', '/')] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    return $hashes
}
$sourceHashes = Get-SnapshotHashes
$binaryPath = Join-Path $resultRoot 'conditions.test.exe'
$buildArguments = @('test', '-mod=readonly', '-trimpath', '-c', '-o', $binaryPath, './conditions')
$buildEnvironment = @{GOOS='windows'; GOARCH='amd64'; CGO_ENABLED='0'; GOWORK='off'; GOFLAGS=''; GOTOOLCHAIN='local'}
$previousEnvironment = @{}
Push-Location $snapshot
try {
    foreach ($key in $buildEnvironment.Keys) {
        $previousEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, $buildEnvironment[$key], 'Process')
    }
    $goVersion = (& go version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Unable to identify the Go toolchain.' }
    & go @buildArguments *> (Join-Path $resultRoot 'build.log')
    if ($LASTEXITCODE -ne 0) { throw "Native test build failed; see $resultRoot\build.log" }
    if (($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-SnapshotHashes) | ConvertTo-Json -Compress)) { throw 'Source snapshot changed during the build.' }
} finally {
    foreach ($key in $previousEnvironment.Keys) { [Environment]::SetEnvironmentVariable($key, $previousEnvironment[$key], 'Process') }
    Pop-Location
}
$binary = Get-Item -LiteralPath $binaryPath
$sha256 = (Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash
$targetDirectory = "C:\ad-sdk-validation\$runId"
$targetBinary = "$targetDirectory\conditions.test.exe"
$session = Wait-LabGuest $member $Credential
$created = $false
try {
    Invoke-Command -Session $session -ArgumentList $targetDirectory -ScriptBlock {
        param($Directory)
        $ErrorActionPreference = 'Stop'
        $root = 'C:\ad-sdk-validation'
        if ((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'The test root must not be a reparse point.' }
        if (-not ([IO.Path]::GetFullPath($Directory)).StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $Directory)) { throw 'Unexpected or existing test directory.' }
        $null = New-Item -ItemType Directory -Path $Directory
    }
    $created = $true
    Copy-Item -LiteralPath $binary.FullName -Destination $targetBinary -ToSession $session
    Write-LabLog "Running native Go condition tests on $($member.name)."
    $result = Invoke-Command -Session $session -ArgumentList $targetBinary -ScriptBlock {
        param($Executable)
        $ErrorActionPreference = 'Continue'
        $build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $previousCorpus = $env:ADSDK_CONDITION_CORPUS
        try {
            $env:ADSDK_CONDITION_CORPUS = Join-Path ([IO.Path]::GetDirectoryName($Executable)) 'reference-corpus.json'
            $output = @(& $Executable '-test.v' '-test.count=1' 2>&1 | ForEach-Object { $_.ToString() })
            $testExit = $LASTEXITCODE
        } finally { $env:ADSDK_CONDITION_CORPUS = $previousCorpus }
        [ordered]@{exit_code=$testExit; build="$($build.CurrentBuild).$($build.UBR)"; architecture=$env:PROCESSOR_ARCHITECTURE; sha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash; output=$output} | ConvertTo-Json -Depth 5
    } | ConvertFrom-Json
    if ($result.sha256 -ne $sha256) { throw 'The guest test binary hash does not match the host artifact.' }
    if ($result.exit_code -eq 0) {
        Copy-Item -LiteralPath "$targetDirectory\reference-corpus.json" -Destination (Join-Path $resultRoot 'reference-corpus.json') -FromSession $session
    }
    [ordered]@{schema_version=1; run=$runId; time=[DateTime]::UtcNow.ToString('o'); passed=($result.exit_code -eq 0); binary_sha256=$sha256; source_sha256=$sourceHashes; build=[ordered]@{toolchain=$goVersion; environment=$buildEnvironment; arguments=@('test', '-mod=readonly', '-trimpath', '-c', '-o', 'conditions.test.exe', './conditions'); source='Retained source snapshot; hashes verified unchanged after build.'}; guest=$result; scope="Native Go conditions package on Server $($LabState.server_version). Syntax, round trips, caller-owned allocation/free balance, and injected native/cleanup failures. No AD policy semantic parity claim."} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $resultRoot 'native-conditions.json') -Encoding UTF8
    if ($result.exit_code -ne 0) { throw "Native condition tests failed; see $resultRoot" }
    Write-LabLog "Native condition tests passed. Results: $resultRoot"
} finally {
    try {
        if ($created) {
            Invoke-Command -Session $session -ArgumentList $targetDirectory, $targetBinary -ScriptBlock {
                param($Directory, $Executable)
                $ErrorActionPreference = 'Stop'
                if (-not ([IO.Path]::GetFullPath($Directory)).StartsWith('C:\ad-sdk-validation\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected cleanup path.' }
                Remove-Item -LiteralPath $Executable -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath (Join-Path $Directory 'reference-corpus.json') -Force -ErrorAction SilentlyContinue
                if (@(Get-ChildItem -LiteralPath $Directory -Force).Count -eq 0) { Remove-Item -LiteralPath $Directory -Force }
            }
        }
    } finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
}
