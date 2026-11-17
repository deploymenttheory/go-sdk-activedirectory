#Requires -Version 5.1
# Offline checks only: no VM, directory, or native test execution.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'source-snapshot.ps1')

function Assert-SnapshotTest([bool]$Condition,[string]$Message) {
    if (-not $Condition) {throw $Message}
}
function Assert-SnapshotRejected([scriptblock]$Action,[string]$Message) {
    $rejected=$false
    try {& $Action | Out-Null} catch {$rejected=$true}
    Assert-SnapshotTest $rejected $Message
}

$temporaryRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
$scratch=[IO.Path]::GetFullPath((Join-Path $temporaryRoot ('adsdk-snapshot-'+[guid]::NewGuid().ToString('N'))))
if (-not $scratch.StartsWith($temporaryRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected snapshot test directory.'}
$null=New-Item -ItemType Directory -Path $scratch
$junction=$null
try {
    $source=Join-Path $scratch 'source'
    $snapshot=Join-Path $scratch 'snapshot'
    $null=New-Item -ItemType Directory -Path $source,$snapshot
    $fixtures=[ordered]@{
        'go.mod'='module example.test/sdk'
        'go.sum'='synthetic dependency pins'
        'activedirectory/activedirectory.go'='package activedirectory'
        'activedirectory/internal/engine/native_windows.go'='package engine'
        'activedirectory/acceptance/lifecycle_test.go'='package acceptance'
        'activedirectory/services/users/models.go'='package users'
        'activedirectory/services/users/testdata/value.json'='{"fixture":true}'
        'conditions/native_windows.go'='package conditions'
        'dccloning/configuration.go'='package dccloning'
        'internal/coverage/coverage.go'='package coverage'
        'testdata/reference.json'='{"reference":true}'
        'coverage/inventory.json'='{"operations":[]}'
        'coverage/scenario-requirements.json'='{"operations":[]}'
    }
    foreach ($name in $fixtures.Keys) {
        $path=Join-Path $source $name
        $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
        [IO.File]::WriteAllText($path,$fixtures[$name],[Text.UTF8Encoding]::new($false))
    }
    [IO.File]::WriteAllText((Join-Path $source 'activedirectory/unrelated.exe'),'excluded build artifact')
    $historical=Join-Path $source 'coverage/lab/server2025/historical.json'
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $historical) -Force
    [IO.File]::WriteAllText($historical,'excluded historical capture')
    Copy-SDKSourceSnapshot $source $snapshot
    $hashes=Get-SDKSnapshotHashes $snapshot
    Assert-SnapshotTest ($hashes.Count -eq $fixtures.Count) 'Snapshot omitted a package/fixture or included unrelated artifacts.'
    foreach ($name in $fixtures.Keys) {
        Assert-SnapshotTest ($hashes.Contains($name)) 'Snapshot lost a relative package path.'
        Assert-SnapshotTest ($hashes[$name] -eq (Get-FileHash -LiteralPath (Join-Path $source $name)).Hash) 'Snapshot bytes differ from their source.'
    }
    $original=$hashes | ConvertTo-Json -Compress
    Assert-SnapshotRejected {Copy-SDKSourceSnapshot $source $snapshot} 'Snapshot overwrite was accepted.'
    Assert-SnapshotTest (((Get-SDKSnapshotHashes $snapshot) | ConvertTo-Json -Compress) -ceq $original) 'Overwrite rejection altered retained inputs.'
    [IO.File]::AppendAllText((Join-Path $snapshot 'activedirectory/services/users/models.go'),'// changed')
    Assert-SnapshotTest (((Get-SDKSnapshotHashes $snapshot) | ConvertTo-Json -Compress) -cne $original) 'Nested source mutation was not detected.'

    foreach ($name in @('../go.mod','/root.go','C:/root.go','activedirectory\root.go','activedirectory//root.go','activedirectory/../root.go','activedirectory/engine./root.go','activedirectory/root.go:stream')) {
        Assert-SnapshotRejected {Test-SDKSnapshotSourceName $name} 'Unsafe relative snapshot path was accepted.'
    }
    Assert-SnapshotTest (-not (Test-SDKSnapshotSourceName 'activedirectory/unrelated.exe')) 'Prepared inputs accepted an executable.'

    $outside=Join-Path $scratch 'outside'
    $null=New-Item -ItemType Directory -Path $outside
    [IO.File]::WriteAllText((Join-Path $outside 'foreign.go'),'foreign source')
    $junction=Join-Path $source 'activedirectory/linked'
    $null=New-Item -ItemType Junction -Path $junction -Target $outside
    $rejectedSnapshot=Join-Path $scratch 'rejected-snapshot'
    $null=New-Item -ItemType Directory -Path $rejectedSnapshot
    Assert-SnapshotRejected {Copy-SDKSourceSnapshot $source $rejectedSnapshot} 'Source snapshot followed a reparse point.'
    Assert-SnapshotRejected {Get-SDKSnapshotHashes $source} 'Snapshot hashing followed a reparse point.'
    Assert-SnapshotTest (@(Get-ChildItem -LiteralPath $rejectedSnapshot -Force).Count -eq 0) 'Rejected source copied partial inputs.'
    Write-Output 'Nested SDK source snapshot checks passed; no AD server or VM was contacted.'
} finally {
    # Remove the owned junction itself before enumerating the ordinary test tree.
    if ($junction -and (Test-Path -LiteralPath $junction)) {
        if (-not ([IO.Path]::GetFullPath($junction)).StartsWith($scratch+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Junction cleanup escaped its test root.'}
        # Windows PowerShell 5.1 Remove-Item can throw on an owned junction.
        # Non-recursive Directory.Delete removes the link, not its target.
        [IO.Directory]::Delete($junction)
    }
    $prefix=$scratch+[IO.Path]::DirectorySeparatorChar
    foreach ($file in @(Get-ChildItem -LiteralPath $scratch -File -Recurse -Force)) {
        if (-not ([IO.Path]::GetFullPath($file.FullName)).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {throw 'Snapshot cleanup escaped its test root.'}
        Remove-Item -LiteralPath $file.FullName
    }
    foreach ($directory in @(Get-ChildItem -LiteralPath $scratch -Directory -Recurse -Force | Sort-Object {$_.FullName.Length} -Descending)) {
        if (-not ([IO.Path]::GetFullPath($directory.FullName)).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {throw 'Snapshot cleanup escaped its test root.'}
        Remove-Item -LiteralPath $directory.FullName
    }
    Remove-Item -LiteralPath $scratch
}
