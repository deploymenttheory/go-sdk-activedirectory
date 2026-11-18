#Requires -Version 7.0
# Offline ownership-boundary tests. No Hyper-V, keys, or lab credentials are used.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'portable-linux.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'The Linux orchestration script does not parse.'}
foreach ($name in @('Assert-LinuxPath','Assert-LinuxState')) {
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if (-not $definition) {throw "Missing ownership guard: $name"}
    Invoke-Expression $definition.Extent.Text
}
function Assert-Rejected([scriptblock]$Operation,[string]$Description) {
    $rejected=$false
    try {& $Operation | Out-Null} catch {$rejected=$true}
    if (-not $rejected) {throw "Ownership guard accepted $Description."}
}
$temporary=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tmp'))
$fixture=[IO.Path]::GetFullPath((Join-Path $temporary ('portable-linux-guards-'+[guid]::NewGuid().ToString('N'))))
if (-not $fixture.StartsWith($temporary+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Test fixture escaped the repository tmp root.'}
$script:root=Join-Path $fixture 'owned'
$null=New-Item -ItemType Directory -Path $script:root
try {
    if ((Assert-LinuxPath (Join-Path $script:root 'disks\client.vhdx')) -cne (Join-Path $script:root 'disks\client.vhdx')) {throw 'An owned path was changed.'}
    Assert-Rejected {Assert-LinuxPath $script:root} 'the root directory itself'
    Assert-Rejected {Assert-LinuxPath (Join-Path $script:root '..\outside.vhdx')} 'parent traversal'
    Assert-Rejected {Assert-LinuxPath ($script:root+'-other\disk.vhdx')} 'a sibling sharing the root prefix'
    $target=Join-Path $fixture 'target';$null=New-Item -ItemType Directory -Path $target
    $junction=Join-Path $script:root 'redirect'
    $null=New-Item -ItemType Junction -Path $junction -Target $target
    try {Assert-Rejected {Assert-LinuxPath (Join-Path $junction 'disk.vhdx')} 'a reparse-point ancestor'}
    finally {Remove-Item -LiteralPath $junction -Force}
    $script:state=[pscustomobject]@{schema_version=1;root=$script:root;id=[guid]::NewGuid().ToString()
        base_disk=(Join-Path $script:root 'disks\base.vhdx');child_disk=(Join-Path $script:root 'disks\client.vhdx')
        seed_iso=(Join-Path $script:root 'secrets\seed.iso');client_key=(Join-Path $script:root 'secrets\client_ed25519')
        host_key=(Join-Path $script:root 'secrets\host_ed25519')}
    Assert-LinuxState
    $script:state.client_key=Join-Path $fixture 'unowned-key'
    Assert-Rejected {Assert-LinuxState} 'an unowned private-key location in the journal'
    $script:state.client_key=Join-Path $script:root 'secrets\client_ed25519'
    $script:state.id='------------------------------------'
    Assert-Rejected {Assert-LinuxState} 'a malformed ownership GUID'
    Write-Output 'PASS: Linux ownership guards reject traversal, sibling prefixes, reparse points, changed key paths, and invalid IDs.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    if (-not $resolved.StartsWith($temporary+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe test cleanup path.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
