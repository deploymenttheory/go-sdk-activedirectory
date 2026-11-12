#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ModulePath,
    [string]$ReferencePath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ReferencePath) { $ReferencePath = Join-Path $PSScriptRoot '..\..\coverage\reference.json' }
$reference = Get-Content -LiteralPath $ReferencePath -Raw | ConvertFrom-Json
$installed = Get-Content -LiteralPath $ModulePath -Raw | ConvertFrom-Json
if ($installed.schema_version -ne 1 -or -not $installed.module_version -or -not $installed.server_build -or -not $installed.commands.Count) { throw 'Missing installed-module provenance or commands.' }

function Index-ByName($Items) {
    $index = @{}
    foreach ($item in $Items) {
        if (-not $item.name -or $index.ContainsKey($item.name)) { throw "Missing or duplicate name: $($item.name)" }
        $index[$item.name] = $item
    }
    return $index
}
function Get-SetName([string]$Name) {
    if ($Name -eq '__AllParameterSets') { return 'Default' }
    return $Name -replace ' \(Default\)$', ''
}
function Get-Signature($Parameters) { return (@($Parameters | Sort-Object) -join '|').ToLowerInvariant() }

$referenceCommands = Index-ByName $reference.commands
$installedCommands = Index-ByName $installed.commands
$differences = @()
$aliases = @()
foreach ($name in @($referenceCommands.Keys | Sort-Object)) {
    if (-not $installedCommands.ContainsKey($name)) {
        $differences += [ordered]@{cmdlet=$name; kind='command_missing_from_module'}
        continue
    }
    $expected = $referenceCommands[$name]
    $actual = $installedCommands[$name]
    $missing = @($expected.parameters | Where-Object { $_ -notin $actual.parameters } | Sort-Object)
    $extra = @($actual.parameters | Where-Object { $_ -notin $expected.parameters } | Sort-Object)
    if ($missing.Count -or $extra.Count) { $differences += [ordered]@{cmdlet=$name; kind='command_parameters'; reference_only=$missing; module_only=$extra} }
    $null = Index-ByName $actual.parameter_sets
    $matched = @{}
    foreach ($expectedSet in $expected.parameter_sets) {
        $candidates = @($actual.parameter_sets | Where-Object { (Get-SetName $_.name) -eq (Get-SetName $expectedSet.name) })
        if ($candidates.Count -eq 0) {
            $candidates = @($actual.parameter_sets | Where-Object { (Get-Signature $_.parameters) -eq (Get-Signature $expectedSet.parameters) })
        }
        if ($candidates.Count -eq 0 -and $expected.parameter_sets.Count -eq 1 -and $actual.parameter_sets.Count -eq 1) { $candidates = @($actual.parameter_sets[0]) }
        if ($candidates.Count -ne 1 -or $matched.ContainsKey($candidates[0].name)) {
            $differences += [ordered]@{cmdlet=$name; kind='parameter_set_unmatched'; reference_set=$expectedSet.name}
            continue
        }
        $actualSet = $candidates[0]
        $matched[$actualSet.name] = $true
        if ($expectedSet.name -ne $actualSet.name) { $aliases += [ordered]@{cmdlet=$name; reference_set=$expectedSet.name; module_set=$actualSet.name} }
        $missing = @($expectedSet.parameters | Where-Object { $_ -notin $actualSet.parameters } | Sort-Object)
        $extra = @($actualSet.parameters | Where-Object { $_ -notin $expectedSet.parameters } | Sort-Object)
        if ($missing.Count -or $extra.Count) { $differences += [ordered]@{cmdlet=$name; kind='parameter_set_parameters'; reference_set=$expectedSet.name; module_set=$actualSet.name; reference_only=$missing; module_only=$extra} }
    }
    foreach ($actualSet in $actual.parameter_sets) {
        if (-not $matched.ContainsKey($actualSet.name)) { $differences += [ordered]@{cmdlet=$name; kind='parameter_set_only_in_module'; module_set=$actualSet.name} }
    }
}
foreach ($name in @($installedCommands.Keys | Sort-Object)) {
    if (-not $referenceCommands.ContainsKey($name)) { $differences += [ordered]@{cmdlet=$name; kind='command_only_in_module'} }
}
[ordered]@{
    reference_commit=$reference.commit; module_version=$installed.module_version; server_build=$installed.server_build
    reference_commands=$referenceCommands.Count; module_commands=$installedCommands.Count
    differences=$differences; parameter_set_name_mappings=$aliases
    scope='Surface comparison only; differences require review and do not change SDK coverage states.'
} | ConvertTo-Json -Depth 8
