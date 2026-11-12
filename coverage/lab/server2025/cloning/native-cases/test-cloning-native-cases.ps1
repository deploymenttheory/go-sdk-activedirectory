#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Import-Functions([string]$Path,[string[]]$Names) {
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count) { throw 'Fixture source failed to parse.' }
    foreach($name in $Names) {
        $definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -eq $name)
        if($definition.Count -ne 1) { throw "Expected one fixture function: $name" }
        $definitionText=$definition[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name)
        . ([ScriptBlock]::Create($definitionText))
    }
}
Import-Functions (Join-Path $PSScriptRoot 'guest-cloning-native-cases.ps1') @('Entry-Keys','Same-Entries')
$entries=@([pscustomobject]@{type='Service';name='A'},[pscustomobject]@{type='Program';name="A`t& <"},[pscustomobject]@{type='Program';name="A`t& <"})
if(-not (Same-Entries $entries @($entries[2],$entries[0],$entries[1]))) { throw 'Order-independent equality failed.' }
if(Same-Entries $entries @($entries[0],$entries[1])) { throw 'Duplicate loss was accepted.' }
if(Same-Entries $entries @($entries[0],$entries[1],[pscustomobject]@{type='WoW64Program';name="A`t& <"})) { throw 'Registry view mismatch was accepted.' }
if(-not (Same-Entries @() @())) { throw 'Empty equality failed.' }
Import-Functions (Join-Path $PSScriptRoot 'run-cloning-native-cases.ps1') @('Assert-UnlinkedPath','Assert-OwnedController')
$profile=Join-Path $PSScriptRoot 'cloning-guard-nonexistent-profile'
$state=[pscustomobject]@{id='owned-lab';switch_id='18cf982f-8c11-45cd-8581-fc2a00648deb';switch_name='owned-private'}
$machine=[pscustomobject]@{id='a364b1d0-7868-47f1-ab29-a5e80c97aa4b';name='owned-vm'}
function Get-Content { param($LiteralPath,[switch]$Raw) return ($script:current | ConvertTo-Json) }
function Get-VMSwitch { param($Id) return $script:fakeSwitch }
function Get-VM { param($Id) return $script:fakeVM }
function Get-VMHardDiskDrive { param($VM) return $script:fakeDisks }
function Get-VMNetworkAdapter { param($VM) return $script:fakeAdapters }
function Reset-OwnedFixture {
    $script:current=[pscustomobject]@{id=$state.id;switch_id=$state.switch_id}
    $script:fakeSwitch=[pscustomobject]@{Name=$state.switch_name;Notes="ad-sdk-lab:$($state.id)";SwitchType='Private'}
    $script:fakeVM=[pscustomobject]@{Name=$machine.name;Notes="ad-sdk-lab:$($state.id)";State='Running';Path=(Join-Path $profile 'vm')}
    $script:fakeDisks=@([pscustomobject]@{Path=(Join-Path $profile 'vm\disk.vhdx')})
    $script:fakeAdapters=@([pscustomobject]@{SwitchId=[guid]$state.switch_id})
}
$checks=0
Reset-OwnedFixture
Assert-OwnedController
$checks++
foreach($mutation in @(
    { $script:current.id='different-lab' },
    { $script:fakeSwitch.SwitchType='External' },
    { $script:fakeSwitch.Notes='other-owner' },
    { $script:fakeVM.Name='other-vm' },
    { $script:fakeVM.State='Off' },
    { $script:fakeVM.Path=$PSScriptRoot },
    { $script:fakeDisks[0].Path=(Join-Path $PSScriptRoot 'unrelated.vhdx') },
    { $script:fakeDisks=@() },
    { $script:fakeAdapters=@() },
    { $script:fakeAdapters+=@([pscustomobject]@{SwitchId=[guid]$state.switch_id}) },
    { $script:fakeAdapters[0].SwitchId=[guid]::NewGuid() }
)) {
    Reset-OwnedFixture
    & $mutation
    $rejected=$false
    try { Assert-OwnedController } catch { $rejected=$true }
    if(-not $rejected) { throw "Ownership mutation $checks was accepted." }
    $checks++
}
Import-Functions (Join-Path $PSScriptRoot 'guest-cloning-native-cases.ps1') @('Run-Generation','Error-Observation')
$generationRoot=Join-Path $PSScriptRoot ('cloning-generation-negative-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $generationRoot
function Assert-LocalPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if($full -cne $generationRoot -and -not $full.StartsWith($generationRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Negative fixture escaped owned root.' }
    return $full
}
function Native-Observation { return [ordered]@{exit_code=1;error='Injected native failure';data=[pscustomobject]@{outcome='not_written'}} }
function Get-ADDCCloningExcludedApplicationList { param([switch]$GenerateXml,[string]$Path,[switch]$Force,[string]$ErrorAction) throw 'Injected reference failure' }
$record=[ordered]@{generation=@();with_programs=@()}
$generationChecks=0
try {
    Run-Generation 'same-rank-new-without-force' $generationRoot
    if($record.generation[-1].passed) { throw 'Mutual failures falsely passed fresh generation.' }
    $generationChecks++
    [IO.File]::WriteAllText((Join-Path $generationRoot 'CustomDCCloneAllowList.xml'),'owned seed')
    Run-Generation 'same-rank-existing-with-force' $generationRoot -Force
    if($record.generation[-1].passed) { throw 'Mutual failures falsely passed force generation.' }
    $generationChecks++
    Run-Generation 'same-rank-existing-without-force' $generationRoot
    if(-not $record.generation[-1].passed) { throw 'Expected rejection with unchanged bytes failed.' }
    $generationChecks++
} finally {
    $full=Assert-LocalPath (Join-Path $generationRoot 'CustomDCCloneAllowList.xml')
    if(Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Force }
    [IO.Directory]::Delete($generationRoot,$false)
}
[pscustomobject]@{passed=$true;comparison_checks=4;ownership_checks=$checks;generation_failure_checks=$generationChecks;powershell=$PSVersionTable.PSVersion.ToString()} | ConvertTo-Json
