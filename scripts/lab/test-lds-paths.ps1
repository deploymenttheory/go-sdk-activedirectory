#Requires -Version 5.1
# Offline regression for the actual trust-state read/write helpers. Reparse
# metadata and link dereference are injected at the filesystem boundary, so CI
# requires neither symbolic-link privileges nor certificate-store access.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'guest-trust-lds-root.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Client trust script syntax error.'}
foreach($name in @('Assert-LDSClientTrustPath','Read-LDSClientTrustState','Write-LDSClientTrustState')) {
    $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$false)
    if(-not $function){throw "Missing trust-state helper: $name"}
    . ([scriptblock]::Create($function.Extent.Text))
}
$testRoot=[IO.Path]::GetFullPath((Join-Path $env:TEMP ('ad-sdk-lds-paths-'+[guid]::NewGuid().ToString('N'))))
$fixture=Join-Path $testRoot 'fixture'
$statePath=Join-Path $fixture 'client-trust.json'
$outside=Join-Path $testRoot 'outside.json'
$null=New-Item -ItemType Directory -Path $fixture
[IO.File]::WriteAllText($statePath,'{"phase":"reserved"}')
[IO.File]::WriteAllText($outside,'{"phase":"external-sentinel"}')
$script:reparsePath='';$script:linkedReads=0;$script:linkedWrites=0
function Get-Item($LiteralPath,[switch]$Force) {
    if($LiteralPath -eq $script:reparsePath){return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint}}
    return Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force
}
function Get-Content($LiteralPath,[switch]$Raw) {
    if($LiteralPath -eq $statePath -and $script:reparsePath){$script:linkedReads++;$LiteralPath=$outside}
    return Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -Raw:$Raw
}
function Set-Content {
    param($LiteralPath,$Encoding,[Parameter(ValueFromPipeline)]$Value)
    process {
        if($LiteralPath -eq $statePath -and $script:reparsePath){$script:linkedWrites++;$LiteralPath=$outside}
        Microsoft.PowerShell.Management\Set-Content -LiteralPath $LiteralPath -Value $Value -Encoding $Encoding
    }
}
function Expect-PathFailure([scriptblock]$Action,[string]$Message) {
    $caught=$null
    try {& $Action | Out-Null}catch{$caught=$_}
    if(-not $caught -or $caught.Exception.Message -notlike "*$Message*"){throw 'Expected trust-path rejection did not occur.'}
}
try {
    Write-LDSClientTrustState @{phase='safe'} $statePath $fixture
    if((Read-LDSClientTrustState $statePath $fixture).phase -ne 'safe'){throw 'Safe trust state roundtrip failed.'}
    foreach($link in @($statePath,$fixture)) {
        $script:reparsePath=$link
        Expect-PathFailure {Read-LDSClientTrustState $statePath $fixture} 'Reparse point'
        Expect-PathFailure {Write-LDSClientTrustState @{phase='unsafe'} $statePath $fixture} 'Reparse point'
        if($script:linkedReads -ne 0 -or $script:linkedWrites -ne 0){throw 'Linked state was dereferenced.'}
        if([IO.File]::ReadAllText($outside) -cne '{"phase":"external-sentinel"}'){throw 'External target was modified.'}
    }
    $script:reparsePath=''
    Expect-PathFailure {Write-LDSClientTrustState @{phase='unsafe'} $outside $fixture} 'outside its fixture'
    'LDS trust state containment and file/ancestor reparse guards: passed'
} finally {
    $script:reparsePath=''
    $boundary=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
    if(-not $testRoot.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($testRoot) -notmatch '^ad-sdk-lds-paths-[a-f0-9]{32}$'){throw 'Unexpected test cleanup path.'}
    foreach($item in @(Microsoft.PowerShell.Management\Get-Item -LiteralPath $testRoot)+@(Get-ChildItem -LiteralPath $testRoot -Recurse -Force)){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point in test cleanup.'}}
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
