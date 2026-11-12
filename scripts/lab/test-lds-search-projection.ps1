#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'reference-lds-search.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'LDS search harness syntax error.'}
$helper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Compare-LDSSearchProjection'},$true)
if (-not $helper) {throw 'LDS search projection helper missing.'}
. ([scriptblock]::Create($helper.Extent.Text))
$native='[{"DistinguishedName":"CN=one,CN=application","Attributes":{"objectguid":["AP+AAAA="],"objectclass":["Y29udGFpbmVy","dG9w"],"description":["b3duZWQ="]}},{"DistinguishedName":"CN=two,CN=application","Attributes":{"objectguid":["AP+AAAE="],"objectclass":["dG9w","Y29udGFpbmVy"]}}]'
$reference='[{"dn":"cn=TWO,cn=application","attributes":{"objectclass":["Y29udGFpbmVy","dG9w"],"objectguid":["AP+AAAE="]}},{"dn":"cn=ONE,cn=application","attributes":{"description":["b3duZWQ="],"objectclass":["dG9w","Y29udGFpbmVy"],"objectguid":["AP+AAAA="]}}]'
Compare-LDSSearchProjection ($native | ConvertFrom-Json) ($reference | ConvertFrom-Json)
Compare-LDSSearchProjection @(($native | ConvertFrom-Json)[1]) ($reference | ConvertFrom-Json) -Subset
Write-Output 'unsorted raw projection and unsorted limited member: passed'
foreach ($case in @('missing-object','duplicate-object','unexpected-object','guid-mismatch','attribute-omitted','hidden-became-present','value-count','limit-overrun')) {
    $bad=$native | ConvertFrom-Json;$subset=$false
    switch ($case) {
        'missing-object' {$bad=@($bad[0])}
        'duplicate-object' {$bad[1]=$bad[0]}
        'unexpected-object' {$bad[1].DistinguishedName='CN=foreign'}
        'guid-mismatch' {$bad[0].Attributes.objectguid[0]='different'}
        'attribute-omitted' {$bad[0].Attributes.PSObject.Properties.Remove('description')}
        'hidden-became-present' {$bad[1].Attributes | Add-Member description @('b3duZWQ=')}
        'value-count' {$bad[0].Attributes.objectguid+=@('AP+AAAA=')}
        'limit-overrun' {$subset=$true}
    }
    $caught=$false
    try {Compare-LDSSearchProjection $bad ($reference | ConvertFrom-Json) -Subset:$subset} catch {$caught=$true}
    if (-not $caught) {throw "$case incorrectly passed."}
    Write-Output "$case`: passed"
}
