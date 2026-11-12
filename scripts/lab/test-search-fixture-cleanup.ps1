#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'reference-search.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Search fixture script syntax error.' }
$helper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-SearchFixtures'},$true)
if (-not $helper) { throw 'Search cleanup helper is missing.' }
. ([scriptblock]::Create($helper.Extent.Text))
function Test-SearchCleanup([string]$Case,[bool]$MustFail) {
    $state=@{present=($Case -ne 'absent');removals=0;ouRemovals=0;children=[Collections.Generic.List[object]]::new()}
    $ou=[pscustomobject]@{Description='owned-marker';ObjectGUID=[guid]'11111111-1111-1111-1111-111111111111';DistinguishedName='OU=owned,DC=test'}
    $state.children.Add([pscustomobject]@{Name='ADSDK-Search-0';Description='owned-marker';ObjectGUID='parent-guid';DistinguishedName='CN=ADSDK-Search-0,OU=owned,DC=test'})
    $state.children.Add([pscustomobject]@{Name='ADSDK-Nested';Description='owned-marker';ObjectGUID='nested-guid';DistinguishedName='CN=ADSDK-Nested,CN=ADSDK-Search-0,OU=owned,DC=test'})
    if ($Case -eq 'foreign-ou') { $ou.Description='foreign-marker' }
    if ($Case -eq 'foreign-child') { $state.children[0].Description='foreign-marker' }
    function Get-ADOrganizationalUnit($LDAPFilter,$SearchBase,$SearchScope,$Properties,$Server) {
        if ($Case -eq 'query-ou-fails') { throw 'Injected OU lookup failure.' }
        if ($state.present) { return $ou }
    }
    function Get-ADObject($LDAPFilter,$SearchBase,$SearchScope,$Properties,$Server) {
        if ($Case -eq 'query-children-fails') { throw 'Injected child lookup failure.' }
        return $state.children.ToArray()
    }
    function Remove-ADObject($Identity,$Server,$Confirm) {
        if ($Identity -notin @('parent-guid','nested-guid')) { throw 'Attempted removal of a foreign object.' }
        $state.removals++
        if ($Case -eq 'child-remove-fails' -and $Identity -eq 'nested-guid') { throw 'Injected removal failure.' }
        if ($Identity -eq 'parent-guid' -and @($state.children | Where-Object ObjectGUID -eq 'nested-guid').Count) { throw 'Parent removed before its nested child.' }
        if ($Case -eq 'remove-no-effect') { return }
        $child=@($state.children | Where-Object ObjectGUID -eq $Identity)[0]
        $null=$state.children.Remove($child)
    }
    function Remove-ADOrganizationalUnit($Identity,$Server,$Confirm) {
        $state.ouRemovals++
        if ($state.children.Count -or $Case -eq 'ou-remove-fails') { throw 'OU is not empty or removal failed.' }
        $state.present=$false
    }
    $guid=if ($Case -eq 'lost-response') { '' } elseif ($Case -eq 'changed-guid') { '22222222-2222-2222-2222-222222222222' } else { $ou.ObjectGUID.ToString() }
    $caught=$null
    try { Remove-SearchFixtures 'source' 'DC=test' 'owned' $guid 'owned-marker' } catch { $caught=$_ }
    if ($MustFail -and -not $caught) { throw "$Case incorrectly succeeded." }
    if (-not $MustFail -and $caught) { throw "$Case failed: $($caught.Exception.Message)" }
    if ($Case -in @('success','lost-response') -and ($state.present -or $state.children.Count)) { throw "$Case left owned fixtures." }
    if ($Case -in @('absent','foreign-ou','foreign-child','changed-guid','query-ou-fails','query-children-fails') -and ($state.removals -or $state.ouRemovals)) { throw "$Case removed an object without confirmed ownership." }
    if ($Case -eq 'child-remove-fails' -and $state.removals -ne 2) { throw 'A failed child prevented an independent cleanup attempt.' }
    Write-Output "$Case`: passed"
}
foreach ($case in @('success','absent','lost-response')) { Test-SearchCleanup $case $false }
foreach ($case in @('foreign-ou','foreign-child','changed-guid','query-ou-fails','query-children-fails','child-remove-fails','ou-remove-fails','remove-no-effect')) { Test-SearchCleanup $case $true }
