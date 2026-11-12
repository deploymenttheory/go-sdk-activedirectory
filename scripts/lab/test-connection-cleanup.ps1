#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'test-connection-denial.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Denial helper syntax error.' }
$helper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-LabDenialUser'},$true)
if (-not $helper) { throw 'Owned-account cleanup helper missing.' }
. ([scriptblock]::Create($helper.Extent.Text))
function Test-DenialCleanup([string]$Case, [bool]$MustFail) {
    $state=@{present=($Case -ne 'not-created');removals=0;lookups=0}
    $user=[pscustomobject]@{Name='owned-user';Description='owned-marker';SID=[pscustomobject]@{Value='owned-sid'}}
    if ($Case -eq 'foreign-marker') { $user.Description='foreign' }
    if ($Case -eq 'changed-sid') { $user.SID.Value='foreign-sid' }
    function Get-LocalUser($Name,$SID,$ErrorAction) {
        $state.lookups++
        if ($ErrorAction -ne 'Stop') { throw 'Lookup must terminate on failure.' }
        if (($Case -eq 'initial-lookup-fails' -and $state.lookups -eq 1) -or ($Case -eq 'final-lookup-fails' -and $state.lookups -eq 2)) { throw 'Injected SAM lookup failure.' }
        if ($state.present) { return $user }
    }
    function Remove-LocalUser($SID) {
        if ($SID -ne 'owned-sid') { throw 'Attempted deletion of foreign SID.' }
        $state.removals++
        if ($Case -eq 'remove-fails') { throw 'Injected removal failure.' }
        if ($Case -ne 'remove-no-effect') { $state.present=$false }
    }
    $caught=$null
    try { Remove-LabDenialUser $(if ($Case -eq 'lost-response') { '' } else { 'owned-sid' }) 'owned-user' 'owned-marker' } catch { $caught=$_ }
    if ($MustFail -and -not $caught) { throw "$Case incorrectly reported cleanup success." }
    if (-not $MustFail -and $caught) { throw "$Case failed: $($caught.Exception.Message)" }
    $expectedRemovals=if ($Case -in @('owned','lost-response','remove-fails','remove-no-effect','final-lookup-fails')) { 1 } else { 0 }
    if ($state.removals -ne $expectedRemovals) { throw "$Case performed an unexpected number of removals." }
    if ($Case -in @('owned','lost-response') -and $state.present) { throw "$Case did not remove the fixture." }
    Write-Output "$Case`: passed"
}
Test-DenialCleanup 'owned' $false
Test-DenialCleanup 'lost-response' $false
Test-DenialCleanup 'not-created' $false
Test-DenialCleanup 'foreign-marker' $true
Test-DenialCleanup 'changed-sid' $true
Test-DenialCleanup 'remove-fails' $true
Test-DenialCleanup 'remove-no-effect' $true
Test-DenialCleanup 'initial-lookup-fails' $true
Test-DenialCleanup 'final-lookup-fails' $true
$failureHelper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Add-DenialFailure'},$true)
if (-not $failureHelper) { throw 'Failure collection helper missing.' }
. ([scriptblock]::Create($failureHelper.Extent.Text))
$proof=[ordered]@{passed=$true;error=$null}
Add-DenialFailure $proof 'operation failure'
Add-DenialFailure $proof 'session cleanup failure'
Add-DenialFailure $proof 'account cleanup failure'
if ($proof.passed -or $proof.error -ne 'operation failure; session cleanup failure; account cleanup failure') { throw 'Original or cleanup error was lost.' }
Write-Output 'preserve-errors: passed'
