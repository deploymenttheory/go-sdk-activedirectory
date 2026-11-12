#Requires -Version 5.1
# Offline regression: execute the reference script's actual finally block with
# mocked directory commands. No AD module, credentials, or VM is needed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'reference-conditions.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'The reference script did not parse.' }
$outerTry = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
if ($outerTry.Count -ne 1 -or $null -eq $outerTry[0].Finally) { throw 'Expected one fixture lifecycle block.' }
$cleanupText = $outerTry[0].Finally.Extent.Text
$cleanup = [scriptblock]::Create($cleanupText.Substring(1, $cleanupText.Length - 2))
$errorFunction = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ErrorDetails'
}, $false)
. ([scriptblock]::Create($errorFunction.Extent.Text))

function Test-Cleanup([string]$Case) {
    $Source = 'dc1'
    $Destination = 'dc2'
    $domain = [pscustomobject]@{DistinguishedName='DC=fixture,DC=test'}
    $policyBase = 'CN=policies,DC=fixture,DC=test'
    $marker = 'owned-fixture'
    $ouName = 'owned-ou'
    $userSam = 'owned-user'
    $createdOU = $true
    $policyNames = @('first', 'second')
    $clean = $false
    $operationFailure = [ordered]@{id='original-operation-failure'}
    $failure = $operationFailure
    $attempts = [Collections.Generic.List[string]]::new()
    $checkedServers = [Collections.Generic.List[string]]::new()
    function Get-ADAuthenticationPolicy($LDAPFilter, $Properties, $Server) {
        $description = $marker
        if ($Case -eq 'foreign-policy' -and $LDAPFilter -eq '(name=first)') { $description = 'not-owned' }
        return [pscustomobject]@{Description=$description; ObjectGUID=$LDAPFilter}
    }
    function Remove-ADAuthenticationPolicy($Identity, $Server, $Confirm) {
        $attempts.Add("policy:$Identity")
        if ($Case -eq 'policy-delete-fails' -and $Identity -eq '(name=first)') { throw 'Injected policy deletion failure.' }
    }
    function Get-ADOrganizationalUnit($LDAPFilter, $SearchBase, $Properties, $Server) {
        return [pscustomobject]@{Description=$marker; ObjectGUID='owned-ou-guid'; DistinguishedName='OU=fixture,DC=fixture,DC=test'}
    }
    function Get-ADUser($LDAPFilter, $SearchBase, $Properties, $Server) {
        return [pscustomobject]@{Description=$marker; ObjectGUID='owned-user-guid'}
    }
    function Remove-ADUser($Identity, $Server, $Confirm) { $attempts.Add("user:$Identity") }
    function Remove-ADOrganizationalUnit($Identity, $Server, $Confirm) { $attempts.Add("ou:$Identity") }
    function Get-ADObject($LDAPFilter, $SearchBase, $Server) { $checkedServers.Add($Server) }
    . $cleanup
    foreach ($expected in @('policy:(name=second)', 'user:owned-user-guid', 'ou:owned-ou-guid')) {
        if (-not $attempts.Contains($expected)) { throw "$Case skipped independent cleanup: $expected" }
    }
    if (-not $clean -or -not $checkedServers.Contains('dc1') -or -not $checkedServers.Contains('dc2')) {
        throw "$Case skipped cleanup verification."
    }
    if ($Case -eq 'success') {
        if ($failure -ne $operationFailure) { throw 'Successful cleanup replaced the original operation error.' }
    } else {
        if ($failure.operation -ne $operationFailure -or $failure.cleanup.Count -ne 1) { throw "$Case lost an operation or cleanup error." }
    }
    if ($Case -eq 'foreign-policy' -and $attempts.Contains('policy:(name=first)')) { throw 'Cleanup attempted to delete an unowned policy.' }
    Write-Output ('{0}: passed' -f $Case)
}
foreach ($case in @('success', 'policy-delete-fails', 'foreign-policy')) { Test-Cleanup $case }
