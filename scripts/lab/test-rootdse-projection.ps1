#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'test-connection.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Connection harness syntax error.' }
$helper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Convert-RootDSEReferenceValue'},$true)
if (-not $helper) { throw 'Reference projection helper missing.' }
. ([scriptblock]::Create($helper.Extent.Text))
$oid=[pscustomobject]@{Value='1.2.840.113556.1.4.800';DisplayName='LDAP_CAP_ACTIVE_DIRECTORY_OID'}
$oid | Add-Member ScriptMethod ToString { return "$($this.Value) ($($this.DisplayName))" } -Force
foreach ($name in @('supportedCapabilities','supportedControl','supportedExtension')) {
    if ((Convert-RootDSEReferenceValue $name $oid) -ne $oid.Value) { throw 'OID display text was not removed.' }
    if ((Convert-RootDSEReferenceValue $name $oid.Value) -ne $oid.Value) { throw 'Plain OID changed.' }
}
if ((Convert-RootDSEReferenceValue 'domainFunctionality' ([DayOfWeek]::Saturday)) -ne '6') { throw 'Named enum was not converted to its numeric value.' }
if ((Convert-RootDSEReferenceValue 'isSynchronized' $false) -cne 'FALSE') { throw 'Boolean normalization failed.' }
'RootDSE PowerShell projection regression passed.'

$ldsAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'reference-lds.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'LDS reference syntax error.'}
$ldsHelper=$ldsAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Convert-RootDSEReferenceValue'},$true)
if(-not $ldsHelper){throw 'LDS reference projection helper missing.'}
. ([scriptblock]::Create($ldsHelper.Extent.Text))
if((Convert-RootDSEReferenceValue 'supportedCapabilities' $oid) -ne $oid.Value -or (Convert-RootDSEReferenceValue 'supportedCapabilities' $oid.Value) -ne $oid.Value){throw 'LDS OID display text was not removed.'}
'LDS capability PowerShell projection regression passed.'
