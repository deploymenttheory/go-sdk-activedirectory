# Pure local reference: no directory cmdlets, connections, credentials or writes.
[CmdletBinding()]
param(
    [string]$AssemblyPath = 'C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\v4.0_10.0.0.0__31bf3856ad364e35\Microsoft.ActiveDirectory.Management.dll'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.DirectoryServices
$assembly = [Reflection.Assembly]::LoadFrom($AssemblyPath)
$utility = $assembly.GetType('Microsoft.ActiveDirectory.Management.Commands.ProtectedFromDeletionUtil', $true)
$constants = $utility.GetNestedType('ACEConstants', [Reflection.BindingFlags]'NonPublic,Public')
if ($null -eq $constants) { throw 'Reference constants unavailable on this version.' }
$flags = [Reflection.BindingFlags]'Static,Public,NonPublic'
$objectRule = $constants.GetField('DeleteAndDeleteTreeAccessRule', $flags).GetValue($null)
$parentRule = $constants.GetField('DeleteChildAccessRule', $flags).GetValue($null)
foreach ($pair in @(@($objectRule, 65600), @($parentRule, 2))) {
    $rule = $pair[0]
    if ($rule.IdentityReference.Value -ne 'S-1-1-0' -or [int]$rule.ActiveDirectoryRights -ne $pair[1] -or $rule.AccessControlType.ToString() -ne 'Deny' -or $rule.InheritanceType.ToString() -ne 'None') { throw 'Reference ACL contract differs.' }
}
$descriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
$descriptor.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;RC;;;WD)')
$before = $descriptor.GetSecurityDescriptorBinaryForm()
$descriptor.AddAccessRule($objectRule)
$enabled = $descriptor.GetSecurityDescriptorBinaryForm()
$removed = $descriptor.RemoveAccessRule($objectRule)
$disabled = $descriptor.GetSecurityDescriptorBinaryForm()
if (-not $removed -or [Convert]::ToBase64String($before) -ne [Convert]::ToBase64String($disabled)) { throw 'Local reference failed to preserve unrelated access rule.' }
[pscustomobject]@{
    kind = 'local-reference-only-no-directory-qualification'
    powershell_version = $PSVersionTable.PSVersion.ToString()
    assembly_version = $assembly.GetName().Version.ToString()
    file_version = (Get-Item -LiteralPath $AssemblyPath).VersionInfo.FileVersion
    assembly_sha256 = (Get-FileHash -LiteralPath $AssemblyPath -Algorithm SHA256).Hash
    object_deny_mask = [int]$objectRule.ActiveDirectoryRights
    parent_deny_mask = [int]$parentRule.ActiveDirectoryRights
    before_base64 = [Convert]::ToBase64String($before)
    enabled_base64 = [Convert]::ToBase64String($enabled)
    disabled_base64 = [Convert]::ToBase64String($disabled)
    unrelated_rule_preserved = $true
} | ConvertTo-Json -Depth 4
