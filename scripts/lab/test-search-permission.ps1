#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.DirectoryServices
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'reference-search.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Search permission script syntax error.' }
foreach ($name in @('New-SearchDescriptionRule','Assert-SearchDescriptionRule','Compare-SearchPermissionProjection','Protect-SearchPermissionOutput')) {
    $helper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if (-not $helper) { throw "Missing search permission helper: $name" }
    . ([scriptblock]::Create($helper.Extent.Text))
}
function Assert-Rejected([string]$Case,[scriptblock]$Action) {
    $caught=$false
    try { & $Action } catch {$caught=$true}
    if (-not $caught) {throw "$Case unexpectedly passed."}
    Write-Output "$Case`: passed"
}
$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-111-222-333-1234')
$attribute=[guid]'11111111-2222-3333-4444-555555555555'
$rule=New-SearchDescriptionRule $sid $attribute
Assert-SearchDescriptionRule $rule $sid.Value $attribute
# Round-trip a real Windows descriptor: adding/removing the exact ACE must
# retain unrelated rights. No directory connection is involved.
$security=[DirectoryServices.ActiveDirectorySecurity]::new()
$security.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-11'),[DirectoryServices.ActiveDirectoryRights]::GenericRead,[Security.AccessControl.AccessControlType]::Allow))
$before=$security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
$security.AddAccessRule($rule)
$roundtrip=[DirectoryServices.ActiveDirectorySecurity]::new()
$roundtrip.SetSecurityDescriptorBinaryForm($security.GetSecurityDescriptorBinaryForm())
$found=@($roundtrip.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -eq $sid.Value})
if ($found.Count -ne 1) {throw 'Property ACE did not round-trip.'}
Assert-SearchDescriptionRule $found[0] $sid.Value $attribute
$roundtrip.RemoveAccessRuleSpecific($found[0])
if ($roundtrip.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne $before) {throw 'Unrelated rights changed.'}
Write-Output 'exact property ACE and other rights: passed'
foreach ($case in @('all-properties','inherited-children','allow','write-property','other-user','other-attribute')) {
    $rights=[DirectoryServices.ActiveDirectoryRights]::ReadProperty
    $type=[Security.AccessControl.AccessControlType]::Deny
    $inheritance=[DirectoryServices.ActiveDirectorySecurityInheritance]::None
    $guid=$attribute; $trustee=$sid
    switch ($case) {
        'all-properties' {$guid=[guid]::Empty}
        'inherited-children' {$inheritance=[DirectoryServices.ActiveDirectorySecurityInheritance]::All}
        'allow' {$type=[Security.AccessControl.AccessControlType]::Allow}
        'write-property' {$rights=[DirectoryServices.ActiveDirectoryRights]::WriteProperty}
        'other-user' {$trustee=[Security.Principal.SecurityIdentifier]::new('S-1-5-11')}
        'other-attribute' {$guid=[guid]'99999999-2222-3333-4444-555555555555'}
    }
    $bad=[DirectoryServices.ActiveDirectoryAccessRule]::new($trustee,$rights,$type,$guid,$inheritance)
    Assert-Rejected $case {Assert-SearchDescriptionRule $bad $sid.Value $attribute}
}
$reference=@([pscustomobject]@{case='hidden';dn='CN=hidden';guid_base64='aGlkZGVu';description=$null},[pscustomobject]@{case='visible';dn='CN=visible';guid_base64='dmlzaWJsZQ==';description='owned-marker'})
$native=[ordered]@{passed=$true;native_allocations_released=$true;username='ordinary';server='source';rows=@(
    @{case='hidden';description_state=1;object=@{DistinguishedName='CN=hidden';Attributes=@{objectguid=@('aGlkZGVu')}}},
    @{case='visible';description_state=2;object=@{DistinguishedName='CN=visible';Attributes=@{objectguid=@('dmlzaWJsZQ==');description=@([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('owned-marker')))}}},
    @{case='unloaded';description_state=0;object=@{DistinguishedName='CN=hidden';Attributes=@{objectguid=@('aGlkZGVu')}}}
)} | ConvertTo-Json -Depth 8
Compare-SearchPermissionProjection ($native | ConvertFrom-Json) $reference 'owned-marker' 'ordinary' 'source'
Write-Output 'hidden/visible/unloaded differential projection: passed'
foreach ($case in @('hidden-present','hidden-unloaded','visible-missing','guid-mismatch','dn-mismatch','duplicate-case','wrong-identity','wrong-server','resources-retained')) {
    $bad=$native | ConvertFrom-Json
    switch ($case) {
        'hidden-present' {$bad.rows[0].object.Attributes | Add-Member description @('c2VjcmV0')}
        'hidden-unloaded' {$bad.rows[0].description_state=0}
        'visible-missing' {$bad.rows[1].object.Attributes.PSObject.Properties.Remove('description')}
        'guid-mismatch' {$bad.rows[0].object.Attributes.objectguid[0]='different'}
        'dn-mismatch' {$bad.rows[0].object.DistinguishedName='CN=foreign'}
        'duplicate-case' {$bad.rows[2].case='hidden'}
        'wrong-identity' {$bad.username='Administrator'}
        'wrong-server' {$bad.server='other'}
        'resources-retained' {$bad.native_allocations_released=$false}
    }
    Assert-Rejected $case {Compare-SearchPermissionProjection $bad $reference 'owned-marker' 'ordinary' 'source'}
}
$secret=[Text.Encoding]::UTF8.GetBytes('Temporary-Test-Secret9!')
try {
    $safe=@(Protect-SearchPermissionOutput "PASS`r`n" $secret)
    if ($safe.Count -ne 1 -or $safe[0] -cne 'PASS') {throw 'Safe output changed.'}
    Assert-Rejected 'plaintext output suppression' {Protect-SearchPermissionOutput ('failure '+[Text.Encoding]::UTF8.GetString($secret)) $secret}
    Assert-Rejected 'base64 output suppression' {Protect-SearchPermissionOutput ('failure '+[Convert]::ToBase64String($secret)) $secret}
} finally {[Array]::Clear($secret,0,$secret.Length)}
