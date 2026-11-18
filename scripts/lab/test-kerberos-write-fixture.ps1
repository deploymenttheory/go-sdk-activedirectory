#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'kerberos-write-fixture.ps1')

function Assert-Rejected([scriptblock]$Action,[string]$Name) {
    $rejected=$false
    try {& $Action} catch {$rejected=$true}
    if (-not $rejected) {throw "Guard accepted $Name."}
}

$run='sdk05-offline-ownership'
$names=Get-KerberosWriteNames $run
$root=[pscustomobject]@{
    run_id=$run;server='adsdk25dc1.ad.sdk.test';parent_dn=$names.parent_dn;client_dn="CN=client,$($names.parent_dn)"
    parent_guid='11111111-1111-4111-8111-111111111111';client_guid='22222222-2222-4222-8222-222222222222'
}
$state=[pscustomobject]@{
    schema_version=1;run_id=$run;server=$root.server;parent_dn=$names.parent_dn;parent_guid=$root.parent_guid;client_guid=$root.client_guid
    client_sid='S-1-5-21-111-222-333-1001';child_dn=$names.child_dn;contact_dn=$names.contact_dn;contact_marker=$names.contact_marker;child_marker=$names.child_marker
    child_guid='33333333-3333-4333-8333-333333333333';contact_guid='44444444-4444-4444-8444-444444444444'
    description_schema_guid='55555555-5555-4555-8555-555555555555';baseline_sddl='owned-baseline';expected_sddl='owned-description-grant';phase='ready'
}
$objects=@(
    [pscustomobject]@{DistinguishedName=$root.parent_dn;ObjectGUID=$root.parent_guid;ObjectClass='organizationalUnit';description="sdk-kerberos-parent:$run"}
    [pscustomobject]@{DistinguishedName=$root.client_dn;ObjectGUID=$root.client_guid;ObjectClass='user';description="sdk-kerberos-client:$run"}
    [pscustomobject]@{DistinguishedName=$state.child_dn;ObjectGUID=$state.child_guid;ObjectClass='organizationalUnit';description=$state.child_marker}
    [pscustomobject]@{DistinguishedName=$state.contact_dn;ObjectGUID=$state.contact_guid;ObjectClass='contact';description=($names.description_prefix+'baseline');displayName=$state.contact_marker}
)
Assert-KerberosWriteObjects $root $state $objects $false
Assert-KerberosWriteACL $state $state.baseline_sddl
Assert-KerberosWriteACL $state $state.expected_sddl
Assert-Rejected {Get-KerberosWriteNames '../escape'} 'an escaping identity'
Assert-Rejected {Get-KerberosWriteNames ('a'*41)} 'an overlong identity'
Assert-Rejected {Assert-KerberosWriteACL $state 'foreign-ace'} 'a foreign ACL'
$original=$state.contact_guid
$state.contact_guid='66666666-6666-4666-8666-666666666666'
Assert-Rejected {Assert-KerberosWriteObjects $root $state $objects $false} 'a replaced contact GUID'
$state.contact_guid=$original
$original=$objects[3].displayName
$objects[3].displayName='foreign marker'
Assert-Rejected {Assert-KerberosWriteObjects $root $state $objects $false} 'a foreign immutable marker'
$objects[3].displayName=$original
$original=$objects[3].DistinguishedName
$objects[3].DistinguishedName="CN=moved,$($names.child_dn)"
Assert-Rejected {Assert-KerberosWriteObjects $root $state $objects $true} 'a moved contact'
$objects[3].DistinguishedName=$original
$foreign=[pscustomobject]@{DistinguishedName="CN=foreign,$($names.child_dn)";ObjectGUID='77777777-7777-4777-8777-777777777777';ObjectClass='contact';description='foreign';displayName='foreign'}
Assert-Rejected {Assert-KerberosWriteObjects $root $state @($objects+$foreign) $false} 'an unexpected descendant'
Assert-Rejected {Assert-KerberosWriteObjects $root $state @($objects+$objects[3]) $false} 'a duplicate object'
Assert-Rejected {Assert-KerberosWriteObjects $root $state @($objects[0..2]) $false} 'an absent active target'
Assert-KerberosWriteObjects $root $state @($objects[0..2]) $true
Assert-KerberosWriteObjects $root $state @($objects[0..1]) $true
$descriptor=[DirectoryServices.ActiveDirectorySecurity]::new()
$descriptor.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
$descriptor.SetGroup([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
$sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access
$before=$descriptor.GetSecurityDescriptorSddlForm($sections)
$copy=[DirectoryServices.ActiveDirectorySecurity]::new()
$copy.SetSecurityDescriptorSddlForm($before,$sections)
$sid=[Security.Principal.SecurityIdentifier]::new($state.client_sid)
$attribute=[guid]$state.description_schema_guid
$copy.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($sid,[DirectoryServices.ActiveDirectoryRights]::WriteProperty,[Security.AccessControl.AccessControlType]::Allow,$attribute,[DirectoryServices.ActiveDirectorySecurityInheritance]::None))
Assert-KerberosWriteGrant $copy $state.client_sid $attribute
if ($descriptor.GetSecurityDescriptorSddlForm($sections) -cne $before) {throw 'Preparing the grant mutated the retained baseline descriptor.'}
$copy.AddAccessRule([DirectoryServices.ActiveDirectoryAccessRule]::new($sid,[DirectoryServices.ActiveDirectoryRights]::GenericAll,[Security.AccessControl.AccessControlType]::Allow))
Assert-Rejected {Assert-KerberosWriteGrant $copy $state.client_sid $attribute} 'a broader delegated ACE'
Write-Output 'Kerberos write fixture ownership guards PASS; no directory mutation performed.'
