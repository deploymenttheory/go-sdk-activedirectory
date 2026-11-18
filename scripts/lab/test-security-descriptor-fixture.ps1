#Requires -Version 5.1
# Offline ownership/delegation guards only; no directory or VM calls.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach ($name in @('security-descriptor-fixture.ps1','security-descriptor-account.ps1')) {
    $tokens=$null;$parseErrors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count) {throw 'Descriptor fixture source does not parse.'}
}
. (Join-Path $PSScriptRoot 'security-descriptor-fixture.ps1')
function Assert-Rejected([scriptblock]$Operation,[string]$Name) {
    $rejected=$false
    try {& $Operation|Out-Null} catch {$rejected=$true}
    if (-not $rejected) {throw "Unsafe descriptor fixture input accepted: $Name"}
}
$run='sdk06-offline-ownership'
$names=Get-DescriptorFixtureNames $run
if ($names.sam.Length -gt 20 -or $names.sam -cne (Get-DescriptorFixtureNames $run).sam -or $names.matching_sam -ceq $names.stale_sam) {throw 'Descriptor account names are not stable and bounded.'}
foreach ($bad in @('../escape','sdk06-UPPER','sdk06-short/escape','sdk06-'+('a'*60))) {Assert-Rejected {Get-DescriptorFixtureNames $bad} 'run identity'}
Assert-Rejected {Assert-DescriptorFixturePath 'C:\adsdk-descriptor-fixtures-other\state.json'} 'sibling path'
Assert-Rejected {Assert-DescriptorFixturePath 'C:\adsdk-descriptor-fixtures\..\outside.json'} 'path traversal'
Assert-Rejected {Get-DescriptorFixtureGUIDTarget ([guid]::Empty)} 'empty GUID target'
if ((Get-DescriptorFixtureGUIDTarget ([guid]'00112233-4455-6677-8899-aabbccddeeff')) -cne '<GUID=33221100554477668899aabbccddeeff>') {throw 'GUID wire target bytes changed.'}
$script:state=[pscustomobject]@{
    schema_version=1;purpose='sdk-portable-descriptor-fixture';run_id=$run;server='adsdk25dc1.ad.sdk.test';parent_dn=$names.parent_dn;parent_guid=[guid]::NewGuid().ToString()
    actor_dn=$names.actor_dn;actor_sam=$names.sam;actor_upn=$names.upn;actor_guid=[guid]::NewGuid().ToString();phase='ready'
    accounts=@(
        [pscustomobject]@{id='matching';dn=$names.matching_dn;sam=$names.matching_sam;guid=[guid]::NewGuid().ToString()}
        [pscustomobject]@{id='stale';dn=$names.stale_dn;sam=$names.stale_sam;guid=[guid]::NewGuid().ToString()}
    )
}
$script:objects=@(
    [pscustomobject]@{ObjectGUID=$state.parent_guid;DistinguishedName=$names.parent_dn;ObjectClass='organizationalUnit';description=$names.parent_marker;sAMAccountName=$null}
    [pscustomobject]@{ObjectGUID=$state.actor_guid;DistinguishedName=$names.actor_dn;ObjectClass='user';description=$names.actor_marker;sAMAccountName=$names.sam}
    [pscustomobject]@{ObjectGUID=$state.accounts[0].guid;DistinguishedName=$names.matching_dn;ObjectClass='msDS-GroupManagedServiceAccount';description=$names.matching_marker;sAMAccountName=$names.matching_sam}
    [pscustomobject]@{ObjectGUID=$state.accounts[1].guid;DistinguishedName=$names.stale_dn;ObjectClass='msDS-GroupManagedServiceAccount';description=$names.stale_marker;sAMAccountName=$names.stale_sam}
)
Assert-DescriptorFixtureObjects $state $objects $false
Assert-DescriptorFixtureObjects $state @() $true
Assert-Rejected {Assert-DescriptorFixtureObjects $state @() $false} 'missing ready objects'
$saved=$objects[2].ObjectGUID;$objects[2].ObjectGUID=[guid]::NewGuid().ToString()
Assert-Rejected {Assert-DescriptorFixtureObjects $state $objects $false} 'replaced object GUID'
$objects[2].ObjectGUID=$saved
$saved=$objects[2].description;$objects[2].description='foreign'
Assert-Rejected {Assert-DescriptorFixtureObjects $state $objects $false} 'foreign marker'
$objects[2].description=$saved
$saved=$objects[2].DistinguishedName;$objects[2].DistinguishedName='CN=moved,DC=ad,DC=sdk,DC=test'
Assert-Rejected {Assert-DescriptorFixtureObjects $state $objects $true} 'moved object'
$objects[2].DistinguishedName=$saved
Assert-Rejected {Assert-DescriptorFixtureObjects $state @($objects+$objects[2]) $true} 'duplicate descendant'
$saved=$state.accounts[0].guid;$state.accounts[0].guid=$null
Assert-Rejected {Assert-DescriptorFixtureObjects $state $objects $true} 'unrecorded GUID outside creation intent'
$state.phase='matching-create-intent';Assert-DescriptorFixtureObjects $state $objects $true
$state.phase='ready';$state.accounts[0].guid=$saved
# An unknown child must stop the actual cleanup path before any deletion.
$script:foreign=[pscustomobject]@{ObjectGUID=[guid]::NewGuid();DistinguishedName="CN=foreign,$($names.parent_dn)";ObjectClass='user';description='foreign';sAMAccountName='foreign'}
$script:deletions=0;$script:liveChecks=0;$script:journalPresent=$true;$script:unjournaledObjects=@()
function Assert-DescriptorFixtureContext {param($RunId,$Server)}
function Assert-DescriptorFixturePath {param($Path);return $Path}
function Test-Path {[CmdletBinding()]param($LiteralPath);return $script:journalPresent}
function Get-Content {[CmdletBinding()]param($LiteralPath,[switch]$Raw);return ($script:state|ConvertTo-Json -Depth 8)}
function Get-DescriptorFixtureLiveObjects {param($State,$AllowMissing);$script:liveChecks++;$all=@($script:objects+$script:foreign);Assert-DescriptorFixtureObjects $State $all $AllowMissing;return $all}
function Get-ADObject {[CmdletBinding()]param($Server,$LDAPFilter);return $script:unjournaledObjects}
function Remove-ADObject {[CmdletBinding()]param($Server,$Identity,[switch]$Confirm);$script:deletions++}
function Remove-ADOrganizationalUnit {[CmdletBinding()]param($Server,$Identity,[switch]$Confirm);$script:deletions++}
Assert-Rejected {Remove-DescriptorDirectoryFixture $run 'adsdk25dc1.ad.sdk.test'} 'unknown child cleanup'
if ($script:deletions -ne 0 -or $script:liveChecks -ne 1) {throw 'Actual cleanup preflight did not reject the unknown child before mutation.'}
$script:journalPresent=$false
$absent=Remove-DescriptorDirectoryFixture $run 'adsdk25dc1.ad.sdk.test'
if (-not $absent.verified -or -not $absent.journal_absent -or $script:deletions -ne 0) {throw 'Unstarted journal absence was not reconciled without mutation.'}
$script:unjournaledObjects=@($objects[1])
Assert-Rejected {Remove-DescriptorDirectoryFixture $run 'adsdk25dc1.ad.sdk.test'} 'unjournaled live actor'
if ($script:deletions -ne 0) {throw 'Unjournaled identity caused a deletion.'}
# Check the exact delegated ObjectAce profile and object-capable ACL revision.
$actorSID='S-1-5-21-1-2-3-1001';$attributeGUID=[guid]::NewGuid()
$baseline=[Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:(A;;CR;;;SY)(A;;WP;;;BA)')
foreach ($ace in $baseline.DiscretionaryAcl) {if (($ace.AccessMask -band 0x10) -ne 0) {throw 'Baseline unintentionally grants editable RP.'}}
$acl=[Security.AccessControl.RawAcl]::new(4,1)
$grant=[Security.AccessControl.ObjectAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,0x30,
    [Security.Principal.SecurityIdentifier]::new($actorSID),[Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,$attributeGUID,[guid]::Empty,$false,$null)
$acl.InsertAce(0,$grant);$baseline.DiscretionaryAcl=$acl
$raw=[byte[]]::new($baseline.BinaryLength);$baseline.GetBinaryForm($raw,0)
Assert-DescriptorFixtureGrant $raw $actorSID $attributeGUID
Assert-Rejected {Assert-DescriptorFixtureGrant $raw $actorSID ([guid]::NewGuid())} 'wrong delegated attribute'
$grant.AccessMask=0x10000000
$raw=[byte[]]::new($baseline.BinaryLength);$baseline.GetBinaryForm($raw,0)
Assert-Rejected {Assert-DescriptorFixtureGrant $raw $actorSID $attributeGUID} 'broader GenericAll delegation'
Write-Output 'PASS: descriptor fixture path/GUID/marker/descendant guards, no-write rejection, and exact retrieval-attribute RP/WP delegation.'
