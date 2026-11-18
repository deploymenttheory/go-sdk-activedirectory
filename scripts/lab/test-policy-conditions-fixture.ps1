#Requires -Version 5.1
# Offline only: no AD, VM, credential, or network calls.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$path=Join-Path $PSScriptRoot 'policy-conditions-fixture.ps1'
$tokens=$null;$parseErrors=$null
$null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) {throw 'Policy fixture source does not parse.'}
. $path
function Assert-PolicyRejected([scriptblock]$Operation,[string]$Name) {
    $rejected=$false
    try {& $Operation|Out-Null} catch {$rejected=$true}
    if (-not $rejected) {throw "Unsafe policy fixture input accepted: $Name"}
}
$run='sdk08-offline-case'
$plan=@(Get-PolicyConditionTargets $run)
if ($plan.Count -ne 4 -or @($plan|Where-Object {$_.dn -cnotlike '*,CN=Configuration,DC=ad,DC=sdk,DC=test'}).Count) {throw 'Policy target partition differs.'}
foreach ($bad in @('../escape','space identity','bad*filter',('a'*41))) {Assert-PolicyRejected {Get-PolicyConditionTargets $bad} 'run identity'}
Assert-PolicyRejected {Assert-PolicyConditionPath 'C:\adsdk-policy-fixtures-other\state.json'} 'sibling path'
Assert-PolicyRejected {Assert-PolicyConditionPath 'C:\adsdk-policy-fixtures\..\outside.json'} 'path traversal'
$script:state=[pscustomobject]@{
    schema_version=1;purpose='sdk-policy-condition-fixture';run_id=$run;server='adsdk25dc1.ad.sdk.test';actor_sid='S-1-5-21-1-2-3-1001'
    phase='ready';journal_index=0;updated_utc=$null;targets=@();reference_schema=@();reference_checks=@()
}
$script:objects=@()
foreach ($target in $plan) {
    $guid=[guid]::NewGuid().ToString()
    $state.targets+=[pscustomobject]@{role=$target.role;dn=$target.dn;class=$target.class;marker=$target.marker;guid=$guid}
    $objects+=[pscustomobject]@{
        DistinguishedName=$target.dn;ObjectClass=$target.class;description=$target.marker;ObjectGUID=$guid
        'msDS-AuthNPolicyEnforced'=$false;'msDS-AssignedAuthNPolicyBL'=$null;'msAuthz-MemberRulesInCentralAccessPolicyBL'=$null
        'msDS-UserAuthNPolicyBL'=$null;'msDS-ComputerAuthNPolicyBL'=$null;'msDS-ServiceAuthNPolicyBL'=$null
    }
}
Assert-PolicyConditionObjects $state $objects $false
Assert-PolicyConditionObjects $state @() $true
Assert-PolicyRejected {Assert-PolicyConditionObjects $state @() $false} 'missing ready object'
$saved=$objects[0].description;$objects[0].description='foreign'
Assert-PolicyRejected {Assert-PolicyConditionObjects $state $objects $true} 'foreign marker'
$objects[0].description=$saved
$saved=$objects[0].ObjectGUID;$objects[0].ObjectGUID=[guid]::NewGuid().ToString()
Assert-PolicyRejected {Assert-PolicyConditionObjects $state $objects $true} 'replaced GUID'
$objects[0].ObjectGUID=$saved
$objects[0].'msDS-AssignedAuthNPolicyBL'=@('CN=account,DC=ad,DC=sdk,DC=test')
Assert-PolicyRejected {Assert-PolicyConditionObjects $state $objects $true} 'assigned authentication policy'
$objects[0].'msDS-AssignedAuthNPolicyBL'=$null
foreach ($name in @('msDS-UserAuthNPolicyBL','msDS-ComputerAuthNPolicyBL','msDS-ServiceAuthNPolicyBL')) {
    $objects[0].$name=@('CN=unexpected-silo,CN=Configuration,DC=ad,DC=sdk,DC=test')
    Assert-PolicyRejected {Assert-PolicyConditionObjects $state $objects $true} 'silo policy association'
    $objects[0].$name=$null
}
$objects[0].PSObject.Properties.Remove('msDS-UserAuthNPolicyBL')
Assert-PolicyRejected {Assert-PolicyConditionObjects $state $objects $true} 'unobserved requested backlink'
$objects[0]|Add-Member -MemberType NoteProperty -Name 'msDS-UserAuthNPolicyBL' -Value $null
$objects[2].'msAuthz-MemberRulesInCentralAccessPolicyBL'=@('CN=effective-policy,CN=Configuration,DC=ad,DC=sdk,DC=test')
Assert-PolicyRejected {Assert-PolicyConditionObjects $state $objects $true} 'linked central rule'
$objects[2].'msAuthz-MemberRulesInCentralAccessPolicyBL'=$null
$objects[0].'msDS-AuthNPolicyEnforced'=$true
Assert-PolicyRejected {Assert-PolicyConditionObjects $state $objects $true} 'enforced policy'
$objects[0].'msDS-AuthNPolicyEnforced'=$false
$saved=$state.targets[0].guid;$state.targets[0].guid=$null
Assert-PolicyRejected {Assert-PolicyConditionObjects $state $objects $true} 'unrecorded GUID'
$state.phase='auth-create-intent';Assert-PolicyConditionObjects $state $objects $true
$state.phase='ready';$state.targets[0].guid=$saved
# Inspect actual Windows ObjectAce bytes, including deny/refusal fixtures.
$actor=[Security.Principal.SecurityIdentifier]::new($state.actor_sid)
$attributes=@([pscustomobject]@{name='first';guid=[guid]::NewGuid()},[pscustomobject]@{name='second';guid=[guid]::NewGuid()})
foreach ($denied in @($false,$true)) {
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:')
    $acl=[Security.AccessControl.RawAcl]::new(4,3)
    $acl.InsertAce(0,[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,0x10,$actor,$false,$null))
    $qualifier=[Security.AccessControl.AceQualifier]::AccessAllowed
    if ($denied) {$qualifier=[Security.AccessControl.AceQualifier]::AccessDenied}
    foreach ($attribute in $attributes) {
        $acl.InsertAce($acl.Count,[Security.AccessControl.ObjectAce]::new([Security.AccessControl.AceFlags]::None,$qualifier,0x20,$actor,
            [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,$attribute.guid,[guid]::Empty,$false,$null))
    }
    $descriptor.DiscretionaryAcl=$acl
    $raw=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($raw,0)
    Assert-PolicyConditionGrant $raw $state.actor_sid $attributes $denied
    Assert-PolicyRejected {Assert-PolicyConditionGrant $raw $state.actor_sid $attributes (-not $denied)} 'reversed allow/deny qualifier'
    $acl[1].AccessMask=0x10000000;$descriptor.GetBinaryForm($raw,0)
    Assert-PolicyRejected {Assert-PolicyConditionGrant $raw $state.actor_sid $attributes $denied} 'GenericAll instead of attribute WP'
}
# Exercise the real cleanup preflight. The remote result contains a foreign
# object in the selected namespace: no deletion or state mutation may occur.
$script:deletions=0;$script:saves=0;$script:searchBases=@();$script:searchServers=@();$script:referenceHit=$false;$script:badSchema=$false
$script:foreign=[pscustomobject]@{DistinguishedName='CN=foreign,CN=Configuration,DC=ad,DC=sdk,DC=test';ObjectClass='container';ObjectGUID=[guid]::NewGuid();description='foreign'}
function Assert-PolicyConditionContext {param($RunId,$Server)}
function Assert-PolicyConditionPath {param($Path);return $Path}
function Test-Path {[CmdletBinding()]param($LiteralPath,$PathType);return $true}
function Get-Content {[CmdletBinding()]param($LiteralPath,[switch]$Raw);return ($script:state|ConvertTo-Json -Depth 12)}
function Get-ADObject {
    [CmdletBinding()]param($Server,$SearchBase,$SearchScope,$LDAPFilter,$Properties,$ResultSetSize)
    $script:searchBases+=,$SearchBase;$script:searchServers+=,$Server
    if ($LDAPFilter.Contains('(description=')) {return @($script:objects)+@($script:foreign|Where-Object {$null -ne $_})}
    if ($LDAPFilter.Contains('(objectClass=attributeSchema)')) {
        foreach ($pair in Get-PolicyConditionReferencePairs) {
            foreach ($name in @($pair.forward,$pair.back)) {
                if (-not $LDAPFilter.Contains('(lDAPDisplayName='+$name+')')) {continue}
                $link=$pair.link_id;if ($name -ceq $pair.back) {$link++};if ($script:badSchema) {$link+=2}
                return [pscustomobject]@{lDAPDisplayName=$name;linkID=$link;schemaIDGUID=[guid]::NewGuid().ToByteArray();isDefunct=$false}
            }
        }
        throw 'Unexpected schema query in policy fixture guard.'
    }
    if ($script:referenceHit) {return [pscustomobject]@{ObjectGUID=[guid]::NewGuid();DistinguishedName='CN=unexpected-silo,CN=Configuration,DC=ad,DC=sdk,DC=test'}}
    return @()
}
function Remove-ADObject {
    [CmdletBinding()]param($Server,$Identity,[switch]$Confirm)
    if ($Identity -isnot [guid] -or @($script:objects|Where-Object {([guid]$_.ObjectGUID) -eq $Identity}).Count -ne 1) {throw 'Cleanup failed to use an exact recorded GUID.'}
    $script:deletions++;$script:objects=@($script:objects|Where-Object {([guid]$_.ObjectGUID) -ne $Identity})
}
function Save-PolicyConditionState {param($State,$Phase);$script:saves++}
Assert-PolicyRejected {Remove-PolicyConditionFixture $run 'adsdk25dc1.ad.sdk.test'} 'foreign object before deletion'
if ($deletions -ne 0 -or $saves -ne 0 -or $searchBases.Count -ne 1 -or $searchBases[0] -cne 'CN=Configuration,DC=ad,DC=sdk,DC=test') {
    throw 'Cleanup did not reject a foreign config-NC object before any mutation.'
}
$script:foreign=$null
$script:badSchema=$true
Assert-PolicyRejected {Remove-PolicyConditionFixture $run 'adsdk25dc1.ad.sdk.test'} 'unknown reference linkID metadata'
$script:badSchema=$false;$script:referenceHit=$true
Assert-PolicyRejected {Remove-PolicyConditionFixture $run 'adsdk25dc1.ad.sdk.test'} 'independent forward-link association'
if ($deletions -ne 0 -or $saves -ne 0) {throw 'Schema/reference refusal occurred after cleanup mutation.'}
$script:referenceHit=$false
$cleanup=Remove-PolicyConditionFixture $run 'adsdk25dc1.ad.sdk.test'
if (-not $cleanup.verified -or $deletions -ne 4 -or $cleanup.observations.Count -ne 2 -or
    @($cleanup.observations|Where-Object {$_.search_base -cne 'CN=Configuration,DC=ad,DC=sdk,DC=test'}).Count -ne 0 -or
    'adsdk25dc2.ad.sdk.test' -cnotin $searchServers) {throw 'Exact GUID cleanup or independent config-NC two-DC verification was lost.'}
Write-Output 'PASS: policy fixture target/partition/GUID/marker/audit/linkage guards; exact RP and attribute-WP allow/deny ACEs; no-delete foreign preflight.'
