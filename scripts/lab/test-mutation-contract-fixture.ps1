#Requires -Version 5.1
# Offline guards only: no directory, VM, credentials, or network calls.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$path=Join-Path $PSScriptRoot 'mutation-contract-fixture.ps1'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) {throw 'Mutation fixture source does not parse.'}
if (@($ast.EndBlock.Statements|Where-Object {$_ -isnot [Management.Automation.Language.FunctionDefinitionAst]}).Count) {throw 'Mutation fixture must contain functions only.'}
. $path
function Assert-MutationRejected([scriptblock]$Operation,[string]$Name) {
    $rejected=$false;try {& $Operation|Out-Null} catch {$rejected=$true}
    if (-not $rejected) {throw "Unsafe mutation fixture accepted: $Name"}
}
$run='sdk09-offline';$plan=@(Get-MutationFixturePlan $run)
if ($plan.Count -ne 12 -or @($plan.role|Select-Object -Unique).Count -ne 12) {throw 'Mutation fixture role inventory differs.'}
foreach ($bad in @('../escape','with space','bad*filter',('a'*41))) {Assert-MutationRejected {Get-MutationFixturePlan $bad} 'run identity'}
Assert-MutationRejected {Assert-MutationFixturePath 'C:\adsdk-mutation-fixtures-other\state.json'} 'sibling path'
Assert-MutationRejected {Assert-MutationFixturePath 'C:\adsdk-mutation-fixtures\..\outside.json'} 'path escape'
$state=[pscustomobject]@{schema_version=1;purpose='sdk-mutation-contract-fixture';run_id=$run;server='adsdk25dc1.ad.sdk.test';
    actor_sid='S-1-5-21-1-2-3-1001';actor_guid=[guid]::NewGuid().ToString();phase='ready';targets=@();attributes=@()}
foreach ($name in @('manager','description','member','options')) {$state.attributes+=[pscustomobject]@{name=$name;guid=[guid]::NewGuid().ToString()}}
$objects=@()
foreach ($target in $plan) {
    $guid=[guid]::NewGuid().ToString()
    $state.targets+=[pscustomobject]@{role=$target.role;dn=$target.dn;class=$target.class;sam=$target.sam;guid=$guid}
    $objects+=[pscustomobject]@{DistinguishedName=$target.dn;ObjectGUID=$guid;ObjectClass=$target.class;sAMAccountName=$target.sam;
        description=$target.marker;userAccountControl=514;member=$null;memberOf=$null;directReports=$null;manager=$null;managedBy=$null}
}
Assert-MutationFixtureObjects $state $objects $false
Assert-MutationFixtureObjects $state @() $true
Assert-MutationRejected {Assert-MutationFixtureObjects $state @() $false} 'missing ready object'
$subject=@($objects|Where-Object DistinguishedName -CEQ @($plan|Where-Object role -CEQ 'subject')[0].dn)[0]
$saved=$subject.description;$subject.description=$null
Assert-MutationFixtureObjects $state $objects $false
$subject.description='sdk09-changed-through-public-SDK'
Assert-MutationFixtureObjects $state $objects $false
$subject.description=$saved
$parent=@($objects|Where-Object ObjectClass -CEQ 'organizationalUnit')[0]
$saved=$parent.description;$parent.description='foreign'
Assert-MutationRejected {Assert-MutationFixtureObjects $state $objects $false} 'immutable parent marker'
$parent.description=$saved
$saved=$subject.ObjectGUID;$subject.ObjectGUID=[guid]::NewGuid().ToString()
Assert-MutationRejected {Assert-MutationFixtureObjects $state $objects $false} 'replaced GUID'
$subject.ObjectGUID=$saved
$saved=$subject.sAMAccountName;$subject.sAMAccountName='foreign'
Assert-MutationRejected {Assert-MutationFixtureObjects $state $objects $false} 'replaced account name'
$subject.sAMAccountName=$saved
$subject.userAccountControl=512
Assert-MutationRejected {Assert-MutationFixtureObjects $state $objects $false} 'enabled user'
$subject.userAccountControl=514
$saved=$subject.DistinguishedName;$subject.DistinguishedName='CN=moved,DC=ad,DC=sdk,DC=test'
Assert-MutationRejected {Assert-MutationFixtureObjects $state $objects $false} 'moved object'
$subject.DistinguishedName=$saved
$subject.memberOf=@('CN=foreign,DC=ad,DC=sdk,DC=test')
Assert-MutationRejected {Assert-MutationFixtureObjects $state $objects $false} 'foreign membership'
$subject.memberOf=@(@($plan|Where-Object role -CEQ 'group-allowed')[0].dn)
Assert-MutationFixtureObjects $state $objects $false
$subject.memberOf=$null
$foreign=[pscustomobject]@{DistinguishedName='CN=foreign,'+@($plan|Where-Object role -CEQ 'site')[0].dn}
Assert-MutationRejected {Assert-MutationFixtureObjects $state ($objects+@($foreign)) $false} 'foreign site child'
$saved=$state.targets[1].guid;$state.targets[1].guid=$state.targets[0].guid
Assert-MutationRejected {Assert-MutationFixtureState $state} 'duplicate pinned GUID'
$state.targets[1].guid=$saved
$saved=$state.attributes[1].guid;$state.attributes[1].guid=$state.attributes[0].guid
Assert-MutationRejected {Assert-MutationFixtureState $state} 'duplicate attribute GUID'
$state.attributes[1].guid=$saved
foreach ($role in @('subject','hidden','group-allowed','group-denied','site','settings','delete-unverified')) {
    $target=@($state.targets|Where-Object role -CEQ $role)[0]
    $acl=[Security.AccessControl.RawAcl]::new(4,8)
    $other=[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,0x10,
        [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),$false,$null)
    $acl.InsertAce($acl.Count,$other)
    foreach ($grant in Get-MutationFixtureGrantPlan $target) {$acl.InsertAce($acl.Count,(New-MutationFixtureGrant $state $grant))}
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:');$descriptor.DiscretionaryAcl=$acl
    $raw=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($raw,0)
    Assert-MutationFixtureGrant $state $target $raw
    if ((@(Get-MutationFixtureUnownedAces $raw $state.actor_sid) -join ';') -cne (Get-MutationFixtureAceBytes $other)) {throw 'Unrelated ACE observation changed.'}
    $sid=[Security.Principal.SecurityIdentifier]::new($state.actor_sid)
    $acl.InsertAce($acl.Count,[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,0x10000000,$sid,$false,$null))
    $descriptor.DiscretionaryAcl=$acl;$raw=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($raw,0)
    Assert-MutationRejected {Assert-MutationFixtureGrant $state $target $raw} 'broad actor grant'
}
[pscustomobject]@{source_parsed=$true;functions_only=$true;ownership_guards=$true;mutable_descriptions_allowed=$true;narrow_acl_guards=$true;
    domain_and_config_targets=$true;live_calls=0;subject_sam=@($plan|Where-Object role -CEQ 'subject')[0].sam}|ConvertTo-Json -Compress
