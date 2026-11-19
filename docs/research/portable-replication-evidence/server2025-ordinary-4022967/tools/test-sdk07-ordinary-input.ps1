# Offline fixture admission tests. Mock filesystem/DPAPI boundaries; no lab calls.
#Requires -Version 7.0
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'sdk07-ordinary-input.ps1')
$script:run='sdk07-p25-20261119t-offline1';$script:profile='11111111-1111-1111-1111-111111111111'
$script:cases=[Collections.Generic.List[string]]::new()
function Join-Path {param([string]$Path,[string]$ChildPath);[IO.Path]::Combine($Path,$ChildPath)}
function Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction);if($script:reparse){[pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint}}else{[pscustomobject]@{Attributes=[IO.FileAttributes]::Normal}}}
function Get-Content {param($LiteralPath,[switch]$Raw);if($LiteralPath.EndsWith('sdk07-ordinary-owner.json')){$script:owner|ConvertTo-Json -Depth 12}elseif($LiteralPath.EndsWith('prepare.json')){$script:prepared|ConvertTo-Json -Depth 12}else{throw 'Unexpected mock read'}}
function Get-FileHash {param($LiteralPath,$Algorithm);[pscustomobject]@{Hash=$script:digest}}
function Import-Clixml {param($LiteralPath);$script:credential}
function Reset-Fixture {
    $sha=[Security.Cryptography.SHA256]::Create();try{$bytes=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($script:run))}finally{$sha.Dispose()}
    $username='sdkkrb'+([BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()).Substring(0,12)
    $principal=$username+'@AD.SDK.TEST';$client='22222222-2222-2222-2222-222222222222';$parent='33333333-3333-3333-3333-333333333333'
    $script:prepared=@{run_id=$script:run;client_guid=$client;parent_guid=$parent;upn=$principal;sam=$username;phase='ready';policy_applied=$false}
    $script:owner=@{purpose='sdk07-ordinary-rpc-refusal';run_id=$script:run;profile_id=$script:profile;server_version='2025';phase='ready';client_guid=$client;parent_guid=$parent;credential_sha256=('a'*64);actor=@{run_id=$script:run;principal=$principal;credential_file=('H:\ad-sdk-lab\portable-kerberos\'+$script:run+'\secrets\client.clixml');policy_applied=$false};membership=@{ordinary=$true;client_guid=$client;sid='S-1-5-21-1-2-3-1100';primary_group=513;member_of=@();authorization_groups=@('S-1-5-21-1-2-3-513','S-1-5-32-545');account_group_changes=0}}
    $script:credential=[PSCredential]::new($principal,(ConvertTo-SecureString 'offline-dummy-only' -AsPlainText -Force))
    $script:reparse=$false;$script:digest='a'*64
}
function Read-Fixture {Read-Sdk07OrdinaryActor -RunId $script:run -ServerVersion '2025' -ProfileId $script:profile}
function Assert-Rejected([string]$Name,[scriptblock]$Mutate) {
    Reset-Fixture;& $Mutate
    $rejected=$false;try{$null=Read-Fixture}catch{$rejected=$true}
    if(-not$rejected){throw ('Admission accepted invalid fixture: '+$Name)}
    $script:cases.Add($Name)
}
Reset-Fixture
$actor=Read-Fixture
if(-not$actor.ordinary-or$actor.credential.UserName-cne$script:prepared.upn-or$actor.client_guid-cne$script:prepared.client_guid){throw 'Valid ordinary fixture was not preserved'}
$script:cases.Add('valid-explicit-ordinary-principal')
Reset-Fixture
$script:owner.membership.authorization_groups+=@('S-1-5-32-554','S-1-1-0','S-1-5-11','S-1-5-15','S-1-18-2','S-1-16-8192')
$actor=Read-Fixture
if(-not$actor.ordinary){throw 'Documented ordinary reference-token identities rejected'}
$script:cases.Add('documented-unprivileged-reference-token-identities')
Assert-Rejected 'wrong-owner-purpose' {$script:owner.purpose='other'}
Assert-Rejected 'cleaned-actor-cannot-run' {$script:owner.phase='cleaned'}
Assert-Rejected 'wrong-profile' {$script:owner.profile_id='other'}
Assert-Rejected 'wrong-server-version' {$script:owner.server_version='2019'}
Assert-Rejected 'changed-client-guid' {$script:prepared.client_guid='44444444-4444-4444-4444-444444444444'}
Assert-Rejected 'wrong-prepared-principal' {$script:prepared.upn='Administrator@AD.SDK.TEST'}
Assert-Rejected 'privileged-role' {$script:owner.membership.authorization_groups+=@('S-1-5-21-1-2-3-512')}
Assert-Rejected 'builtin-administrators-role' {$script:owner.membership.authorization_groups+=@('S-1-5-32-544')}
Assert-Rejected 'direct-membership' {$script:owner.membership.member_of=@('CN=Administrators')}
Assert-Rejected 'nonordinary-primary-group' {$script:owner.membership.primary_group=512}
Assert-Rejected 'unproven-role' {$script:owner.membership.ordinary=$false}
Assert-Rejected 'changed-private-file' {$script:digest='b'*64}
Assert-Rejected 'reparse-path' {$script:reparse=$true}
Assert-Rejected 'wrong-private-principal' {$script:credential=[PSCredential]::new('Administrator@AD.SDK.TEST',(ConvertTo-SecureString 'offline-dummy-only' -AsPlainText -Force))}
Assert-Rejected 'unexpected-secret-location' {$script:owner.actor.credential_file='C:\other\client.clixml'}
Assert-Rejected 'policy-changed' {$script:prepared.policy_applied=$true}
$invalid=$false;try{$null=Read-Sdk07OrdinaryActor -RunId '../outside' -ServerVersion '2025' -ProfileId $script:profile}catch{$invalid=$true}
if(-not$invalid){throw 'Invalid run escaped admission'};$script:cases.Add('invalid-run-rejected-before-reads')
[pscustomobject]@{passed=$true;checks=$script:cases.Count;cases=$script:cases;lab_calls=0;private_credentials_created=0}|ConvertTo-Json -Depth 5
