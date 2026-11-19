#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Prepare','Cleanup')][string]$Action,[string]$RunId='',[ValidateSet('2016','2019','2022','2025')][string]$ServerVersion='2025')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$lab='H:\ad-sdk-lab';$root=$PSScriptRoot
if(-not$RunId){if($Action-cne'Prepare'){throw 'Cleanup requires the original actor RunId.'};$RunId='sdk07-p'+$ServerVersion.Substring(2)+'-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ').ToLowerInvariant()}
if($RunId-cnotmatch'\Asdk07-p(16|19|22|25)-[a-z0-9-]{10,25}\z'-or-not$RunId.StartsWith(('sdk07-p'+$ServerVersion.Substring(2)+'-'),[StringComparison]::Ordinal)){throw 'Unexpected owned ordinary actor identity.'}
$helperRoot=Join-Path $root 'sdk09-live\59718ec\source\scripts\lab'
$proof=Get-Content -LiteralPath (Join-Path $root 'sdk09-live\59718ec\source-provenance.json') -Raw|ConvertFrom-Json
foreach($name in @('kerberos-account.ps1','kerberos-fixture.ps1')){if((Get-FileHash -LiteralPath (Join-Path $helperRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()-cne$proof.source_files.('scripts/lab/'+$name)){throw 'Frozen ordinary actor fixture source differs.'}}
$capture=Join-Path "$lab\portable-kerberos" $RunId;$manifest=Join-Path $capture 'sdk07-ordinary-owner.json'
$profile=Get-Content -LiteralPath "$lab\server$ServerVersion\state.json" -Raw|ConvertFrom-Json
if($profile.server_version-cne$ServerVersion-or$profile.domain-cne'ad.sdk.test'){throw 'Ordinary actor lab profile differs.'}
Import-Module Hyper-V
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if($switch.SwitchType-ne'Private'-or$switch.Notes-cne('ad-sdk-lab:'+$profile.id)){throw 'Ordinary actor requires the exact owned private switch.'}
$vms=@{};foreach($entry in $profile.machines){$vm=Get-VM -Id ([guid]$entry.id);$nic=@(Get-VMNetworkAdapter -VM $vm);if($vm.Name-cne$entry.name-or$vm.Notes-cne('ad-sdk-lab:'+$profile.id)-or$vm.State-ne'Running'-or$nic.Count-ne1-or$nic[0].SwitchId.ToString()-cne$profile.switch_id){throw 'Owned ordinary actor VM identity differs.'};$vms[$entry.role]=$vm}
$saved=Import-Clixml -LiteralPath "$lab\server$ServerVersion\credential.clixml";$admin=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
$server='adsdk'+$ServerVersion.Substring(2)+'dc1.ad.sdk.test'
if($Action-ceq'Prepare'){
    if(Test-Path -LiteralPath $capture){throw 'Fresh actor fixture required.'}
    $actor=& (Join-Path $helperRoot 'kerberos-account.ps1') -Action Prepare -ServerVersion $ServerVersion -RunId $RunId
    if($actor.policy_applied-or$actor.run_id-cne$RunId){throw 'Expected policy-unchanged ordinary actor differs.'}
    $prepared=Get-Content -LiteralPath (Join-Path $capture 'prepare.json') -Raw|ConvertFrom-Json
    $record=@{purpose='sdk07-ordinary-rpc-refusal';run_id=$RunId;profile_id=$profile.id;server_version=$ServerVersion;phase='before-ordinary-membership-proof';actor=$actor;client_guid=$prepared.client_guid;parent_guid=$prepared.parent_guid;credential_sha256=(Get-FileHash -LiteralPath $actor.credential_file -Algorithm SHA256).Hash.ToLowerInvariant()}
    $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $manifest -Encoding utf8
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $capture 'sdk07-actor-prepare-source.ps1.txt')
    $membership=Invoke-Command -VMId $vms.dc1.Id -Credential $admin -ArgumentList $prepared.client_guid,$server -ScriptBlock {
        param($guid,$server)
        $ErrorActionPreference='Stop';$env:ADPS_LoadDefaultDrive='0';Import-Module ActiveDirectory
        $user=Get-ADUser -Server $server -Identity ([guid]$guid) -Properties memberOf,primaryGroupID,SID -ErrorAction Stop
        $domain=Get-ADDomain -Server $server -ErrorAction Stop
        $groups=@(Get-ADAccountAuthorizationGroup -Server $server -Identity $user -ErrorAction Stop|ForEach-Object {$_.SID.Value})
        # Explicit unprivileged group/context SIDs observed by the reference API.
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
        $allowed=@(($domain.DomainSID.Value+'-513'),'S-1-5-32-545','S-1-5-32-554','S-1-1-0','S-1-5-11','S-1-5-15','S-1-18-2','S-1-16-8192')
        $ordinary=$user.primaryGroupID-eq513-and@($user.memberOf).Count-eq0-and@($groups|Where-Object {$_-cnotin$allowed}).Count-eq0
        [pscustomobject]@{client_guid=$user.ObjectGUID.ToString();sid=$user.SID.Value;primary_group=$user.primaryGroupID;member_of=@($user.memberOf);authorization_groups=$groups;ordinary=$ordinary;account_group_changes=0}
    }
    $membership|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $capture 'sdk07-ordinary-membership.json') -Encoding utf8
    $record.membership=$membership;if(-not$membership.ordinary){$record.phase='ordinary-role-not-established';$record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $manifest -Encoding utf8;throw 'Ordinary role not proven; clean fixture before testing.'}
    $record.phase='ready';$record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $manifest -Encoding utf8
    [pscustomobject]@{run_id=$RunId;capture=$capture;phase='ready';client_guid=$record.client_guid;ordinary=$true;policy_applied=$false}|ConvertTo-Json
}else{
    $record=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json -AsHashtable
    if($record.purpose-cne'sdk07-ordinary-rpc-refusal'-or$record.run_id-cne$RunId-or$record.profile_id-cne$profile.id-or$record.server_version-cne$ServerVersion){throw 'Ordinary cleanup owner differs.'}
    if($record.phase-cnotin@('ready','ordinary-role-not-established')){throw 'Directory cleanup already attempted; use independent read-only reconciliation instead of repeating deletes.'}
    $source=[IO.File]::ReadAllText((Join-Path $helperRoot 'kerberos-fixture.ps1'))
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $capture 'sdk07-actor-cleanup-source.ps1.txt')
    $record.phase='cleanup-intent';$record|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $manifest -Encoding utf8
    $cleanup=Invoke-Command -VMId $vms.dc1.Id -Credential $admin -ArgumentList $source,$RunId,$server,$record.client_guid,$record.parent_guid -ScriptBlock {
        param($source,$run,$server,$clientGUID,$parentGUID)
        $ErrorActionPreference='Stop';$env:ADPS_LoadDefaultDrive='0';. ([scriptblock]::Create($source))
        $removed=Remove-KerberosDirectoryFixture $run $server
        $deadline=[DateTime]::UtcNow.AddSeconds(30);$rounds=@()
        do{
            $observations=@(foreach($dc in @($server,$server.Replace('dc1.','dc2.'))){
                foreach($guid in @($clientGUID,$parentGUID)){
                    $missing=$false;try{$null=Get-ADObject -Server $dc -Identity ([guid]$guid) -ErrorAction Stop}catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{$missing=$true}
                    [pscustomobject]@{server=$dc;guid=$guid;absent=$missing}
                }
            })
            $verified=$removed.verified-and$observations.Count-eq4-and@($observations|Where-Object absent -NE $true).Count-eq0
            $rounds+=@{recorded_utc=[DateTime]::UtcNow.ToString('o');observations=$observations;verified=$verified}
            if($verified-or[DateTime]::UtcNow-ge$deadline){break};Start-Sleep -Seconds 5
        }while($true)
        [pscustomobject]@{removed=$removed;observations=$observations;rounds=$rounds;verified=$verified}
    }
    $record.cleanup=$cleanup;$record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $manifest -Encoding utf8
    if(-not$cleanup.verified){throw 'Independent both-DC ordinary actor cleanup incomplete; retain private file.'}
    $secret=[IO.Path]::GetFullPath($record.actor.credential_file);$expected=[IO.Path]::GetFullPath((Join-Path $capture 'secrets\client.clixml'))
    if($secret-cne$expected-or(Get-Item -LiteralPath $secret -Force).Attributes-band[IO.FileAttributes]::ReparsePoint-or(Get-FileHash -LiteralPath $secret -Algorithm SHA256).Hash.ToLowerInvariant()-cne$record.credential_sha256){throw 'Exact private actor leaf differs; no retirement.'}
    Remove-Item -LiteralPath $secret -Force
    $record.phase='cleaned';$record.private_credential_retired=-not(Test-Path -LiteralPath $secret);$record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $manifest -Encoding utf8
    [pscustomobject]@{run_id=$RunId;capture=$capture;phase='cleaned';verified=$true;private_credential_retired=$record.private_credential_retired}|ConvertTo-Json
}
$saved=$null;$admin=$null
