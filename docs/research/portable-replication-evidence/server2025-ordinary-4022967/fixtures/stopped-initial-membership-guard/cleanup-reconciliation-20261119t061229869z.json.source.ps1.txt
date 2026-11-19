# Read-only directory reconciliation after acknowledged fixture deletion.
# Only the exact protected credential leaf is retired after both-DC absence.
#Requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\Asdk07-p25-[a-z0-9-]{10,25}\z')][string]$RunId)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$capture=Join-Path 'H:\ad-sdk-lab\portable-kerberos' $RunId
$manifest=Join-Path $capture 'sdk07-ordinary-owner.json'
$record=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json -AsHashtable
$profile=Get-Content -LiteralPath 'H:\ad-sdk-lab\server2025\state.json' -Raw|ConvertFrom-Json
if($record.purpose-cne'sdk07-ordinary-rpc-refusal'-or$record.run_id-cne$RunId-or$record.profile_id-cne$profile.id-or$record.server_version-cne'2025'-or$record.phase-cne'cleanup-intent'-or-not$record.cleanup.removed.verified-or$record.cleanup.removed.run_id-cne$RunId-or$record.cleanup.removed.parent_guid-cne$record.parent_guid-or$record.cleanup.removed.deleted_client_guids.Count-ne1-or$record.cleanup.removed.deleted_client_guids[0]-cne$record.client_guid){throw 'Exact previously acknowledged fixture cleanup is required.'}
Import-Module Hyper-V
$entry=@($profile.machines|Where-Object role -CEQ 'dc1');if($entry.Count-ne1){throw 'Owned reconciliation DC is ambiguous.'}
$vm=Get-VM -Id ([guid]$entry[0].id);$nic=@(Get-VMNetworkAdapter -VM $vm)
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if($switch.SwitchType-ne'Private'-or$switch.Notes-cne('ad-sdk-lab:'+$profile.id)-or$vm.Name-cne$entry[0].name-or$vm.Notes-cne('ad-sdk-lab:'+$profile.id)-or$vm.State-ne'Running'-or$nic.Count-ne1-or$nic[0].SwitchId.ToString()-cne$profile.switch_id){throw 'Exact owned reconciliation VM/switch differs.'}
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ').ToLowerInvariant()
$path=Join-Path $capture ('cleanup-reconciliation-'+$stamp+'.json')
Copy-Item -LiteralPath $PSCommandPath -Destination ($path+'.source.ps1.txt')
$saved=Import-Clixml -LiteralPath 'H:\ad-sdk-lab\server2025\credential.clixml';$admin=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
try{
    $proof=Invoke-Command -VMId $vm.Id -Credential $admin -ArgumentList $record.client_guid,$record.parent_guid -ScriptBlock {
        param($client,$parent)
        $ErrorActionPreference='Stop';$env:ADPS_LoadDefaultDrive='0';Import-Module ActiveDirectory -ErrorAction Stop
        $deadline=[DateTime]::UtcNow.AddSeconds(30);$rounds=@()
        do{
            $observations=@(foreach($dc in @('adsdk25dc1.ad.sdk.test','adsdk25dc2.ad.sdk.test')){
                $root=Get-ADRootDSE -Server $dc -ErrorAction Stop
                if($root.dnsHostName-ine$dc-or$root.defaultNamingContext-cne'DC=ad,DC=sdk,DC=test'){throw 'Reconciliation directory differs.'}
                foreach($guid in @($client,$parent)){
                    $absent=$false;try{$null=Get-ADObject -Server $dc -Identity ([guid]$guid) -ErrorAction Stop}catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{$absent=$true}
                    [pscustomobject]@{server=$dc;guid=$guid;absent=$absent}
                }
            })
            $verified=$observations.Count-eq4-and@($observations|Where-Object absent -NE $true).Count-eq0
            $rounds+=@{recorded_utc=[DateTime]::UtcNow.ToString('o');observations=$observations;verified=$verified}
            if($verified-or[DateTime]::UtcNow-ge$deadline){break};Start-Sleep -Seconds 5
        }while($true)
        [pscustomobject]@{rounds=$rounds;verified=$verified;directory_deletes_submitted=0;directory_mutations=0}
    }
    $proof|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $path -Encoding utf8
    if(-not$proof.verified){throw 'Both-DC absence still incomplete; retain private credential and do not replay deletions.'}
    $secret=[IO.Path]::GetFullPath($record.actor.credential_file);$expected=[IO.Path]::GetFullPath((Join-Path $capture 'secrets\client.clixml'))
    if($secret-cne$expected){throw 'Private credential leaf differs.'}
    for($cursor=$secret;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)){if((Get-Item -LiteralPath $cursor -Force).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Credential path cannot traverse a reparse point.'}}
    if((Get-FileHash -LiteralPath $secret -Algorithm SHA256).Hash.ToLowerInvariant()-cne$record.credential_sha256){throw 'Private credential blob differs.'}
    Remove-Item -LiteralPath $secret -Force
    $record.cleanup_reconciliation=@{report=$path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();verified=$true;directory_deletes_submitted=0}
    $record.phase='cleaned';$record.private_credential_retired=-not(Test-Path -LiteralPath $secret)
    $record|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $manifest -Encoding utf8
    [pscustomobject]@{run_id=$RunId;verified=$true;directory_deletes_submitted=0;private_credential_retired=$record.private_credential_retired;report=$path}|ConvertTo-Json
}finally{$saved=$null;$admin=$null}
