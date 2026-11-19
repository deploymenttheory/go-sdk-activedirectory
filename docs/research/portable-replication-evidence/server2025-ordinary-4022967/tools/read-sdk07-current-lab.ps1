# Read-only ownership and readiness proof for the original Server2025 baseline.
#Requires -Version 7.0
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$profile=Get-Content -LiteralPath 'H:\ad-sdk-lab\server2025\state.json' -Raw|ConvertFrom-Json
if($profile.server_version-cne'2025'-or$profile.domain-cne'ad.sdk.test'){throw 'Expected Server2025 profile differs.'}
Import-Module Hyper-V
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if($switch.SwitchType-ne'Private'-or$switch.Notes-cne('ad-sdk-lab:'+$profile.id)){throw 'Expected private switch differs.'}
$saved=Import-Clixml -LiteralPath 'H:\ad-sdk-lab\server2025\credential.clixml';$admin=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
try{
    $rows=@(foreach($entry in $profile.machines){
        $vm=Get-VM -Id ([guid]$entry.id);$nic=@(Get-VMNetworkAdapter -VM $vm)
        if($vm.Name-cne$entry.name-or$vm.Notes-cne('ad-sdk-lab:'+$profile.id)-or$vm.State-ne'Running'-or$nic.Count-ne1-or$nic[0].SwitchId.ToString()-cne$profile.switch_id){throw 'Expected owned Running VM differs.'}
        $root=$null
        if($entry.role-cne'member'){
            $root=Invoke-Command -VMId $vm.Id -Credential $admin -ArgumentList $entry.name -ScriptBlock {
                param($expected)
                $ErrorActionPreference='Stop';$env:ADPS_LoadDefaultDrive='0';Import-Module ActiveDirectory -ErrorAction Stop
                if($env:COMPUTERNAME-cne$expected){throw 'Guest identity differs.'}
                $r=Get-ADRootDSE -Server ($expected+'.ad.sdk.test') -ErrorAction Stop
                $sync=@($r.isSynchronized)
                if($r.dnsHostName-ine($expected+'.ad.sdk.test')-or$r.defaultNamingContext-cne'DC=ad,DC=sdk,DC=test'-or$sync.Count-ne1-or$sync[0]-ine'TRUE'){throw 'Expected synchronized DC differs.'}
                [pscustomobject]@{host_name=$r.dnsHostName;default_nc=$r.defaultNamingContext;synchronized=$true}
            }
        }
        [pscustomobject]@{role=$entry.role;id=$vm.Id.ToString();name=$vm.Name;state=$vm.State.ToString();switch_id=$nic[0].SwitchId.ToString();directory=$root}
    })
    $helper=Join-Path $PSScriptRoot 'worktrees\sdk-auth-2016-completion\scripts\lab\portable-linux.ps1'
    $linux=& $helper Status
    if($linux.manifest.id-cne'6df04253-32aa-4dd4-8031-1dd9174ca405'-or$linux.manifest.server_version-cne'2025'-or$linux.state-ne'Running'){throw 'Owned Linux baseline differs.'}
    [pscustomobject]@{recorded_utc=[DateTime]::UtcNow.ToString('o');purpose='SDK209-current-candidate-readonly-baseline';profile_id=$profile.id;server_version='2025';machines=$rows;linux_owner=$linux.manifest.id;linux_profile=$linux.manifest.server_version;linux_state=$linux.state;directory_mutations=0;verified=$true}|ConvertTo-Json -Depth 8
}finally{$saved=$null;$admin=$null}
