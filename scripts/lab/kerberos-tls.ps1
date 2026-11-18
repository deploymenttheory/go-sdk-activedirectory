# Host-side owned TLS preparation/cleanup for a prepared Kerberos lab account.
#Requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Prepare','Cleanup')][string]$Action='Prepare',
    [Parameter(Mandatory)][string]$RunId,
    [ValidateSet('2016','2019','2022','2025')][string]$ServerVersion='2025',
    [string]$LabRoot='H:\ad-sdk-lab'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($RunId -cnotmatch '\A[a-z0-9][a-z0-9-]{5,39}\z'){throw 'Invalid owned TLS run.'}
$source=Join-Path $PSScriptRoot 'portable-tls-fixture.ps1'
$profileRoot=[IO.Path]::GetFullPath((Join-Path $LabRoot ('server'+$ServerVersion)))
$profile=Get-Content -LiteralPath (Join-Path $profileRoot 'state.json') -Raw|ConvertFrom-Json
if([IO.Path]::GetFullPath($profile.root)-cne$profileRoot-or$profile.server_version-cne$ServerVersion-or$profile.domain-cne'ad.sdk.test'){throw 'Owned TLS lab profile differs.'}
$capture=Join-Path (Join-Path $LabRoot 'portable-kerberos') $RunId
$prepared=Get-Content -LiteralPath (Join-Path $capture 'prepare.json') -Raw|ConvertFrom-Json
Import-Module Hyper-V
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if($switch.SwitchType-ne'Private'-or$switch.Name-cne('ad-sdk-'+$ServerVersion)-or$switch.Notes-cne("ad-sdk-lab:"+$profile.id)){throw 'Owned TLS private switch differs.'}
$dc=@($profile.machines|Where-Object role -CEQ 'dc1')
if($dc.Count -ne 1 -or $prepared.run_id -cne $RunId){throw 'Unexpected isolated lab/fixture identity.'}
$vm=Get-VM -Id ([guid]$dc[0].id);$nics=@(Get-VMNetworkAdapter -VM $vm)
if($vm.Name -cne $dc[0].name -or $vm.Notes -cne "ad-sdk-lab:$($profile.id)" -or $vm.State -ne 'Running' -or $nics.Count -ne 1 -or $nics[0].SwitchId.ToString() -cne $profile.switch_id){throw 'Owned DC identity changed.'}
$saved=Import-Clixml -LiteralPath (Join-Path $profileRoot 'credential.clixml')
$admin=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
$guestSource="C:\adsdk-kerberos-code\$RunId\portable-tls-fixture.ps1"
$session=New-PSSession -VMId $vm.Id -Credential $admin
$ready=$false
try{
    if($Action -ceq 'Prepare'){
        Invoke-Command -Session $session -ArgumentList $guestSource -ScriptBlock {param($path);if(Test-Path -LiteralPath $path){throw 'Fresh fixture source required.'};$parent=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($path));if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Unsafe fixture code path.'}}
        Copy-Item -LiteralPath $source -Destination $guestSource -ToSession $session
        Copy-Item -LiteralPath $source -Destination (Join-Path $capture 'portable-tls-fixture.ps1')
    }
    $digest=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $state=Invoke-Command -Session $session -ArgumentList $guestSource,$digest,$RunId,$prepared.server,$Action,$ServerVersion -ScriptBlock {
        param($source,$expected,$run,$server,$action,$version)
        $ErrorActionPreference='Stop'
        if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash-cne$expected){throw 'TLS helper digest differs.'}
        . $source
        if($action -ceq 'Prepare'){New-PortableTlsFixture $run $server ('server'+$version)}else{Remove-PortableTlsFixture $run $server}
    }
    $state|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $capture ('tls-'+$Action.ToLowerInvariant()+'.json')) -Encoding utf8
    if($Action -ceq 'Prepare'){
        Copy-Item -LiteralPath $state.ca_public_file -Destination (Join-Path $capture 'root.pem') -FromSession $session
        if(-not $state.readiness.verified -or $state.private_keys_exported){throw 'Owned TLS readiness failed.'}
    }
    $ready=$true
    $state
}finally{
    try{
        if($Action-ceq'Prepare'-and-not$ready){
            $cleanup=Invoke-Command -Session $session -ArgumentList $guestSource,$RunId,$prepared.server -ScriptBlock {param($source,$run,$server);$ErrorActionPreference='Stop';. $source;$directory=Get-PortableTlsFixtureDirectory $run;if(Test-Path -LiteralPath (Join-Path $directory 'fixture.json')){Remove-PortableTlsFixture $run $server}}
            $cleanup|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $capture 'tls-prepare-failure-cleanup.json') -Encoding utf8
        }
    }finally{Remove-PSSession $session}
}
