#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState,[Parameter(Mandatory)][PSCredential]$Credential,[Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
if(-not $LabState.configured -or $LabState.server_version -ne '2025'){throw 'The initial LDS fixture requires the configured Server 2025 profile.'}
$member=$LabState.machines | Where-Object role -eq member
$client=$LabState.machines | Where-Object role -eq dc2
$null=Get-OwnedVM $member $LabState
$null=Get-OwnedVM $client $LabState
$statePath=Assert-LabPath (Join-Path $LabRoot 'lds-state.json')
if(Test-Path -LiteralPath $statePath) {
    $lds=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if($lds.lab_id -ne $LabState.id -or $lds.member_id -ne $member.id -or $lds.client_id -ne $client.id){throw 'LDS fixture ownership differs from the lab manifest.'}
} else {
    $id=[guid]::NewGuid().ToString('D')
    $suffix=$id.Replace('-','').Substring(0,8).ToUpperInvariant()
    $lds=[pscustomobject][ordered]@{
        schema_version=1;id=$id;lab_id=$LabState.id;member_id=$member.id;client_id=$client.id
        member=$member.name;server="$($member.name).$($LabState.domain)";client=$client.name
        administrator=$Credential.UserName;partition='CN=SdkLds,DC=lab,DC=test';marker="ad-sdk-lds:$id"
        primary="ADSDKLDS-${suffix}-A";replica="ADSDKLDS-${suffix}-B"
        ldap_port=51300;ssl_port=51301;replica_ldap_port=51400;replica_ssl_port=51401
        phase='reserved';guest=$null
    }
    $lds | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $statePath -Encoding UTF8
}
$session=$null
try {
    $session=Wait-LabGuest $member $Credential
    $restart=Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference='Stop'
        $installed=Install-WindowsFeature -Name ADLDS -IncludeManagementTools
        if(-not $installed.Success){throw 'AD LDS feature installation failed.'}
        return $installed.RestartNeeded -eq 'Yes'
    }
    if($restart){$session=Restart-LabGuest $member $session $Credential}
    Write-LabLog "Configuring owned LDS instances on $($member.name)."
    $lds.guest=Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'guest-configure-lds.ps1') -ArgumentList ($lds | ConvertTo-Json -Depth 8 -Compress) | ConvertFrom-Json
    $lds.phase=$lds.guest.phase
    $tls=Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'guest-configure-lds-tls.ps1') -ArgumentList ($lds | ConvertTo-Json -Depth 10 -Compress) | ConvertFrom-Json
    $lds | Add-Member -Force -NotePropertyName tls -NotePropertyValue $tls
    $clientSession=$null
    try {
        $clientSession=Wait-LabGuest $client $Credential
        $trust=Invoke-Command -Session $clientSession -FilePath (Join-Path $PSScriptRoot 'guest-trust-lds-root.ps1') -ArgumentList ($lds | ConvertTo-Json -Depth 10 -Compress),($tls | ConvertTo-Json -Depth 6 -Compress) | ConvertFrom-Json
        $lds | Add-Member -Force -NotePropertyName client_tls -NotePropertyValue $trust
        $lds.phase='tls-listeners-ready'
    } finally {if($clientSession){Remove-PSSession $clientSession}}
    $readerPath=Assert-LabPath (Join-Path $LabRoot 'lds-reader.clixml')
    $readerDN="CN=SDKReader,$($lds.partition)"
    if(Test-Path -LiteralPath $readerPath) {
        $readerCredential=Import-Clixml -LiteralPath $readerPath
        if($readerCredential -isnot [PSCredential] -or $readerCredential.UserName -cne $readerDN){throw 'Stored LDS reader credential differs.'}
    } else {
        $random=New-Object byte[] 24
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try {$rng.GetBytes($random);$password='Aa9!Lds'+[BitConverter]::ToString($random).Replace('-','')} finally {$rng.Dispose();[Array]::Clear($random,0,$random.Length)}
        $readerCredential=[PSCredential]::new($readerDN,(ConvertTo-SecureString $password -AsPlainText -Force))
        $password=$null
        $readerCredential | Export-Clixml -LiteralPath $readerPath
    }
    $reader=Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'guest-seed-lds.ps1') -ArgumentList ($lds | ConvertTo-Json -Depth 10 -Compress),$readerCredential | ConvertFrom-Json
    $lds | Add-Member -Force -NotePropertyName reader -NotePropertyValue $reader
    $lds.phase='fixture-ready'
    $temporary=Assert-LabPath (Join-Path $LabRoot 'lds-state.tmp')
    $lds | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $statePath -Force
    Write-LabLog "LDS fixture phase: $($lds.phase)."
} finally {if($session){Remove-PSSession $session}}
