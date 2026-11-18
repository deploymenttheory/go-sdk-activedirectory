#Requires -Version 5.1
# Functions only. The outer collector verifies the owned member VM and ACL first.

function Assert-PortableTlsPeerRoot([string]$RunId,[string]$Code) {
    if($RunId -cnotmatch '\A[a-z0-9][a-z0-9-]{5,47}\z'){throw 'Invalid peer fixture identity.'}
    $expected="C:\adsdk-qualification\$RunId"
    if([IO.Path]::GetFullPath($Code) -cne $expected){throw 'Peer fixture escaped its owned code directory.'}
    $parent=$expected
    while($parent){
        if((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Peer fixture cannot use a reparse point.'}
        $parent=[IO.Path]::GetDirectoryName($parent)
    }
    return $expected
}
function New-PortableTlsNegativeFixture([string]$RunId,[string]$Code,[string]$ExpectedMember) {
    $code=Assert-PortableTlsPeerRoot $RunId $Code
    $actual="$env:COMPUTERNAME.ad.sdk.test".ToLowerInvariant()
    if($ExpectedMember -cne $actual){throw 'Peer fixture is not on the expected isolated member.'}
    $path=Join-Path $code 'peer'
    if(Test-Path -LiteralPath $path){throw 'Peer certificate directory must be fresh.'}
    $binary=Join-Path $code 'tls-peer.exe'
    $ruleName="adsdk-portable-peer-$RunId"
    if(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue){throw 'Peer firewall rule must be fresh.'}
    $null=New-NetFirewallRule -Name $ruleName -DisplayName "ADSDK-portable-tls-peer:$RunId" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress '10.77.23.20' -RemoteAddress '10.77.23.30' -Program $binary -Profile Any -Enabled True
    $process=Start-Process -FilePath $binary -ArgumentList @('generate','-dir',$path,'-server',$actual) -WindowStyle Hidden -PassThru
    try {if(-not $process.WaitForExit(60000)){$process.Kill();throw 'Owned peer generation timed out.'};if($process.ExitCode -ne 0){throw 'Owned peer generation failed.'}}
    finally {$process.Dispose()}
    $manifest=Get-Content -LiteralPath (Join-Path $path 'manifest.json') -Raw | ConvertFrom-Json
    return [pscustomobject]@{run_id=$RunId;member=$actual;directory=$path;manifest=$manifest;private_keys_exported_from_guest=$false}
}
function Start-PortableTlsNegativePeer([string]$RunId,[string]$Code,[string]$Case,[string]$Mode,[string]$Label,[string]$Server) {
    $code=Assert-PortableTlsPeerRoot $RunId $Code
    if($Case -cnotin @('valid','expired','wrong-host','untrusted','refusal') -or $Mode -cnotin @('ldaps','starttls') -or $Label -cnotmatch '\A[a-z0-9-]{1,100}\z'){throw 'Invalid peer case.'}
    if($Case -eq 'refusal' -and $Mode -ne 'starttls'){throw 'Refusal requires StartTLS.'}
    $certificate=if($Case -eq 'refusal'){'valid'}else{$Case}
    $ready=Join-Path $code "$Label-ready.json";$result=Join-Path $code "$Label-peer.json"
    if((Test-Path -LiteralPath $ready) -or (Test-Path -LiteralPath $result)){throw 'Peer evidence files must be fresh.'}
    $arguments=@('serve','-mode',$Mode,'-listen','10.77.23.20:0','-cert',"$code\peer\$certificate.pem",'-key',"$code\peer\$certificate-key.pem",'-ready',$ready,'-result',$result,'-connections','1','-timeout','60s','-connection-timeout','20s')
    if($Case -eq 'refusal'){$arguments+='-refuse-starttls'}
    if($Case -eq 'valid'){$arguments+=@('-upstream',"$($Server):636",'-upstream-ca',"$code\root.pem",'-upstream-name',$Server)}
    $binary=Join-Path $code 'tls-peer.exe'
    $process=Start-Process -FilePath $binary -ArgumentList $arguments -WindowStyle Hidden -PassThru
    try {
        $until=[DateTime]::UtcNow.AddSeconds(15)
        while(-not(Test-Path -LiteralPath $ready)){
            if($process.HasExited -or [DateTime]::UtcNow -gt $until){throw 'Owned peer did not become ready.'}
            Start-Sleep -Milliseconds 100
        }
        $signal=Get-Content -LiteralPath $ready -Raw | ConvertFrom-Json
        if($signal.pid -ne $process.Id -or $signal.mode -cne $Mode -or $signal.address -cnotmatch '\A10\.77\.23\.20:[0-9]+\z'){throw 'Peer readiness identity mismatch.'}
        return [pscustomobject]@{run_id=$RunId;pid=$process.Id;binary=$binary;ready=$ready;result=$result;address=$signal.address;case=$Case;mode=$Mode}
    } finally {$process.Dispose()}
}
function Get-PortableTlsNegativePeerResult($Peer,[string]$RunId,[string]$Code) {
    $code=Assert-PortableTlsPeerRoot $RunId $Code
    if($Peer.run_id -cne $RunId -or $Peer.binary -cne "$code\tls-peer.exe"){throw 'Peer result ownership mismatch.'}
    $until=[DateTime]::UtcNow.AddSeconds(25)
    while(-not(Test-Path -LiteralPath $Peer.result)){
        if([DateTime]::UtcNow -gt $until){throw 'Owned peer did not publish its result.'}
        Start-Sleep -Milliseconds 100
    }
    return Get-Content -LiteralPath $Peer.result -Raw | ConvertFrom-Json
}
function Remove-PortableTlsNegativeFixture([string]$RunId,[string]$Code) {
    $code=Assert-PortableTlsPeerRoot $RunId $Code
    $binary=Join-Path $code 'tls-peer.exe'
    foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='tls-peer.exe'")){
        if($process.ExecutablePath -ieq $binary){
            if($process.CommandLine -notlike "*$code*" ){throw 'Peer command line ownership mismatch.'}
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
        }
    }
    $remaining=@(Get-CimInstance Win32_Process -Filter "Name='tls-peer.exe'" | Where-Object {$_.ExecutablePath -ieq $binary})
    if($remaining.Count -ne 0){throw 'Owned peer processes remain.'}
    $path=[IO.Path]::GetFullPath((Join-Path $code 'peer'))
    if($path -cne "$code\peer"){throw 'Peer deletion target escaped its owned directory.'}
    if(Test-Path -LiteralPath $path){
        foreach($item in @(Get-ChildItem -LiteralPath $path -Recurse -Force)){
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Refusing recursive peer cleanup through a reparse point.'}
        }
        Remove-Item -LiteralPath $path -Recurse -Force
    }
    $ruleName="adsdk-portable-peer-$RunId"
    $rule=Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if($rule){
        $application=$rule | Get-NetFirewallApplicationFilter
        if($rule.DisplayName -cne "ADSDK-portable-tls-peer:$RunId" -or $application.Program -ine $binary){throw 'Peer firewall rule ownership changed.'}
        $rule | Remove-NetFirewallRule
    }
    if(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue){throw 'Owned peer firewall rule remains.'}
    $keys=@(Get-ChildItem -LiteralPath $code -Filter '*-key.pem' -File -Recurse -Force)
    if($keys.Count -ne 0 -or (Test-Path -LiteralPath $path)){throw 'Owned peer private key files remain.'}
    return [pscustomobject]@{run_id=$RunId;verified=$true;owned_processes_remaining=0;owned_private_key_files_remaining=0;owned_firewall_rules_remaining=0;verified_utc=[DateTime]::UtcNow.ToString('o')}
}
