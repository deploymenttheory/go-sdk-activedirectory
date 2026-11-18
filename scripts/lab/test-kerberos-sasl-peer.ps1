#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'kerberos-sasl-peer.ps1')

function Assert-PeerRejected([scriptblock]$Action,[string]$Name) {
    $rejected=$false
    try {& $Action} catch {$rejected=$true}
    if (-not $rejected) {throw "Peer guard accepted $Name."}
}
$run='sdk05-peer-ownership'
$case='windows-sign-tampered'
$directory="C:\adsdk-kerberos\$run\sasl-peer\$case"
$server='adsdk25dc1.ad.sdk.test'
$state=[pscustomobject]@{schema_version=1;run_id=$run;case_id=$case;server=$server;directory=$directory;binary=(Join-Path $directory 'peer.exe');binary_sha256=('a'*64);firewall_name="adsdk-sasl-$run-$case";scenario='tampered'}
Assert-KerberosSASLPeerRecord $state $run $case $directory $server
foreach ($change in @(@('run_id','foreign-run'),@('directory','C:\Windows'),@('binary','C:\foreign.exe'),@('binary_sha256','bad'),@('server','foreign.ad.sdk.test'),@('firewall_name','foreign-rule'),@('scenario','unknown'))) {
    $name=$change[0];$old=$state.$name;$state.$name=$change[1]
    Assert-PeerRejected {Assert-KerberosSASLPeerRecord $state $run $case $directory $server} $name
    $state.$name=$old
}

# Fake filter objects exercise exact rule scoping without touching a firewall.
function Get-NetFirewallPortFilter {param([Parameter(ValueFromPipeline)]$Rule) process {$script:ports}}
function Get-NetFirewallAddressFilter {param([Parameter(ValueFromPipeline)]$Rule) process {$script:addresses}}
function Get-NetFirewallApplicationFilter {param([Parameter(ValueFromPipeline)]$Rule) process {$script:applications}}
$rule=[pscustomobject]@{Name=$state.firewall_name;DisplayName=$state.firewall_name;Group=$state.firewall_name;Direction='Inbound';Action='Allow'}
$script:ports=[pscustomobject]@{LocalPort='31389';Protocol='TCP'}
$script:addresses=[pscustomobject]@{LocalAddress=@('10.77.23.10');RemoteAddress=@('10.77.23.20','10.77.23.30')}
$script:applications=[pscustomobject]@{Program=$state.binary}
Assert-KerberosSASLPeerRule $rule $state.firewall_name $state.binary
$script:addresses.RemoteAddress=@('Any')
Assert-PeerRejected {Assert-KerberosSASLPeerRule $rule $state.firewall_name $state.binary} 'a broad remote address'
$script:addresses.RemoteAddress=@('10.77.23.20','10.77.23.30')
$script:ports.LocalPort='389'
Assert-PeerRejected {Assert-KerberosSASLPeerRule $rule $state.firewall_name $state.binary} 'an unrelated service port'
$script:ports.LocalPort='31389'
$script:applications.Program='Any'
Assert-PeerRejected {Assert-KerberosSASLPeerRule $rule $state.firewall_name $state.binary} 'a broad program filter'
Write-Output 'SASL peer ownership/firewall guards PASS; no process or firewall mutation performed.'
