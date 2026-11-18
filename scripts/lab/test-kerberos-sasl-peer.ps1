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

$temporary=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tmp'))
$fixture=Join-Path $temporary ('peer-source-guards-'+[guid]::NewGuid().ToString('N'))
if(-not$fixture.StartsWith($temporary+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe offline peer fixture.'}
$script:publicPeerRoot=Join-Path $fixture 'cache'
function Get-KerberosSASLPublicPeerRoot {return $script:publicPeerRoot}
$owner='11111111-1111-4111-8111-111111111111';$cache=Join-Path $script:publicPeerRoot $owner
$null=New-Item -ItemType Directory -Path $cache
try{
    $payload=[byte[]]@(0,1,2,255);$binary=Join-Path $cache 'peer.exe';[IO.File]::WriteAllBytes($binary,$payload)
    $hash=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    $rootState=[pscustomobject]@{run_id=$run;server=$server}
    $source=[pscustomobject]@{schema_version=1;owner_id=$owner;run_id=$run;server=$server;profile_id='22222222-2222-4222-8222-222222222222';vm_id='33333333-3333-4333-8333-333333333333';path=$binary;sha256=$hash;bytes=$payload.Length}
    $cacheOwner=$source|ConvertTo-Json|ConvertFrom-Json
    $cacheOwner|Add-Member NoteProperty purpose 'adsdk-public-sasl-peer'
    $cacheOwner|Add-Member NoteProperty phase 'complete'
    $cacheOwner|Add-Member NoteProperty private_material_staged $false
    $ownerPath=Join-Path $cache 'owner.json'
    function Write-TestPeerOwner {$cacheOwner|ConvertTo-Json|Set-Content -LiteralPath $ownerPath -Encoding utf8}
    Write-TestPeerOwner
    if((Get-KerberosSASLPublicPeerSource $rootState $source $hash)-cne$binary){throw 'Valid exact owned public peer was rejected.'}
    $script:peerMutationCalls=0
    function Get-KerberosFixtureState($RunId,$ExpectedServer){if($RunId-cne$run-or$ExpectedServer-cne$server){throw 'Unexpected offline fixture identity.'};return $rootState}
    function Assert-KerberosPolicyLease($State){}
    function New-Item {$script:peerMutationCalls++;throw 'Unexpected peer directory mutation.'}
    function New-NetFirewallRule {$script:peerMutationCalls++;throw 'Unexpected peer firewall mutation.'}
    function Start-Process {$script:peerMutationCalls++;throw 'Unexpected peer process creation.'}
    foreach($property in @('owner_id','run_id','server','profile_id','vm_id','path','sha256','bytes','phase','purpose')){
        $old=$cacheOwner.$property
        if($property-ceq'bytes'){$cacheOwner.$property=999}else{$cacheOwner.$property='foreign'}
        Write-TestPeerOwner
        Assert-PeerRejected {New-KerberosSASLPeer $run $server $case 'pass' $null $hash $source} ('changed public cache '+$property)
        $cacheOwner.$property=$old;Write-TestPeerOwner
    }
    Assert-PeerRejected {New-KerberosSASLPeer $run $server $case 'pass' $payload $hash $source} 'mixed pre-staged and transferred payloads'
    [IO.File]::WriteAllBytes($binary,[byte[]]@(9,9,9,9))
    Assert-PeerRejected {New-KerberosSASLPeer $run $server $case 'pass' $null $hash $source} 'same-size corrupted public peer bytes'
    [IO.File]::WriteAllBytes($binary,$payload)
    [IO.File]::WriteAllText((Join-Path $cache 'private.key'),'synthetic unexpected file')
    Assert-PeerRejected {New-KerberosSASLPeer $run $server $case 'pass' $null $hash $source} 'an unexpected private cache member'
    if($script:peerMutationCalls-ne0){throw 'An invalid public source mutated a directory, firewall or process.'}
    Write-Output 'PASS: real filesystem public-peer guards reject mismatched owner/run/profile/VM/path/hash/size/phase, corrupt bytes and mixed payloads before any process/firewall/directory mutation.'
}finally{
    $resolved=[IO.Path]::GetFullPath($fixture)
    if(-not$resolved.StartsWith($temporary+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe offline peer fixture cleanup.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
