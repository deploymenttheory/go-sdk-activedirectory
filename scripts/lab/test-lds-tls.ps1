#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState,[Parameter(Mandatory)][PSCredential]$Credential,[Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
$lds=Get-Content -LiteralPath (Assert-LabPath (Join-Path $LabRoot 'lds-state.json')) -Raw | ConvertFrom-Json
$client=$LabState.machines | Where-Object role -eq dc2
$member=$LabState.machines | Where-Object role -eq member
foreach($machine in @($client,$member)){$null=Get-OwnedVM $machine $LabState}
if($lds.lab_id -ne $LabState.id -or $lds.client_id -ne $client.id -or $lds.member_id -ne $member.id -or $lds.phase -ne 'fixture-ready' -or $client.ip -ne '10.77.23.11' -or $member.ip -ne '10.77.23.20' -or $lds.server -ine 'ADSDK25MEM.ad.sdk.test'){throw 'Complete the owned Server 2025 LDS fixture before TLS qualification.'}
$reader=Import-Clixml -LiteralPath (Assert-LabPath (Join-Path $LabRoot 'lds-reader.clixml'))
if($reader -isnot [PSCredential] -or $reader.UserName -cne $lds.reader.dn){throw 'TLS fixture reader identity differs.'}
$runId='lds-tls-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$resultRoot=Assert-LabPath (Join-Path $LabRoot "results\$runId")
$snapshot=Join-Path $resultRoot 'source';$harness=Join-Path $resultRoot 'harness'
$peerSource=Join-Path $snapshot 'scripts\lab\tls-peer'
$null=New-Item -ItemType Directory -Path $peerSource,$harness
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$sourceHashes=[ordered]@{};$harnessHashes=[ordered]@{};$nativeHash='';$peerHash='';$toolchain=''
$memberSession=$null;$clientSession=$null;$memberInitialized=$false;$clientInitialized=$false
$memberSetup=$null;$clientSetup=$null;$generated=$null;$trusted=$null;$memberCleanup=$null;$clientCleanup=$null
$phase='snapshot';$failure=$null;$cleanupErrors=@();$cases=@()

function Get-LDSTLSError($Record) {
    $exception=$Record.Exception
    while($exception){[pscustomobject]@{type=$exception.GetType().FullName;hresult=$exception.HResult};$exception=$exception.InnerException}
}
function Get-LDSTLSSourceHashes {
    $hashes=[ordered]@{}
    foreach($file in (Get-ChildItem -LiteralPath $snapshot -File -Recurse | Sort-Object FullName)) {
        $name=$file.FullName.Substring($snapshot.Length+1).Replace('\','/')
        $hashes[$name]=(Get-FileHash -LiteralPath $file.FullName).Hash
    }
    return $hashes
}
function Invoke-LDSTLSPeer($Session,[string]$Operation,[string]$CaseName='',[string]$Public='') {
    return Invoke-Command -Session $Session -FilePath (Join-Path $harness 'guest-lds-tls-peer.ps1') -ArgumentList $Operation,$specification,$runId,$peerHash,$nativeHash,$CaseName,$Public | ConvertFrom-Json
}
function Test-LDSTLSPairedCase($Case,$Manifest,$Guest,$Peer) {
    if(-not $Guest -or -not $Guest.passed -or -not $Peer -or -not $Peer.passed){throw 'TLS client or peer did not complete successfully.'}
    $observation=$Peer.peer
    $expected=$Manifest.certificates.PSObject.Properties[$Case.leaf].Value
    $expectedPolicy=switch($Case.leaf){'valid'{'0'};'expired'{'800B0101'};'wrong-host'{'800B010F'};'untrusted'{'800B0109'};default{throw 'Unknown certificate case.'}}
    if(-not $Guest.PSObject.Properties['certificate_policy'] -or -not $Guest.certificate_policy.passed -or -not $Guest.certificate_policy.logging_restored){throw 'Certificate-policy evidence or logging restoration is missing.'}
    foreach($policy in @($Guest.certificate_policy.native,$Guest.certificate_policy.reference)) {
        if(-not $policy -or -not $policy.passed -or $policy.result -cne $expectedPolicy -or $policy.certificate_thumbprint -ine $expected.thumbprint -or $policy.certificate_sha256 -cne $expected.sha256 -or $policy.server_name -ine 'ADSDK25MEM.ad.sdk.test'){throw 'Certificate-policy evidence does not match the expected leaf, host, or result.'}
    }
    if($Guest.case -cne $Case.name -or $observation.mode -cne $Case.transport -or $observation.address -cne "10.77.23.20:$($Case.port)" -or $observation.connection_limit -ne 2 -or @($observation.connections).Count -ne 2 -or $observation.outcome -cne 'connection_limit' -or $observation.configured_certificate.sha256 -cne $expected.sha256){throw 'TLS peer case identity or certificate differs.'}
    if(-not $Guest.output_secret_checked -or -not $Guest.process_stopped -or $Guest.native.context_expired){throw 'TLS client lifetime or private-output check failed.'}
    foreach($connection in $observation.connections) {
        if(-not $connection.PSObject.Properties['selected_certificate'] -or $connection.selected_certificate.sha256 -cne $expected.sha256 -or $connection.plaintext_bind_requests -ne 0 -or $connection.starttls_accepted -ne ($Case.transport -eq 'starttls')){throw 'TLS peer did not select the expected certificate or observed a plaintext bind.'}
        if($Case.expect_failure) {
            if($connection.handshake_complete -or $connection.bind_requests -ne 0 -or $connection.ldap_bytes_forwarded -ne 0 -or $connection.ldap_bytes_received -ne 0 -or $connection.upstream_handshake_complete -or -not $connection.PSObject.Properties['error_category'] -or $connection.error_category -cnotin @('peer_closed','peer_tls_alert')){throw 'Invalid certificate reached bind/forwarding or lacks a corroborated peer rejection.'}
        } elseif(-not $connection.handshake_complete -or $connection.bind_requests -ne 1 -or $connection.ldap_bytes_forwarded -le 0 -or -not $connection.upstream_handshake_complete -or -not $connection.PSObject.Properties['upstream_certificate'] -or $connection.upstream_bytes_received -le 0){throw 'Valid TLS proxy control did not complete a validated bind/read exchange.'}
    }
    if($Case.expect_failure) {
        if($Guest.native.dial_succeeded -or -not $Guest.native.tls_negotiation_error -or $Guest.reference.bind_succeeded){throw 'Invalid certificate was not rejected by both clients.'}
    } elseif(-not $Guest.native.partition_read -or -not $Guest.reference.partition_read -or $Guest.native.partition -cne $Guest.reference.partition -or $Guest.native.instance_type -ne $Guest.reference.instance_type){throw 'Valid control partition reads differ.'}
    return $true
}

try {
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'go.mod'),(Join-Path $sourceRoot 'go.sum') -Destination $snapshot
    Get-ChildItem -LiteralPath $sourceRoot -Filter '*.go' -File | Copy-Item -Destination $snapshot
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'tls-peer') -Filter '*.go' -File | Copy-Item -Destination $peerSource
    $sourceHashes=Get-LDSTLSSourceHashes
    foreach($name in @('lab.ps1','guest.ps1','test-lds-tls.ps1','reference-lds-tls.ps1','guest-lds-tls-peer.ps1','lds-certificate-policy.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $harness
        $harnessHashes[$name]=(Get-FileHash -LiteralPath (Join-Path $harness $name)).Hash
    }
    $phase='build'
    $nativeBinary=Join-Path $resultRoot 'lds-tls.test.exe';$peerBinary=Join-Path $resultRoot 'tls-peer.exe'
    $saved=@{}
    foreach($name in @('GOOS','GOARCH','CGO_ENABLED','GOWORK','GOFLAGS','GOCACHE','GOTMPDIR')){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
    $buildCache=Assert-LabPath (Join-Path $LabRoot 'host-go-cache')
    $buildTemporary=Assert-LabPath (Join-Path $LabRoot 'host-go-tmp')
    $null=New-Item -ItemType Directory -Path $buildCache,$buildTemporary -Force
    Push-Location $snapshot
    try {
        $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0';$env:GOWORK='off';$env:GOFLAGS=''
        $env:GOCACHE=$buildCache;$env:GOTMPDIR=$buildTemporary
        $toolchain=(& go version | Out-String).Trim()
        & go test -mod=readonly -trimpath -c -o $nativeBinary . *> (Join-Path $resultRoot 'native-build.log')
        if($LASTEXITCODE -ne 0){throw 'TLS native build failed.'}
        & go build -mod=readonly -trimpath -o $peerBinary ./scripts/lab/tls-peer *> (Join-Path $resultRoot 'peer-build.log')
        if($LASTEXITCODE -ne 0){throw 'TLS peer build failed.'}
        if(($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-LDSTLSSourceHashes) | ConvertTo-Json -Compress)){throw 'TLS source snapshot changed during build.'}
    } finally {foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')};Pop-Location}
    $nativeHash=(Get-FileHash -LiteralPath $nativeBinary).Hash;$peerHash=(Get-FileHash -LiteralPath $peerBinary).Hash
    $specification=$lds | ConvertTo-Json -Depth 16 -Compress
    $phase='guest-setup'
    $memberSession=Wait-LabGuest $member $Credential;$clientSession=Wait-LabGuest $client $Credential
    $memberSetup=Invoke-LDSTLSPeer $memberSession 'Initialize';$memberInitialized=$true
    $clientSetup=Invoke-LDSTLSPeer $clientSession 'Initialize';$clientInitialized=$true
    if(-not $memberSetup.passed -or -not $clientSetup.passed){throw 'TLS guest directory initialization failed.'}
    $expectedDirectory="C:\ad-sdk-lds\$($lds.id)\tls-peers\$runId"
    if($memberSetup.directory -cne $expectedDirectory -or $clientSetup.directory -cne $expectedDirectory){throw 'TLS guest run directory differs.'}
    Copy-Item -LiteralPath $peerBinary -Destination "$expectedDirectory\tls-peer.exe" -ToSession $memberSession
    Copy-Item -LiteralPath $nativeBinary -Destination "$expectedDirectory\lds-tls.test.exe" -ToSession $clientSession
    Copy-Item -LiteralPath (Join-Path $harness 'lds-certificate-policy.ps1') -Destination "$expectedDirectory\lds-certificate-policy.ps1" -ToSession $clientSession
    $generated=Invoke-LDSTLSPeer $memberSession 'Generate'
    $generated | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $resultRoot 'certificate-generation.json') -Encoding UTF8
    if(-not $generated.passed){throw 'Guest-only TLS certificate generation failed.'}
    $trusted=Invoke-LDSTLSPeer $clientSession 'Trust' '' ($generated.public_root | ConvertTo-Json -Compress)
    if(-not $trusted.passed){throw 'Temporary public-root trust installation failed.'}
    # Complete both valid controls first. All remaining rows are still collected
    # after a disagreement, but the final matrix cannot pass without both controls.
    foreach($leaf in @('valid','expired','wrong-host','untrusted')) {
        foreach($transport in @('ldaps','starttls')) {
            $certificate=$generated.manifest.certificates.PSObject.Properties[$leaf].Value
            $case=[pscustomobject][ordered]@{name="$leaf-$transport";leaf=$leaf;transport=$transport;port=0;expect_failure=($leaf -ne 'valid');certificate_thumbprint=$certificate.thumbprint;certificate_sha256=$certificate.sha256}
            $row=[ordered]@{case=$case.name;passed=$false;specification=$case;ready=$null;client=$null;peer=$null;error=$null}
            $phase=$case.name
            Write-LabLog "Running owned TLS certificate case $($case.name)."
            try {
                $ready=Invoke-LDSTLSPeer $memberSession 'Start' $case.name
                $row.ready=$ready
                if(-not $ready.passed){throw 'TLS peer start failed.'}
                $case.port=[int]$ready.port
                try {
                    $row.client=Invoke-Command -Session $clientSession -FilePath (Join-Path $harness 'reference-lds-tls.ps1') -ArgumentList $specification,$runId,($case | ConvertTo-Json -Compress),$reader,$nativeHash,$harnessHashes['lds-certificate-policy.ps1'] | ConvertFrom-Json
                } catch {$row.error=[ordered]@{phase='client';errors=@(Get-LDSTLSError $_)}}
                # Collect even when the client failed so partial peer evidence is
                # retained. The peer has a 150-second total lifetime of its own.
                $row.peer=Invoke-LDSTLSPeer $memberSession 'Collect' $case.name
                $row.passed=Test-LDSTLSPairedCase $case $generated.manifest $row.client $row.peer
            } catch {
                if(-not $row.error){$row.error=[ordered]@{phase=$phase;line=$_.InvocationInfo.ScriptLineNumber;errors=@(Get-LDSTLSError $_)}}
            }
            $cases+=@([pscustomobject]$row)
            $row | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath (Join-Path $resultRoot "$($case.name).json") -Encoding UTF8
        }
    }
} catch {$failure=[ordered]@{phase=$phase;line=$_.InvocationInfo.ScriptLineNumber;errors=@(Get-LDSTLSError $_)}}
finally {
    if($clientSession -and $clientInitialized) {
        try {$clientCleanup=Invoke-LDSTLSPeer $clientSession 'Cleanup';if(-not $clientCleanup.passed){throw 'Client trust cleanup failed.'}} catch {$cleanupErrors+=@(Get-LDSTLSError $_)}
    }
    if($memberSession -and $memberInitialized) {
        try {$memberCleanup=Invoke-LDSTLSPeer $memberSession 'Cleanup';if(-not $memberCleanup.passed){throw 'Member peer cleanup failed.'}} catch {$cleanupErrors+=@(Get-LDSTLSError $_)}
    }
    foreach($session in @($clientSession,$memberSession)){if($session){try{Remove-PSSession $session}catch{$cleanupErrors+=@(Get-LDSTLSError $_)}}}
}
$integrity=$true
try {
    foreach($name in $harnessHashes.Keys){if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -ne $harnessHashes[$name]){$integrity=$false}}
} catch {$integrity=$false;if(-not $failure){$failure=[ordered]@{phase='harness-integrity';errors=@(Get-LDSTLSError $_)}}}
$passed=($null -eq $failure -and $cleanupErrors.Count -eq 0 -and $integrity -and $cases.Count -eq 8 -and @($cases | Where-Object {-not $_.passed}).Count -eq 0 -and $clientCleanup -and $clientCleanup.passed -and $memberCleanup -and $memberCleanup.passed)
[ordered]@{schema_version=1;run=$runId;time=[DateTime]::UtcNow.ToString('o');passed=[bool]$passed;lab_id=$LabState.id;fixture_id=$lds.id;image=$LabState.image;source_sha256=$sourceHashes;harness_sha256=$harnessHashes;native_binary_sha256=$nativeHash;peer_binary_sha256=$peerHash;toolchain=$toolchain;harness_unchanged=$integrity;error=$failure;cleanup_errors=$cleanupErrors;member_setup=$memberSetup;client_setup=$clientSetup;temporary_root_trust=$trusted;member_cleanup=$memberCleanup;client_cleanup=$clientCleanup;cases=$cases;private_pem_retained_only_in_owned_guest_directory=$true;scope='One valid and three invalid certificates over LDAPS and StartTLS; sequential native SDK and .NET LDAP clients; expected certificate selection, bind/forward counters, valid bind/partition proxy control, and exact temporary-trust/firewall/process cleanup.'} | ConvertTo-Json -Depth 28 | Set-Content -LiteralPath (Join-Path $resultRoot 'lds-tls-reference.json') -Encoding UTF8
if(-not $passed){throw "LDS TLS matrix failed; nonsecret evidence is retained at $resultRoot"}
Write-LabLog "LDS TLS certificate matrix passed. Results: $resultRoot"
