#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureManifest,
    [Parameter(Mandatory)][string]$RunDirectory,
    [Parameter(Mandatory)][string]$RunID,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SDKRevision,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$BinarySHA256,
    [Parameter(Mandatory)][string]$Peer,
    [Parameter(Mandatory)][ValidateSet('Before','After','Compare')][string]$Phase
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'replication-reference.ps1')
$fixture=Read-DirectoryFixture $FixtureManifest
$run=Assert-DirectoryRun $RunDirectory $RunID $fixture.fixture_id
$fixtureHash=(Get-FileHash -LiteralPath $FixtureManifest -Algorithm SHA256).Hash
$owner=Get-Content -LiteralPath (Join-Path $run 'owner.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($owner.fixture_sha256 -ine $fixtureHash) {throw 'Run owner does not pin this fixture manifest.'}
$servers=@($fixture.server.ToLowerInvariant(),$Peer.ToLowerInvariant())
$owned=@('adsdk25dc1.ad.sdk.test','adsdk25dc2.ad.sdk.test')
if ($fixture.domain_dns -cne 'ad.sdk.test' -or $fixture.server_version -cne '2025' -or $servers[0] -ceq $servers[1] -or @($servers | Where-Object {$_ -notin $owned}).Count) {throw 'This check requires the existing owned Server 2025 DC pair.'}
$phaseName=$Phase.ToLowerInvariant()
$destination=Join-Path $run ('replication-'+$(if ($Phase -eq 'Compare') {'comparison'} else {$phaseName})+'.json')
if (Test-Path -LiteralPath $destination) {throw 'A replication observation already exists; start a fresh run.'}
if ($Phase -eq 'Compare') {
    $snapshots=@{}
    foreach ($name in @('before','native','after')) {
        $path=Assert-DirectoryPlainPath (Join-Path $run ('replication-'+$name+'.json'))
        if ((Get-Item -LiteralPath $path).Length -gt 8MB) {throw 'Replication artifact exceeds the bounded input size.'}
        $snapshot=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($snapshot.run_id -cne $RunID -or $snapshot.fixture_id -cne $fixture.fixture_id -or $snapshot.sdk_revision -ine $SDKRevision -or $snapshot.binary_sha256 -ine $BinarySHA256 -or (@($snapshot.servers) -join ',') -cne ($servers -join ',')) {throw 'Replication observation differs from the requested run/pins/targets.'}
        $snapshots[$name]=$snapshot
    }
    $hash=(Get-FileHash -LiteralPath (Join-Path $run 'replication-before.json') -Algorithm SHA256).Hash
    $result=Compare-ReplicationSnapshots $snapshots.before $snapshots.native $snapshots.after $hash
    Write-DirectoryNewJSON $destination $result
    if (-not $result.passed) {throw 'Replication comparison failed; inspect the named checks.'}
    Write-Output 'Read-only replication comparison passed; full ticket qualification remains incomplete.'
    return
}
if ([Environment]::MachineName -ine $fixture.client_computer) {throw 'Reference collection is running on the wrong fixture computer.'}
$reference=[ordered]@{
    schema_version=1;purpose='go-sdk-activedirectory-replication-reference';phase=$phaseName
    run_id=$RunID;fixture_id=$fixture.fixture_id;fixture_sha256=$fixtureHash;sdk_revision=$SDKRevision.ToLowerInvariant();binary_sha256=$BinarySHA256.ToLowerInvariant()
    client_computer=[Environment]::MachineName;domain_dns=$fixture.domain_dns;domain_dn=$null
    domain_guid_binary=([BitConverter]::ToString(([guid]$fixture.domain_guid).ToByteArray())).Replace('-','').ToLowerInvariant()
    servers=$servers;records=@();started=[DateTime]::UtcNow.ToString('o');finished=$null;passed=$false;full_ticket_complete=$false
    source_provenance_verified=$false;failure_type=$null;collector_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
}
$failure=$null
$previousDrive=$env:ADPS_LoadDefaultDrive
try {
    # Every read names its endpoint; do not create an implicit default AD drive.
    $env:ADPS_LoadDefaultDrive='0'
    Import-Module ActiveDirectory -ErrorAction Stop
    foreach ($server in $servers) {
        $root=Get-ADRootDSE -Server $server -ErrorAction Stop
        if ($root.dnsHostName -ine $server -or -not $root.defaultNamingContext) {throw 'Reference endpoint identity mismatch.'}
        $domain=Get-ADDomain -Identity $root.defaultNamingContext -Server $server -ErrorAction Stop
        if ($domain.DNSRoot -ine $fixture.domain_dns -or $domain.ObjectGUID -ne [guid]$fixture.domain_guid) {throw 'Reference domain GUID/DNS identity mismatch.'}
        if ($null -ne $reference.domain_dn -and $reference.domain_dn -ine $domain.DistinguishedName) {throw 'The target pair has different naming contexts.'}
        $reference.domain_dn=$domain.DistinguishedName
    }
    foreach ($server in $servers) {$reference.records+=@(Get-ReplicationReferenceServer $server $servers[0])}
    $reference.passed=@($reference.records | Where-Object {$_.errors.Count -ne 0}).Count -eq 0
    if (-not $reference.passed) {throw 'A replication reference category failed; errors were retained.'}
} catch {
    $failure=$_;$reference.failure_type=$_.Exception.GetType().FullName
} finally {
    $env:ADPS_LoadDefaultDrive=$previousDrive
    $reference.finished=[DateTime]::UtcNow.ToString('o')
    Write-DirectoryNewJSON $destination $reference
}
if ($failure) {throw 'Read-only reference collection failed; inspect the retained artifact.'}
Write-Output ('Read-only replication reference captured: '+$phaseName)
