#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName='Source')]
param(
    [Parameter(Mandatory,ParameterSetName='Source')][string]$FixtureManifest,
    [Parameter(Mandatory,ParameterSetName='Source')][string]$ArtifactRoot,
    [Parameter(ParameterSetName='Source')][ValidateSet('core','trust','topology','extended')][string]$Profile='core',
    [Parameter(ParameterSetName='Source')][string]$TrustPartner,
    [Parameter(ParameterSetName='Source')][ValidateSet('amd64','arm64')][string]$Architecture='amd64',
    [Parameter(ParameterSetName='Source')][string]$SourceRoot=(Join-Path $PSScriptRoot '..\..'),
    [Parameter(ParameterSetName='Source')][switch]$PrepareOnly,
    [Parameter(Mandatory,ParameterSetName='Prepared')][string]$PreparedRun
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'directory-harness.ps1')
$preparation=$null
if ($PreparedRun) {
    $preparedPath=Assert-DirectoryPlainPath $PreparedRun
    $preparation=Get-Content -LiteralPath (Assert-DirectoryPlainPath (Join-Path $preparedPath 'preparation.json')) -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($preparation.schema_version -ne 1 -or -not $preparation.prepared -or $preparation.profile -notin @('core','trust','topology','extended') -or $preparation.architecture -notin @('amd64','arm64') -or $preparation.source_revision -notmatch '\A[0-9a-f]{40}\z') {throw 'Invalid prepared bundle identity.'}
    $FixtureManifest=Join-Path $preparedPath 'fixture.json'
    $Profile=$preparation.profile;$TrustPartner=$preparation.trust_partner;$Architecture=$preparation.architecture
}
$Profile=$Profile.ToLowerInvariant();$Architecture=$Architecture.ToLowerInvariant()
$fixturePath=Assert-DirectoryPlainPath $FixtureManifest
$fixture=Read-DirectoryFixture $fixturePath
if ($Profile -in @('trust','extended')) {
    if (-not $TrustPartner -or @($fixture.trust_partners | Where-Object {$_.dns_name -ieq $TrustPartner}).Count -ne 1) { throw 'Select an owned trust partner for this profile.' }
} elseif ($TrustPartner) { throw 'TrustPartner requires the trust or extended profile.' }
if ($preparation) {
    $null=Assert-DirectoryRun $preparedPath $preparation.run_id $fixture.fixture_id
    if ($preparation.fixture_id -cne $fixture.fixture_id -or $preparation.fixture_snapshot_sha256 -ine (Get-FileHash -LiteralPath $fixturePath).Hash) {throw 'Prepared fixture snapshot changed.'}
    foreach ($name in @('reference.json','native.json','manifest.json','reference.log','native.log')) {if (Test-Path -LiteralPath (Join-Path $preparedPath $name)) {throw 'Prepared runs are single use; create a fresh preparation.'}}
    $fixtureHash=$preparation.supplied_fixture_sha256
    $run=[pscustomobject]@{ID=$preparation.run_id;Path=$preparedPath}
} else {
    $source=Assert-DirectoryPlainPath $SourceRoot
    $fixtureHash=(Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash
    $run=New-DirectoryRun $ArtifactRoot $fixture.fixture_id $fixtureHash
}
$snapshot=Join-Path $run.Path 'source';$harness=Join-Path $run.Path 'harness'
$sourceHashes=[ordered]@{};$harnessHashes=[ordered]@{};$artifactHashes=[ordered]@{}
$revision=$null;$binaryHash=$null;$referenceHash=$null;$toolchain=$null;$native=$null
$failure=$null;$phase='snapshot';$referenceExit=$null;$nativeExit=$null;$timedOut=$false;$passed=$false

function Get-DirectoryFileHashes([string]$Directory) {
    $hashes=[ordered]@{}
    if (@(Get-ChildItem -LiteralPath $Directory -Directory).Count) {throw 'Unexpected directory inside the retained flat snapshot.'}
    foreach ($file in (Get-ChildItem -LiteralPath $Directory -File | Sort-Object Name)) {
        $null=Assert-DirectoryPlainPath $file.FullName
        $hashes[$file.Name]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    return $hashes
}

try {
    $binary=Join-Path $run.Path 'directory.test.exe'
    if ($preparation) {
        $phase='prepared-input-check'
        $sourceHashes=ConvertTo-DirectoryHashMap $preparation.source_sha256 'source'
        $harnessHashes=ConvertTo-DirectoryHashMap $preparation.harness_sha256 'harness'
        $revision=$preparation.source_revision;$binaryHash=$preparation.binary_sha256;$toolchain=$preparation.toolchain
        if (($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-DirectoryFileHashes $snapshot) | ConvertTo-Json -Compress) -or ($harnessHashes | ConvertTo-Json -Compress) -cne ((Get-DirectoryFileHashes $harness) | ConvertTo-Json -Compress)) {throw 'Prepared source or harness snapshot changed.'}
        if ((Get-FileHash -LiteralPath (Assert-DirectoryPlainPath $binary)).Hash -ine $binaryHash) {throw 'Prepared binary hash mismatch.'}
        foreach ($name in @('directory-harness.ps1','reference-directory.ps1','test-directory.ps1')) {
            if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -ine $harnessHashes[$name]) {throw 'Invoked harness differs from its prepared snapshot.'}
        }
    } else {
    $git=(Get-Command git -CommandType Application).Source
    $go=(Get-Command go -CommandType Application).Source
    $status=Invoke-DirectoryProcess $git @('-C',$source,'status','--porcelain','--untracked-files=normal') $source 30
    if ($status.ExitCode -ne 0 -or $status.TimedOut -or $status.Stdout.Trim()) { throw 'A clean committed SDK source checkout is required.' }
    $head=Invoke-DirectoryProcess $git @('-C',$source,'rev-parse','HEAD') $source 30
    $revision=$head.Stdout.Trim()
    if ($head.ExitCode -ne 0 -or $head.TimedOut -or $revision -notmatch '^[0-9a-f]{40}$') { throw 'Cannot pin the SDK revision.' }
    $null=New-Item -ItemType Directory -Path $snapshot,$harness
    foreach ($file in @(Get-ChildItem -LiteralPath $source -Filter '*.go' -File)+@((Get-Item -LiteralPath (Join-Path $source 'go.mod')),(Get-Item -LiteralPath (Join-Path $source 'go.sum')))) {
        $null=Assert-DirectoryPlainPath $file.FullName
        Copy-Item -LiteralPath $file.FullName -Destination $snapshot
    }
    $sourceHashes=Get-DirectoryFileHashes $snapshot
    foreach ($name in @('directory-harness.ps1','reference-directory.ps1','test-directory.ps1')) {
        $file=Assert-DirectoryPlainPath (Join-Path $source "scripts\lab\$name")
        Copy-Item -LiteralPath $file -Destination $harness
    }
    $harnessHashes=Get-DirectoryFileHashes $harness
    foreach ($name in $sourceHashes.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $source $name)).Hash -ne $sourceHashes[$name]) { throw 'Source changed while taking its snapshot.' }
    }
    $status=Invoke-DirectoryProcess $git @('-C',$source,'status','--porcelain','--untracked-files=normal') $source 30
    if ($status.ExitCode -ne 0 -or $status.TimedOut -or $status.Stdout.Trim()) { throw 'Source changed during snapshot collection.' }
    # The invoked orchestrator/helpers must be the same files as the pinned
    # source, rather than an unrelated script beside a clean checkout.
    foreach ($name in @('directory-harness.ps1','reference-directory.ps1','test-directory.ps1')) {
        if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -ne $harnessHashes[$name]) { throw 'Invoked harness differs from the pinned checkout.' }
    }
    Write-DirectoryNewJSON (Join-Path $run.Path 'fixture.json') $fixture
    $phase='build'
    $version=Invoke-DirectoryProcess $go @('version') $source 30
    if ($version.ExitCode -ne 0 -or $version.TimedOut) { throw 'Cannot identify Go toolchain.' }
    $toolchain=$version.Stdout.Trim()
    if (Test-Path -LiteralPath $binary) {throw 'Native binary destination already exists.'}
    $build=Invoke-DirectoryProcess $go @('test','-mod=readonly','-trimpath','-c','-o',$binary,'.') $snapshot 600 @{GOOS='windows';GOARCH=$Architecture;CGO_ENABLED='0';GOWORK='off';GOFLAGS=''}
    Write-DirectoryNewText (Join-Path $run.Path 'build.log') ($build.Stdout+$build.Stderr)
    $timedOut=$build.TimedOut
    if ($build.ExitCode -ne 0 -or $build.TimedOut) { throw 'Directory native test build failed.' }
    $binaryHash=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    if (($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-DirectoryFileHashes $snapshot) | ConvertTo-Json -Compress) -or ($harnessHashes | ConvertTo-Json -Compress) -cne ((Get-DirectoryFileHashes $harness) | ConvertTo-Json -Compress)) {throw 'Build changed the retained source or harness.'}
    Write-DirectoryNewJSON (Join-Path $run.Path 'preparation.json') ([ordered]@{
        schema_version=1;prepared=$true;run_id=$run.ID;fixture_id=$fixture.fixture_id;profile=$Profile;trust_partner=$TrustPartner;architecture=$Architecture
        source_revision=$revision;source_sha256=$sourceHashes;harness_sha256=$harnessHashes;binary_sha256=$binaryHash;toolchain=$toolchain;supplied_fixture_sha256=$fixtureHash
        fixture_snapshot_sha256=(Get-FileHash -LiteralPath (Join-Path $run.Path 'fixture.json')).Hash;timestamp=[DateTime]::UtcNow.ToString('o');full_ticket_complete=$false
    })
    if ($PrepareOnly) {$phase='prepared';Write-Output "Prepared directory reference bundle without contacting AD: $($run.Path)";return}
    }
    $phase='reference'
    $powershell=Assert-DirectoryPlainPath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $harness 'reference-directory.ps1'),'-FixtureManifest',(Join-Path $run.Path 'fixture.json'),'-RunDirectory',$run.Path,'-RunID',$run.ID,'-SDKRevision',$revision,'-Profile',$Profile)
    if ($TrustPartner) {$arguments+=@('-TrustPartner',$TrustPartner)}
    $reference=Invoke-DirectoryProcess $powershell $arguments $run.Path 300
    $referenceExit=$reference.ExitCode;$timedOut=$reference.TimedOut
    Write-DirectoryNewText (Join-Path $run.Path 'reference.log') ($reference.Stdout+$reference.Stderr)
    if ($reference.ExitCode -ne 0 -or $reference.TimedOut) { throw 'Directory reference collector failed.' }
    $referencePath=Assert-DirectoryPlainPath (Join-Path $run.Path 'reference.json')
    $referenceHash=(Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash
    $referenceData=Get-Content -LiteralPath $referencePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $referenceData.passed -or $referenceData.run_id -cne $run.ID -or $referenceData.fixture_id -cne $fixture.fixture_id -or $referenceData.server -ine $fixture.server -or $referenceData.sdk_revision -cne $revision) { throw 'Reference artifact identity mismatch.' }
    if ($referenceData.collector_sha256 -ine $harnessHashes['reference-directory.ps1'] -or $referenceData.fixture_sha256 -ine (Get-FileHash -LiteralPath (Join-Path $run.Path 'fixture.json')).Hash) { throw 'Reference collector/fixture hashes do not match the snapshot.' }
    $phase='native-comparison'
    $null=Assert-DirectoryRun $run.Path $run.ID $fixture.fixture_id
    if ((Get-FileHash -LiteralPath $binary).Hash -ne $binaryHash) { throw 'Native binary changed after build.' }
    $resultPath=Join-Path $run.Path 'native.json'
    $execution=Invoke-DirectoryProcess $binary @('-test.run','^TestDirectoryProjectionLab$','-test.v','-test.count=1','-test.timeout=10m') $run.Path 660 @{ADSDK_DIRECTORY_REFERENCE=$referencePath;ADSDK_DIRECTORY_RESULT=$resultPath;ADSDK_DIRECTORY_RUN_ID=$run.ID;ADSDK_DIRECTORY_REFERENCE_SHA256=$referenceHash}
    $nativeExit=$execution.ExitCode;$timedOut=$execution.TimedOut
    Write-DirectoryNewText (Join-Path $run.Path 'native.log') ($execution.Stdout+$execution.Stderr)
    if ($execution.ExitCode -ne 0 -or $execution.TimedOut) { throw 'Native directory comparison failed.' }
    $native=Get-Content -LiteralPath (Assert-DirectoryPlainPath $resultPath) -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $native.passed -or $native.full_ticket_complete -or $native.reference_provenance_verified -or $native.run_id -cne $run.ID -or $native.fixture_id -cne $fixture.fixture_id -or $native.server -ine $fixture.server -or $native.sdk_revision -cne $revision -or $native.reference_sha256 -ine $referenceHash -or $native.binary_sha256 -ine $binaryHash -or $native.runtime_os -cne 'windows' -or $native.runtime_architecture -cne $Architecture) { throw 'Native artifact identity or qualification scope mismatch.' }
    $phase='retained-input-check'
    if (($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-DirectoryFileHashes $snapshot) | ConvertTo-Json -Compress) -or ($harnessHashes | ConvertTo-Json -Compress) -cne ((Get-DirectoryFileHashes $harness) | ConvertTo-Json -Compress)) { throw 'Retained source or harness changed during execution.' }
    if ((Get-FileHash -LiteralPath $referencePath).Hash -ne $referenceHash -or (Get-FileHash -LiteralPath $binary).Hash -ne $binaryHash) { throw 'Reference or binary changed during execution.' }
    $passed=$true;$phase='complete'
} catch { $failure=$_ }
finally {
    $null=Assert-DirectoryRun $run.Path $run.ID $fixture.fixture_id
    foreach ($name in @('preparation.json','fixture.json','reference.json','native.json','directory.test.exe','build.log','reference.log','native.log')) {
        $path=Join-Path $run.Path $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {$null=Assert-DirectoryPlainPath $path;$artifactHashes[$name]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
    }
    if (-not $PrepareOnly -or $failure) {Write-DirectoryNewJSON (Join-Path $run.Path 'manifest.json') ([ordered]@{
        schema_version=1;scope='directory-projection-differential';run_id=$run.ID;fixture_id=$fixture.fixture_id;profile=$Profile;server=$fixture.server
        passed=[bool]$passed;full_ticket_complete=$false;source_revision=$revision;source_sha256=$sourceHashes;harness_sha256=$harnessHashes;artifact_sha256=$artifactHashes
        supplied_fixture_sha256=$fixtureHash;binary_sha256=$binaryHash;reference_sha256=$referenceHash;toolchain=$toolchain;requested_architecture=$Architecture
        reference_exit_code=$referenceExit;native_exit_code=$nativeExit;process_timed_out=$timedOut;process_tree_cleanup_verified=$false
        failure_phase=$(if ($failure) {$phase} else {$null});failure_type=$(if ($failure) {$failure.Exception.GetType().FullName} else {$null})
        timestamp=[DateTime]::UtcNow.ToString('o');fixture_ownership_source='operator-supplied provisioning manifest; reference artifact records live identity checks when reached';server_os_independently_verified=$false
    })}
}
if ($failure) { throw "Directory comparison failed; retained artifacts: $($run.Path)" }
Write-Output "Directory projection comparison passed for profile $Profile. Full ticket qualification remains incomplete. Artifacts: $($run.Path)"
