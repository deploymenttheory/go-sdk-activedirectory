# Import completed offline qualification evidence; never execute its harnesses.
[CmdletBinding()]
param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$buildRoot = 'H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T211528Z-81823b4e'
$source = Join-Path $buildRoot 'server2025-clone-config-negative-v1'
$repo = Join-Path $PSScriptRoot 'work-dc-clone-config'
$target = Join-Path $repo 'coverage\lab\server2025\cloning\configuration-negative'
$commit = '4120ce5d13dd49de490cef67d41767ac3b409715'
$manifestPin = '6AB9B1B9129A39BC9C68FB4B00CB38D6DB4A31C4E925BB1C3790431927AD9E29'
$helperManifestPin = '0D9B53AF8EDDD7E942144158D6BE56E343B5A4C2F576A0D4D79CA7F594907C75'
$hostPin = '65D7BC70A1327950F1FE6D11D7B7079920CEB8E1F206341A6F3A200EA7DFD3DC'
$guestPin = '2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D'
$bootstrapPin = 'D38E2A64106FCFDCA3BAE9EB96A1CB869947BF38E61E0CD92BA6DA02AC27C894'

function Unlinked([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    for ($cursor = $full; $cursor; $cursor = [IO.Path]::GetDirectoryName($cursor)) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Evidence path traverses a reparse point: $full"
        }
    }
    return $full
}
function Within([string]$Root, [string]$Relative) {
    if ([IO.Path]::IsPathRooted($Relative) -or $Relative -match '(^|[\\/])\.\.?([\\/]|$)' -or $Relative.Contains(':')) {
        throw "Invalid evidence name: $Relative"
    }
    $full = Unlinked (Join-Path $Root $Relative)
    if (-not $full.StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence path escaped its root.' }
    return $full
}
function Read-Json([string]$Path) { return Get-Content -LiteralPath (Unlinked $Path) -Raw | ConvertFrom-Json }
function Digest([string]$Path) { return (Get-FileHash -LiteralPath (Unlinked $Path) -Algorithm SHA256).Hash }
function Byte-Digest([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-', '') } finally { $hasher.Dispose() }
}
function Assert-Pin([string]$Path, [string]$Expected) {
    if ($Expected -cnotmatch '^[A-F0-9]{64}$' -or (Digest $Path) -cne $Expected) { throw "Artifact pin differs: $Path" }
}
function Assert-Bool($Value, [bool]$Expected, [string]$Label) {
    if ($Value -isnot [bool] -or $Value -ne $Expected) { throw "Boolean evidence differs: $Label" }
}
function Assert-Same($Actual, $Expected, [string]$Label) {
    if (($Actual | ConvertTo-Json -Depth 40 -Compress) -cne ($Expected | ConvertTo-Json -Depth 40 -Compress)) {
        throw "Corroborating evidence differs: $Label"
    }
}
function Decode-Return([string]$Name) {
    $outer = Read-Json (Join-Path $source $Name)
    if (@($outer.payload).Count -ne 1 -or $outer.payload[0].value -isnot [string]) { throw "Returned envelope differs: $Name" }
    return $outer.payload[0].value | ConvertFrom-Json
}

$source = Unlinked $source
$target = Unlinked $target
if (Test-Path -LiteralPath $target) { throw 'Existing imported evidence is preserved; destination must not exist.' }
$qualification = Read-Json (Join-Path $source 'qualification.json')
foreach ($field in @('terminal', 'passed', 'staging_preserved')) { Assert-Bool $qualification.$field $true $field }
Assert-Bool $qualification.guest_uncertain $false 'guest_uncertain'
if ($null -ne $qualification.error -or $qualification.phase -cne 'passed-staging-preserved' -or
    $qualification.source_commit -cne $commit -or $qualification.manifest_sha256 -cne $manifestPin -or
    $qualification.helper_manifest_sha256 -cne $helperManifestPin -or $qualification.host_script_sha256 -cne $hostPin -or
    $qualification.guest_script_sha256 -cne $guestPin -or $qualification.bootstrap_sha256 -cne $bootstrapPin) {
    throw 'Completed qualification identity differs.'
}
if (@($qualification.jobs).Count -ne 3) { throw 'Expected three completed owned jobs.' }
Assert-Same @($qualification.jobs.action) @('stage', 'negative-cases', 'capture') 'owned job sequence'
foreach ($job in $qualification.jobs) {
    if ($job.state -cne 'Completed' -or $null -ne $job.error) { throw 'Owned job completion failed.' }
    Assert-Bool $job.timeout $false 'job timeout'
    Assert-Bool $job.removed $true 'job removal'
}
Assert-Same (Read-Json (Join-Path $source 'run-journal.json')) $qualification 'terminal journal'
foreach ($pair in @(
    @('build.json', $manifestPin), @('helper-v2-build.json', $helperManifestPin),
    @('run-clone-config-negative.ps1', $hostPin), @('guest-clone-config-negative.ps1', $guestPin),
    @('bootstrap-clone-config-negative.ps1', $bootstrapPin)
)) { Assert-Pin (Join-Path $source $pair[0]) $pair[1] }
$build = Read-Json (Join-Path $source 'build.json')
$helper = Read-Json (Join-Path $source 'helper-v2-build.json')
if ($build.source_commit -cne $commit -or $helper.source_commit -cne $commit -or
    $build.source_archive_sha256 -cne $helper.source_archive_sha256 -or $build.status -cne 'built') { throw 'Build provenance differs.' }
Assert-Pin (Join-Path $source 'clone-config-helper.go') $helper.helper_source_sha256
$helperTests = Join-Path $buildRoot 'helper-v2\clone-config-helper_test.go'
Assert-Pin $helperTests $helper.helper_tests_sha256

$rawRoot = Unlinked (Join-Path $source 'raw')
$capture = Decode-Return 'capture-return.json'
$outcome = Decode-Return 'guest-return.json'
$summary = Read-Json (Join-Path $rawRoot 'negative-cases\summary.json')
$captureMap = Read-Json (Join-Path $source 'captured-evidence.json')
Assert-Same $captureMap $qualification.captures 'capture hash manifest'
Assert-Same $summary $outcome 'raw summary and returned guest result'
if ($capture.run -cne $qualification.execution_id -or $summary.run -cne $qualification.execution_id -or
    $summary.source_commit -cne $commit -or $summary.source_archive_sha256 -cne $build.source_archive_sha256 -or
    $summary.build_manifest_sha256 -cne $manifestPin -or $summary.helper_build_manifest_sha256 -cne $helperManifestPin -or
    $summary.helper_source_sha256 -cne $helper.helper_source_sha256 -or $summary.helper_binary_sha256 -cne $helper.helper_executable_sha256 -or
    $summary.harness_sha256 -cne $guestPin -or $summary.mode -cne 'explicit Offline only' -or
    $summary.computer -cne 'ADSDK25DC1' -or $null -ne $summary.error) { throw 'Raw summary identity differs.' }
foreach ($field in @('completed', 'passed', 'staging_preserved')) { Assert-Bool $summary.$field $true $field }
foreach ($field in @('process_uncertain', 'publication_uncertain', 'capture_failed')) { Assert-Bool $summary.$field $false $field }
$names = @('control-v4-static', 'control-four-v6-dns', 'dynamic-with-static-fields', 'static-missing-address',
    'static-missing-mask', 'static-missing-dns', 'static-empty-dns', 'malformed-ipv4-address', 'broadcast-address',
    'broadcast-gateway', 'noncontiguous-mask', 'dynamic-with-gateway', 'five-v4-dns', 'five-v6-dns',
    'static-without-family', 'static-v4-dns-only', 'broadcast-dns', 'malformed-v4-dns', 'malformed-v6-dns')
Assert-Same @($summary.cases.name) $names '19-case sequence'
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$captureFiles = @($capture.files)
if ($captureFiles.Count -ne 359 -or @($qualification.captures.PSObject.Properties).Count -ne 359) { throw 'Expected 359 raw captures.' }
$totalBytes = 0L
foreach ($file in $captureFiles) {
    $path = Within $rawRoot $file.name
    if (-not $seen.Add($file.name) -or $file.length -lt 0 -or $file.length -gt 2097152 -or $file.bytes_base64.Length -gt 2796204) {
        throw 'Raw capture identity or size differs.'
    }
    $bytes = [Convert]::FromBase64String($file.bytes_base64)
    $totalBytes += $bytes.Length
    if ($bytes.Length -ne $file.length -or $totalBytes -gt 33554432 -or
        (Byte-Digest $bytes) -cne $file.sha256 -or $qualification.captures.($file.name) -cne $file.sha256 -or
        (Get-Item -LiteralPath $path).Length -ne $file.length) { throw "Raw envelope differs: $($file.name)" }
    Assert-Pin $path $file.sha256
}
$rawFiles = @(Get-ChildItem -LiteralPath $rawRoot -Force -Recurse -File)
if ($rawFiles.Count -ne $captureFiles.Count) { throw 'Raw file set differs from the capture envelope.' }
foreach ($file in $rawFiles) {
    $relative = (Unlinked $file.FullName).Substring($rawRoot.Length + 1).Replace('\', '/')
    if (-not $seen.Contains($relative)) { throw 'Unrecorded raw file found.' }
}
foreach ($owner in @('owner.txt', 'negative-cases\owner.txt')) {
    if ([IO.File]::ReadAllText((Within $rawRoot $owner)) -cne $qualification.execution_id) { throw 'Captured owner differs.' }
}
$classifications = [Collections.Generic.List[object]]::new()
foreach ($case in $summary.cases) {
    Assert-Bool $case.passed $true 'case passed'
    if ($null -ne $case.error) { throw "Case error: $($case.name)" }
    $prefix = 'negative-cases/' + $case.name + '/'
    foreach ($suffix in @('case.json', 'options.json', 'before.json', 'sdk-observed.json', 'observations.json', 'reference.json', 'result.json', 'reference.streams.txt')) {
        if (-not $seen.Contains($prefix + $suffix)) { throw 'Mandatory case evidence is missing.' }
    }
    Assert-Same (Read-Json (Within $rawRoot ($prefix + 'result.json'))) $case 'per-case result'
    Assert-Same (Read-Json (Within $rawRoot ($prefix + 'reference.json'))) $case.reference 'reference result'
    Assert-Same (Read-Json (Within $rawRoot ($prefix + 'case.json'))) $case.expectations 'case expectations'
    foreach ($pair in @(@($case.sdk_process, 'sdk'), @($case.reference_process, 'reference-child'))) {
        $process = $pair[0]
        $stem = $pair[1]
        Assert-Bool $process.completed $true 'child completed'
        Assert-Bool $process.process_uncertain $false 'child uncertainty'
        if ($null -ne $process.error -or $process.pid -le 0 -or -not $process.started_utc -or $null -eq $process.exit_code) { throw 'Child completion differs.' }
        foreach ($suffix in @('.requested.json', '.started.json', '.finished.json', '.stdout.txt', '.stderr.txt')) {
            if (-not $seen.Contains($prefix + $stem + $suffix)) { throw 'Child execution record missing.' }
        }
        Assert-Same (Read-Json (Within $rawRoot ($prefix + $stem + '.finished.json'))) $process 'child finished record'
        foreach ($stream in @('stdout', 'stderr')) {
            if ($process.($stream + '_sha256') -cne $qualification.captures.($prefix + $stem + '.' + $stream + '.txt')) { throw 'Child stream hash differs.' }
        }
    }
    Assert-Bool $case.reference.completed $true 'reference completed'
    Assert-Bool $case.reference.offline $true 'reference offline'
    if ($null -ne $case.reference.harness_error -or $case.reference.streams_sha256 -cne $qualification.captures.($prefix + 'reference.streams.txt')) {
        throw 'Reference harness or stream hash differs.'
    }
    foreach ($pair in @(@($case.sdk_file, 'sdk'), @($case.reference.file, 'reference'))) {
        $observation = $pair[0]
        $name = $prefix + $pair[1] + '/DCCloneConfig.xml'
        Assert-Bool $observation.exists ($seen.Contains($name)) 'XML existence'
        if ($observation.exists) {
            Assert-Pin (Within $rawRoot $name) $observation.sha256
            if ((Byte-Digest ([Convert]::FromBase64String($observation.bytes_base64))) -cne $observation.sha256) { throw 'Observed XML bytes differ.' }
        }
    }
    Assert-Bool $case.sdk.data.checks_skipped $true 'SDK offline checks skipped'
    $positive = $case.expectations.positive_control
    if ($positive -isnot [bool]) { throw 'Case classification is not explicit.' }
    if ($positive) {
        if ($case.expectations.sdk_expectation -cne 'written' -or $case.expectations.reference_expectation -cne 'written' -or
            $case.sdk_process.exit_code -ne 0 -or $case.sdk.error_details.present -or $case.sdk.data.outcome -cne 'written' -or
            -not $case.sdk_file.exists -or -not $case.reference.file.exists) { throw 'Positive control result differs.' }
        $classification = 'positive-control'
    } else {
        if ($case.expectations.sdk_expectation -cne 'invalid_configuration' -or $case.sdk_process.exit_code -ne 1 -or
            -not $case.sdk.error_details.present -or -not $case.sdk.error_details.invalid_configuration -or
            $case.sdk.data.outcome -cne 'not_written' -or $case.sdk_file.exists) { throw 'SDK invalid configuration result differs.' }
        if ($case.expectations.reference_expectation -ceq 'written') {
            if (-not $case.reference.file.exists -or -not $case.expectations.intentional_difference) { throw 'Intentional reference-write difference lacks proof.' }
            $classification = 'invalid-sdk-stricter-reference-written'
        } elseif ($case.expectations.reference_expectation -ceq 'no_file') {
            if ($case.reference.file.exists) { throw 'Reference unexpectedly wrote a file.' }
            $classification = 'invalid-reference-no-file'
        } else { throw 'Unknown reference expectation.' }
    }
    $classifications.Add([ordered]@{name = $case.name; classification = $classification; intentional_difference = $case.expectations.intentional_difference})
}
if (@($classifications | Where-Object classification -eq 'positive-control').Count -ne 2 -or
    @($classifications | Where-Object classification -eq 'invalid-reference-no-file').Count -ne 8 -or
    @($classifications | Where-Object classification -eq 'invalid-sdk-stricter-reference-written').Count -ne 9) { throw 'Case classifications differ.' }

$plan = [Collections.Generic.List[object]]::new()
$destinations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
function Add-Artifact([string]$From, [string]$OriginalName, [string]$DestinationName, [string]$SourceGroup) {
    $fromPath = Unlinked $From
    if ([IO.Path]::GetExtension($fromPath) -cin @('.exe', '.dll', '.com', '.msi')) { throw 'Executable artifacts are excluded from this import.' }
    if ($DestinationName.EndsWith('.go', [StringComparison]::OrdinalIgnoreCase)) { $DestinationName += '.txt' }
    $to = Within $target $DestinationName
    if (-not $destinations.Add($to) -or (Test-Path -LiteralPath $to)) { throw 'Destination collision; no existing artifact is overwritten.' }
    $plan.Add([ordered]@{source = $fromPath; source_group = $SourceGroup; original_name = $OriginalName.Replace('\', '/');
        destination_name = $DestinationName.Replace('\', '/'); sha256 = (Digest $fromPath); bytes = (Get-Item -LiteralPath $fromPath).Length})
}
foreach ($file in @(Get-ChildItem -LiteralPath $source -Force -File -Recurse | Sort-Object FullName)) {
    $from = Unlinked $file.FullName
    if (-not $from.StartsWith($source + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Source artifact escaped.' }
    $relative = $from.Substring($source.Length + 1)
    Add-Artifact $from $relative $relative 'qualification'
}
foreach ($name in @('clone-config-negative-host-checks-ps51.json', 'clone-config-negative-host-checks-ps7.json')) {
    $path = Join-Path $PSScriptRoot $name
    $report = Read-Json $path
    Assert-Bool $report.passed $true 'offline host test report'
    if ($report.checks -ne 160 -or $report.host_script_sha256 -cne $hostPin -or
        $report.guest_script_sha256 -cne $guestPin -or $report.bootstrap_sha256 -cne $bootstrapPin) { throw 'Offline host report does not match frozen harnesses.' }
    Add-Artifact $path $name $name 'offline-host-checks'
}
foreach ($name in @('test-clone-config-negative-host.ps1', 'test-clone-config-negative.ps1')) {
    Add-Artifact (Join-Path $PSScriptRoot $name) $name $name 'offline-test-snapshot'
}
foreach ($name in @('clone-config-helper_test.go', 'helper-test.log', 'helper-build.log')) {
    Add-Artifact (Join-Path $buildRoot ('helper-v2\' + $name)) $name $name 'helper-v2'
}
Add-Artifact $PSCommandPath 'import-clone-config-negative.ps1' 'import-clone-config-negative.ps1' 'importer'
if ($ValidateOnly) {
    [ordered]@{validated = $true; artifacts = $plan.Count; raw_captures = $captureFiles.Count; cases = 19; positive_controls = 2;
        invalid_reference_no_file = 8; invalid_sdk_stricter_reference_written = 9; destination_created = $false} | ConvertTo-Json
    return
}

# All source checks and destination collision checks finish before creating output.
[void][IO.Directory]::CreateDirectory($target)
foreach ($artifact in $plan) {
    $to = Within $target $artifact.destination_name
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($to))
    [IO.File]::Copy($artifact.source, $to, $false)
    Assert-Pin $artifact.source $artifact.sha256
    Assert-Pin $to $artifact.sha256
}
$readme = @'
# Server 2025 offline clone configuration negative cases

This directory preserves a completed 19-case qualification from 2026-11-12.
The host wrapper reached terminal success at 22:01:09.2578338Z; all three owned
jobs completed and were removed, with no timeout, wrapper error, or guest
uncertainty. Guest staging was preserved. The raw summary reports completion,
no process/publication uncertainty or capture failure, and all cases passed.

There are **two positive controls and 17 invalid-input cases**, not 19 invalid
cases. Both controls (control-v4-static and control-four-v6-dns) wrote files
through the SDK and the reference. All 17 invalid cases returned the SDK's
invalid_configuration result and left no SDK output file.

| Classification | Cases | Meaning |
| --- | ---: | --- |
| Positive controls | 2 | SDK and reference both wrote configuration files. |
| Invalid; reference also wrote no file | 8 | Expected publication outcomes agree; error representations can differ. |
| Invalid; SDK stricter, reference wrote a file | 9 | Intentional validation differences, not SDK/reference equivalence. |

The eight invalid cases with no reference file are dynamic-with-static-fields,
static-missing-address, static-missing-mask, static-missing-dns, static-empty-dns,
dynamic-with-gateway, five-v4-dns, and five-v6-dns.

The nine intentional differences are malformed-ipv4-address, broadcast-address,
broadcast-gateway, noncontiguous-mask, static-without-family, static-v4-dns-only,
broadcast-dns, malformed-v4-dns, and malformed-v6-dns. The SDK rejects malformed
or broadcast addresses, noncontiguous masks, and incomplete static settings.
The reference serializes those address strings or selects another configuration
shape: no IPSettings for static-without-family, and dynamic IPv4 for
static-v4-dns-only. Each raw case records its exact expectations and difference.

Qualification provenance remains SDK source commit
4120ce5d13dd49de490cef67d41767ac3b409715, source archive SHA-256
1FA1A904FDEE8ED7F49428117C8215989F895E3EBCF7AC3554827248654C2E19,
and the helper-v2 manifest and source/test pins retained here. The later
c72c7b0a4a785f177a70f26729b7d9ffff140a46 discovery fix changes online locator
flag selection only; it is not the source revision executed by this offline
qualification. These results do not establish completion of broader issue #55.

The raw qualification ran on ADSDK25DC1, OS 10.0.26100.0, Windows PowerShell
5.1.26100.7462. Reference observations record ActiveDirectory module 1.0.1.0
and assembly 10.0.26100.7309. Every call used explicit Offline mode; these results
do not qualify online prerequisite checks or a domain-controller cloning run.

The import validates all 359 raw files against the qualification hash map,
captured-evidence.json, and the base64 capture-return.json envelope. The raw
summary must equal guest-return.json; per-case results, process completion,
stream hashes, and XML presence/bytes must corroborate it. Import-audit.json
records every copied artifact's source, original name, destination name, length,
and SHA-256. Captured bytes are unchanged; local .gitattributes disables text
conversion. Go source/test snapshots use .go.txt filenames to keep them outside
SDK package discovery. No executable binaries are imported.

The frozen host, guest, and bootstrap scripts are retained, together with the
matching offline 160-check reports for Windows PowerShell 5.1 and PowerShell 7.
These reports exercise local harness helpers and are separate from the actual
19-case guest qualification. The guest-harness test source is retained, but no
saved 83-check guest-harness report was available for import; no such retained
report is claimed. The helper-v2 source, tests, build manifest, and test/build
logs are also retained. This import performs no guest or AD operations and
changes no coverage states.
'@
$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $target '.gitattributes'), "* -text whitespace=cr-at-eol" + [Environment]::NewLine, $utf8)
[IO.File]::WriteAllText((Join-Path $target 'README.md'), $readme + [Environment]::NewLine, $utf8)
$generated = @(
    [ordered]@{name = '.gitattributes'; sha256 = (Digest (Join-Path $target '.gitattributes'))},
    [ordered]@{name = 'README.md'; sha256 = (Digest (Join-Path $target 'README.md'))}
)
$audit = [ordered]@{
    source = $source; destination = $target; copied_utc = [DateTime]::UtcNow.ToString('o')
    source_commit = $commit; qualification_terminal_utc = $qualification.updated
    qualification_sha256 = (Digest (Join-Path $source 'qualification.json'))
    source_manifest_sha256 = $manifestPin; helper_manifest_sha256 = $helperManifestPin
    copied_artifact_count = $plan.Count; raw_capture_count = $captureFiles.Count
    total_artifact_count_including_audit = $plan.Count + 3
    cases = 19; positive_controls = 2; invalid_cases = 17
    invalid_reference_no_file = 8; invalid_sdk_stricter_reference_written = 9
    case_classifications = @($classifications.ToArray())
    validated_raw_envelope = $true; validated_guest_return = $true; staging_preserved = $true
    coverage_states_changed = $false; executable_binaries_imported = $false; guest_83_check_report_available = $false
    artifacts = @($plan.ToArray()); generated_artifacts = $generated
    audit_note = 'This audit is generated metadata; its own digest is not self-referentially included.'
}
$auditPath = Join-Path $target 'import-audit.json'
[IO.File]::WriteAllText($auditPath, ($audit | ConvertTo-Json -Depth 12), $utf8)
if (@(Get-ChildItem -LiteralPath $target -Force -File -Recurse).Count -ne $plan.Count + 3) { throw 'Final artifact count differs.' }
[ordered]@{target = $target; artifacts = $plan.Count + 3; copied_artifacts = $plan.Count; raw_captures = $captureFiles.Count;
    cases = 19; positive_controls = 2; invalid_reference_no_file = 8; invalid_sdk_stricter_reference_written = 9;
    audit = $auditPath; audit_sha256 = (Digest $auditPath)} | ConvertTo-Json
