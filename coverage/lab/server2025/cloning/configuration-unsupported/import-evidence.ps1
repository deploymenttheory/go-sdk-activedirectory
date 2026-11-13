#Requires -Version 5.1
# Import already completed evidence only; never invoke guest/VM/AD commands.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T232022Z-008266ad'
$source=Join-Path $buildRoot 'server2025-unsupported-member-v1'
$target=Join-Path $PSScriptRoot 'work-clone-config-qualification\coverage\lab\server2025\cloning\configuration-unsupported'
$run='clone-config-unsupported-server2025-59346e9-v1'
$encoding=[Text.UTF8Encoding]::new($false)
function Unlinked([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked evidence path.' }
    };return $full
}
function Digest([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','') } finally { $hasher.Dispose() }
}
function Assert-Digest([string]$Path,[string]$Expected) {
    $null=Unlinked $Path
    if((Get-FileHash -LiteralPath $Path).Hash -cne $Expected) { throw "Evidence digest differs: $Path" }
}
function Read-Json([string]$Name) { return Get-Content -LiteralPath (Unlinked (Join-Path $source $Name)) -Raw|ConvertFrom-Json }
function Require-Bool($Value,[bool]$Expected) { if($Value -isnot [bool] -or $Value -ne $Expected) { throw 'Recorded safety state differs.' } }
$null=Unlinked $target;if(Test-Path -LiteralPath $target) { throw 'Existing imported evidence is immutable.' }
$pins=[ordered]@{
    'build.json'='386ECB6700D11F28EBD4B4A9033392A9DAD03968AC0E5BE2E7AB60859E1F141F'
    'guest-return.json'='E9DAD79AE8D426D23A244B4C2349CB48205337C25E74CB610C662EA4A66F6A03'
    'guest.ps1'='D043F3AD5E5C88584E5752238BB82F60B3CB5BE073C2025C2CCE5362C72AB558'
    'helper-v4-build.json'='362DE5A85947FFDE1DB6571617F5AA908037553661F899B6A32E4E22DF38E377'
    'host.ps1'='F8D73A8A41C242B1A98F6A8FAAE3CC0D6DBBB4A61013B449CAF0E9A2831346F5'
    'negative-process-support.ps1'='2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D'
    'options.json'='A4338A4FA31E000912323683E693F252F997EFAF14D8F69D83A4C31445AAC6F7'
    'owner.txt'='E03A4E0DAE21E7478339BA4912BABB78213FD368DEDFBDCC51F148483028B0D1'
    'qualification.json'='495D55E45E3E2DF3C94D4D9F47AEE020D6AA8FEE3E66697E10469E50B6FDCCE4'
    'run-journal.json'='495D55E45E3E2DF3C94D4D9F47AEE020D6AA8FEE3E66697E10469E50B6FDCCE4'
    'sdk.finished.json'='0A9ADFED4F8D1DB8C7569BEC8B4B1E04CB9BB20FCF5D75B27EB0DDACB8657682'
    'sdk.requested.json'='7353B6BCEAD412C26914B03C3C3AC75E977EE26848E8F4F23AB269703E47F025'
    'sdk.started.json'='35AA94B8E70774F2976F1D4B3B69C626F9FC2D3DBB8BA5F4918C936587194A0A'
    'sdk.stderr.txt'='B7E91CDE93DB11B72F7A1F0FEFC18A607E886FF8198BF5ECBA05733E0C90F6EA'
    'sdk.stdout.txt'='10AD8112608DE9E9AC1A4AF4C5CBC2739ED7ACE93C6D12314F67A292009742C5'
    'summary.json'='D4CCEAD0DD751DCD0840B92BA1DAF2FE6C12491628B3B8ABD82F084B704F32C7'
}
if(@(Get-ChildItem -LiteralPath $source -Force).Count -ne $pins.Count) { throw 'Completed evidence directory changed.' }
foreach($name in $pins.Keys) { Assert-Digest (Join-Path $source $name) $pins[$name] }
$journal=Read-Json 'run-journal.json';$summary=Read-Json 'summary.json';$wire=Read-Json 'sdk.stdout.txt';$finished=Read-Json 'sdk.finished.json'
foreach($field in @('terminal','passed','power_restored','staging_preserved')) { Require-Bool $journal.$field $true }
Require-Bool $journal.guest_uncertain $false
if($journal.execution_id -cne $run -or $journal.phase -cne 'passed-member-restored-off' -or $journal.initial_power -cne 'Off' -or $journal.final_power -cne 'Off' -or
    $journal.vm_id -cne '80aa4382-c228-489c-b5f7-007c7feee3ff' -or $journal.lab_state_sha256 -cne 'F11DBEEAB66BB28B2EDF9A6CCA57B510AD76C5505BD2F5FDCBF2010E569619FE' -or
    $journal.host_sha256 -cne $pins['host.ps1'] -or $journal.guest_sha256 -cne $pins['guest.ps1'] -or $null -ne $journal.error) { throw 'Terminal host proof differs.' }
$actions=@('start-member','member-heartbeat','unsupported-member-probe','normal-member-shutdown')
if(@($journal.jobs).Count -ne $actions.Count) { throw 'Host job count differs.' }
for($index=0;$index -lt $actions.Count;$index++) {
    $job=$journal.jobs[$index];Require-Bool $job.timeout $false;Require-Bool $job.removed $true
    if($job.action -cne $actions[$index] -or $job.state -cne 'Completed' -or $null -ne $job.error) { throw 'Host job did not finish cleanly.' }
}
foreach($field in @('terminal','passed','child_invoked','staging_preserved')) { Require-Bool $summary.$field $true }
foreach($field in @('part_of_domain','process_uncertain','capture_failed')) { Require-Bool $summary.$field $false }
if($summary.run -cne $run -or $summary.computer -cne 'ADSDK25MEM' -or $summary.cim_domain_role -ne 2 -or $summary.product_type -ne 3 -or
    $summary.os_build -cne '26100' -or $summary.source_commit -cne '59346e9641feada4915a3313273ee2fc845bdbeb' -or @($summary.output_files).Count -ne 0 -or $null -ne $summary.error) { throw 'Guest identity/outcome differs.' }
Require-Bool $finished.completed $true;Require-Bool $finished.process_uncertain $false
if($finished.exit_code -ne 1 -or $finished.pid -le 0 -or -not $finished.started_utc -or $null -ne $finished.error -or
    ($finished|ConvertTo-Json -Depth 12 -Compress) -cne ($summary.process|ConvertTo-Json -Depth 12 -Compress) -or
    $finished.stdout_sha256 -cne $pins['sdk.stdout.txt'] -or $finished.stderr_sha256 -cne $pins['sdk.stderr.txt']) { throw 'Native process proof differs.' }
Require-Bool $wire.data.checks_skipped $false;Require-Bool $wire.data.prerequisites.complete $false
Require-Bool $wire.error_details.present $true;Require-Bool $wire.error_details.not_domain_controller $true
if($wire.protocol_version -ne 1 -or $wire.operation -cne 'generate_config' -or $wire.data.outcome -cne 'not_written' -or $wire.data.prerequisites.role.machine_role -ne 2) { throw 'Typed unsupported-host result differs.' }
foreach($name in @('source_host','primary_controller')) { $property=$wire.data.prerequisites.PSObject.Properties[$name];if($null -ne $property -and $property.Value) { throw 'Unexpected directory observation.' } }
$options=Read-Json 'options.json';Require-Bool $options.Offline $false
if($options.Directory -cne ('C:\ad-sdk-validation\'+$run+'\output') -or $options.Timeout -ne 10000000000) { throw 'Options differ.' }
$transport=Read-Json 'guest-return.json';$payloads=@($transport.payload)
if($payloads.Count -ne 1) { throw 'Transport cardinality differs.' }
# ConvertTo-Json retains the PSDirect string's extended remoting properties.
$wrapped=$payloads[0]
if($wrapped.value -isnot [string] -or @($wrapped.PSObject.Properties).Count -ne 4 -or
    $wrapped.PSComputerName -cne 'ADSDK25MEM' -or $wrapped.RunspaceId -isnot [string] -or $wrapped.PSShowComputerName -isnot [bool]) { throw 'Transport wrapper differs.' }
$envelope=$wrapped.value|ConvertFrom-Json
if($envelope.run -cne $run -or ($envelope.summary|ConvertTo-Json -Depth 24 -Compress) -cne ($summary|ConvertTo-Json -Depth 24 -Compress)) { throw 'Returned summary differs from raw summary.' }
$names=@('owner.txt','options.json','sdk.requested.json','sdk.started.json','sdk.finished.json','sdk.stdout.txt','sdk.stderr.txt','summary.json')
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach($artifact in @($envelope.artifacts)) {
    if($artifact.name -cnotin $names -or -not $seen.Add($artifact.name)) { throw 'Unexpected/duplicate captured artifact.' }
    $bytes=[Convert]::FromBase64String($artifact.base64);$raw=Join-Path $source $artifact.name
    if($bytes.Length -ne $artifact.bytes -or (Get-Item -LiteralPath $raw).Length -ne $bytes.Length -or
        (Digest $bytes) -cne $artifact.sha256 -or $artifact.sha256 -cne $pins[$artifact.name]) { throw 'Captured bytes differ from raw file.' }
}
if($seen.Count -ne $names.Count) { throw 'Capture incomplete.' }
$helperManifest=Read-Json 'helper-v4-build.json'
$archive=Join-Path $buildRoot 'source.zip';$helper=Join-Path $buildRoot 'helper-v4\clone-config-helper.exe'
Assert-Digest $archive 'D8D05B12B9678D0B11A7EA5081FEE24FAD4B9C44E185F1C91DECD2228B9E8B05'
Assert-Digest $helper '09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957'
if($journal.source_archive_sha256 -cne $helperManifest.source_archive_sha256 -or $summary.helper_sha256 -cne $helperManifest.helper_executable_sha256 -or
    $summary.source_commit -cne $helperManifest.source_commit -or $helperManifest.source_build_manifest_sha256 -cne $pins['build.json']) { throw 'Source/binary build chain differs.' }
Require-Bool $helperManifest.source_archive_verified_before_and_after $true;Require-Bool $helperManifest.helper_tests_passed $true
$checks=@('unsupported-member-checks-ps51-revised.json','unsupported-member-checks-ps7-revised.json')
foreach($name in $checks) {
    $check=Get-Content -LiteralPath (Join-Path $PSScriptRoot $name) -Raw|ConvertFrom-Json;Require-Bool $check.passed $true
    if($check.checks -ne 72 -or $check.host_sha256 -cne $pins['host.ps1'] -or $check.guest_sha256 -cne $pins['guest.ps1'] -or
        $check.tests_sha256 -cne '71B6954C74F156A0F1D9A3260EC06953686EACE7B8338B458729612CF925605C') { throw 'Final offline check provenance differs.' }
}
Assert-Digest (Join-Path $PSScriptRoot 'test-clone-config-unsupported-member.ps1') '71B6954C74F156A0F1D9A3260EC06953686EACE7B8338B458729612CF925605C'
Assert-Digest (Join-Path $PSScriptRoot 'run-clone-config-offline.ps1') '116353985A315D63E60B16B3386B8E305B965F9D36FEA131D80A6B8F999C06BE'
$copies=[Collections.Generic.List[object]]::new()
function Copy-Evidence([string]$From,[string]$Name) {
    $from=Unlinked $From;$to=Unlinked (Join-Path $target $Name)
    if(-not $to.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $to)) { throw 'Unexpected import destination.' }
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($to))
    $bytes=[IO.File]::ReadAllBytes($from);[IO.File]::WriteAllBytes($to,$bytes);$hash=Digest $bytes;Assert-Digest $to $hash
    $copies.Add([ordered]@{name=$Name.Replace('\','/');source=$from;sha256=$hash;bytes=$bytes.Length})
}
[void][IO.Directory]::CreateDirectory($target)
foreach($name in $pins.Keys) { if($name -cne 'guest-return.json') { Copy-Evidence (Join-Path $source $name) $name } }
Copy-Evidence (Join-Path $PSScriptRoot 'run-clone-config-offline.ps1') 'host-support.ps1'
Copy-Evidence (Join-Path $PSScriptRoot 'test-clone-config-unsupported-member.ps1') 'checks\test-clone-config-unsupported-member.ps1'
foreach($name in @($checks)+@('unsupported-member-wait-regression-red.json')) { Copy-Evidence (Join-Path $PSScriptRoot $name) ('checks\'+$name) }
foreach($name in @('clone-config-helper.go','clone-config-helper_test.go')) {
    $path=Join-Path $buildRoot ('helper-v4\'+$name);Assert-Digest $path $helperManifest.source_hashes.$name;Copy-Evidence $path ($name+'.txt')
}
Copy-Evidence $PSCommandPath 'import-evidence.ps1'
[IO.File]::WriteAllText((Join-Path $target '.gitattributes'),"* -text whitespace=cr-at-eol`n*.ps1 whitespace=cr-at-eol,-blank-at-eof`n",$encoding)
$audit=[ordered]@{schema_version=1;copied_utc=[DateTime]::UtcNow.ToString('o');run=$run;source_commit=$summary.source_commit;source_archive=[ordered]@{path=$archive;sha256=$helperManifest.source_archive_sha256};helper=[ordered]@{path=$helper;sha256=$helperManifest.helper_executable_sha256};transport=[ordered]@{path=(Join-Path $source 'guest-return.json');sha256=$pins['guest-return.json'];captured_artifacts_verified=$seen.Count;retained_on_host=$true};artifacts=@($copies.ToArray());coverage_states_changed=$false;staging_preserved=$true;power_restored=$true}
[IO.File]::WriteAllText((Join-Path $target 'import-audit.json'),($audit|ConvertTo-Json -Depth 12),$encoding)
[ordered]@{target=$target;artifacts=$copies.Count;raw_captures_verified=$seen.Count;passed=$true;power_restored=$true}|ConvertTo-Json
