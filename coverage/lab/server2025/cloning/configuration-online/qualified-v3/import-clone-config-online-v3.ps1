#Requires -Version 5.1
# Preserve completed v3 evidence alongside, without rewriting, the failed runs.
[CmdletBinding()]
param([switch]$ValidateOnly)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Join-Path $PSScriptRoot 'work-clone-config-qualification'
$evidenceRoot=Join-Path $repo 'coverage\lab\server2025\cloning\configuration-online'
$target=Join-Path $evidenceRoot 'qualified-v3'
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T232022Z-008266ad'
$source=Join-Path $buildRoot 'server2025-online-qualification-v3'
$commit='59346e9641feada4915a3313273ee2fc845bdbeb'
$run='clone-config-reviewed-20261112T232022Z-008266ad-online-qualification-server2025-v3'
$pins=[ordered]@{
    host='3DE82E35946BD92F8D022BCE4E39A6F7D5959A50FD71DF65D0E07AE15041FD61'
    bootstrap='B46E06F348658F3D08E3A971AB240B08F263DB7EBEECB7CDD6F66AB0498BC33E'
    guest='CD1493A141F9986249D384BE5E55EED9B84C83B90E57D59DDB5B4C53FC502ECB'
    build='386ECB6700D11F28EBD4B4A9033392A9DAD03968AC0E5BE2E7AB60859E1F141F'
    helper_build='362DE5A85947FFDE1DB6571617F5AA908037553661F899B6A32E4E22DF38E377'
    archive='D8D05B12B9678D0B11A7EA5081FEE24FAD4B9C44E185F1C91DECD2228B9E8B05'
    binary='09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957'
    helper_source='F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1'
    baseline='12280A1773B53B317BDEC242362B79DC8E9AF44BAC7ECA8555822B5868B63A23'
    inventory='69BA8CE559775192047F61105499AB23917721188C588F29A9BE1D6B4E2FCF68'
    process_support='2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D'
    schema='A061F397D27B26563E6B4C7D611F707F5A3CA4A5B9CBD3353CB2CDC7BA9D7F35'
    journal='57B801DF960D89C37749A8A75F792B9484F9E23735A7E9F56556146D6A899D46'
    summary='A7D114D1F971889380975BCCCA01719143F58F7A043C49982BAA69012C97BE09'
}
$plan=[Collections.Generic.List[object]]::new();$retained=[Collections.Generic.List[object]]::new()
$destinations=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
# Reuse exact file/digest/import guards as function ASTs only. Do not execute
# the original importer entrypoint or any qualification harness entrypoint.
$support=Join-Path $evidenceRoot 'import-clone-config-online-partial.ps1'
if((Get-FileHash -LiteralPath $support).Hash -cne '6B1EEB5D1D8966579A1F391D23B0B67F30273AC624E121838E01D7318FBB4693'){throw 'Pinned import helper differs.'}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($support,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Pinned import helper parse failed.'}
$names=@('Unlinked','Within','Digest','Bytes-Digest','Read-Json','Pin','Bool','Same','Decode-Return','Import-Functions','Add-Artifact','Retain-Artifact','Check-Jobs','Check-RestoredWorld','Check-RestoredReplicas','Check-Capture','Read-XMLProjection')
foreach($name in $names){$matches=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object Name -ceq $name);if($matches.Count -ne 1){throw 'Pinned import function cardinality differs.'};. ([scriptblock]::Create($matches[0].Extent.Text))}
$target=Unlinked $target;$source=Unlinked $source;$buildRoot=Unlinked $buildRoot
if(Test-Path -LiteralPath $target){throw 'Existing v3 evidence is immutable.'}
Pin $support '6B1EEB5D1D8966579A1F391D23B0B67F30273AC624E121838E01D7318FBB4693'
foreach($item in @(@('build.json',$pins.build),@('helper-v4-build.json',$pins.helper_build),@('clone-config-helper.go',$pins.helper_source),@('inventory.json',$pins.baseline),@('negative-process-support.ps1',$pins.process_support),@('schema-evidence.json',$pins.schema),@('run-clone-config-online-qualification.ps1',$pins.host),@('guest-clone-config-online-qualification.ps1',$pins.guest),@('bootstrap-clone-config-online-qualification.ps1',$pins.bootstrap),@('inventory-support.ps1',$pins.inventory),@('run-journal.json',$pins.journal),@('raw\online-cases\summary.json',$pins.summary))){Pin (Join-Path $source $item[0]) $item[1]}
Pin (Join-Path $buildRoot 'build.json') $pins.build;Pin (Join-Path $buildRoot 'helper-v4\build.json') $pins.helper_build
Pin (Join-Path $buildRoot 'source.zip') $pins.archive;Pin (Join-Path $buildRoot 'helper-v4\clone-config-helper.exe') $pins.binary
$build=Read-Json (Join-Path $source 'build.json');$helper=Read-Json (Join-Path $source 'helper-v4-build.json')
if($build.source_commit -cne $commit -or $helper.source_commit -cne $commit -or $build.source_archive_sha256 -cne $pins.archive -or $helper.source_archive_sha256 -cne $pins.archive -or $helper.helper_executable_sha256 -cne $pins.binary -or $helper.source_build_manifest_sha256 -cne $pins.build -or $build.status -cne 'built'){throw 'V3 SDK build provenance differs.'}
Bool $helper.helper_tests_passed $true 'helper tests passed';Bool $helper.source_archive_verified_before_and_after $true 'helper archived source validation'
foreach($property in $helper.source_hashes.PSObject.Properties){Pin (Within (Join-Path $buildRoot 'helper-v4') $property.Name) $property.Value}
$baseline=Read-Json (Join-Path $source 'inventory.json')
Bool $baseline.completed $true 'baseline complete'
if($baseline.run -cne 'clone-config-reviewed-20261112T215735Z-b4707e3f-online-inventory-v1' -or $null -ne $baseline.error -or @($baseline.applications.reference_entries).Count -ne 28){throw 'Original baseline provenance differs.'}
$journal=Read-Json (Join-Path $source 'qualification.json')
Check-Jobs $journal @('stage','online-qualification','capture') $true
Same (Read-Json (Join-Path $source 'run-journal.json')) $journal 'v3 terminal journal'
if($journal.execution_id -cne $run -or $journal.phase -cne 'passed-staging-preserved' -or $journal.host_script_sha256 -cne $pins.host -or $journal.bootstrap_sha256 -cne $pins.bootstrap){throw 'V3 host identity differs.'}
Import-Functions (Join-Path $source 'run-clone-config-online-qualification.ps1') @('Get-OnlineCaseNames','Assert-OnlineMatrixState','Test-OnlineEvidenceName')
Import-Functions (Join-Path $source 'guest-clone-config-online-qualification.ps1') @('Project-OnlineXML')
$summary=Read-Json (Join-Path $source 'raw\online-cases\summary.json');Assert-OnlineMatrixState $summary
foreach($field in @('completed','passed','cleanup_complete','staging_preserved')){Bool $summary.$field $true $field}
foreach($field in @('process_uncertain','publication_uncertain','mutation_uncertain','capture_failed')){Bool $summary.$field $false $field}
$expected=[ordered]@{run=$run;source_commit=$commit;source_archive_sha256=$pins.archive;build_manifest_sha256=$pins.build;helper_build_manifest_sha256=$pins.helper_build;helper_source_sha256=$pins.helper_source;helper_binary_sha256=$pins.binary;harness_sha256=$pins.guest;inventory_sha256=$pins.baseline;process_support_sha256=$pins.process_support;inventory_support_sha256=$pins.inventory;schema_evidence_sha256=$pins.schema}
foreach($key in $expected.Keys){if($summary.$key -cne $expected[$key] -or $journal.identity.$key -cne $expected[$key]){throw "V3 provenance differs: $key"}}
Same @($summary.cases.name) @(Get-OnlineCaseNames) 'complete ten-case matrix'
if($summary.computer -cne 'ADSDK25DC1' -or $summary.phase -cne 'restored' -or $null -ne $summary.error -or
   $summary.recovery.group_added -ne $false -or $null -ne $summary.recovery.custom_file -or $null -ne $summary.recovery.config_file -or $null -ne $summary.recovery.intent){throw 'V3 recovery state is not fully restored.'}
foreach($case in $summary.cases){Bool $case.passed $true 'v3 case passed'}
$sdk=$summary.cases[5];$sdkExisting=$summary.cases[6];$referenceExisting=$summary.cases[7];$reference=$summary.cases[8]
if($sdk.process.exit_code -ne 0 -or $sdk.observation.data.outcome -cne 'written' -or $sdk.observation.error_details.present -ne $false -or $sdk.observation.data.prerequisites.complete -ne $true -or
   $sdkExisting.process.exit_code -ne 1 -or $sdkExisting.observation.data.outcome -cne 'not_written' -or $sdkExisting.observation.error_details.output_exists -ne $true -or
   $reference.process.exit_code -ne 0 -or $null -ne $reference.observation.cmdlet_error -or $reference.output_after.exists -ne $true){throw 'V3 generation or typed existing-output behavior differs.'}
Same $sdkExisting.output_before $sdkExisting.output_after 'SDK existing-file metadata unchanged'
Same $referenceExisting.output_before $referenceExisting.output_after 'reference existing-file metadata unchanged'
Same $sdk.output_after $sdkExisting.output_after 'SDK collision observes the successful file'
Same $sdk.output_after $referenceExisting.output_after 'reference collision observes the successful file'
$rawCount=Check-Capture $source $journal $summary
$sdkXML=Read-XMLProjection (Join-Path $source 'raw\online-cases\online-sdk-success\output.xml') (Join-Path $source 'schema-evidence.json')
$referenceXML=Read-XMLProjection (Join-Path $source 'raw\online-cases\online-reference-success\output.xml') (Join-Path $source 'schema-evidence.json')
$expectedXML=[ordered]@{name='DCCloneConfig';namespace='uri:microsoft.com:schemas:DCCloneConfig';value='';children=@([ordered]@{name='ComputerName';namespace='';value='ADSDK25CLONE';children=@()})}
Same $sdkXML $expectedXML 'expected SDK XML projection';Same $sdkXML $referenceXML 'schema-valid SDK/reference namespace/order/value projections'
$worlds=@(Get-ChildItem -LiteralPath (Join-Path $source 'raw\online-cases\snapshots') -File -Filter '*-world.json'|Sort-Object Name)
if($worlds.Count -eq 0){throw 'V3 restoration inventory missing.'};Check-RestoredWorld (Read-Json $worlds[-1].FullName)
$replicas=@(Get-ChildItem -LiteralPath (Join-Path $source 'raw\online-cases\snapshots') -File -Filter '*-replicas-restored.json')
if($replicas.Count -ne 1){throw 'V3 restored replicas missing.'};Check-RestoredReplicas (Read-Json $replicas[0].FullName)
foreach($file in @(Get-ChildItem -LiteralPath $source -File -Force -Recurse|Sort-Object FullName)) {
    $path=Unlinked $file.FullName;$name=$path.Substring($source.Length+1)
    if($name -cin @('capture-return.json','guest-return.json')){Retain-Artifact $path 'Validated original envelope; raw bytes and capture map imported without base64 duplication.'}
    else {Add-Artifact $path $name 'qualified-v3'}
}
Retain-Artifact (Join-Path $buildRoot 'source.zip') 'Verified executed SDK source archive; retained on H:.'
Retain-Artifact (Join-Path $buildRoot 'helper-v4\clone-config-helper.exe') 'Verified executed native helper; executable retained on H:.'
foreach($version in @('ps51','ps7')) {
    foreach($item in @(@(('host-checks-'+$version+'.json'),'host',224),@(('guest-checks-'+$version+'.json'),'guest',84),@(('inventory-checks-'+$version+'.json'),'inventory',90))) {
        $path=Join-Path $PSScriptRoot ('clone-online-v3\'+$item[0]);$report=Read-Json $path;Bool $report.passed $true 'v3 offline checks'
        if($report.checks -ne $item[2]){throw 'V3 offline count differs.'}
        if($item[1] -ceq 'host'){if($report.host_sha256 -cne $pins.host -or $report.guest_sha256 -cne $pins.guest -or $report.bootstrap_sha256 -cne $pins.bootstrap){throw 'Host check source differs.'}}
        elseif($report.guest_sha256 -cne $pins.($item[1])){throw 'Guest/inventory check source differs.'}
        Add-Artifact $path ('checks/'+$item[0]) 'offline-checks'
    }
}
foreach($name in @('test-clone-config-online-inventory.ps1','test-clone-config-online-qualification.ps1','test-clone-config-online-qualification-host.ps1','preparation.json')){Add-Artifact (Join-Path $PSScriptRoot ('clone-online-v3\'+$name)) ('checks/'+$name) 'offline-preparation'}
foreach($name in @('clone-config-helper_test.go','helper-tests.log','helper-build.log')){Add-Artifact (Join-Path $buildRoot ('helper-v4\'+$name)) ('build/'+$name) 'helper-build'}
Add-Artifact $support 'import-clone-config-online-partial.ps1' 'pinned-import-helper'
Add-Artifact $PSCommandPath 'import-clone-config-online-v3.ps1' 'importer'
if($ValidateOnly){[pscustomobject]@{validated=$true;copied_artifacts=$plan.Count;raw_captures=$rawCount;cases=10;cleanup_complete=$true;xml_projections_match=$true;destination_created=$false}|ConvertTo-Json;return}
[void][IO.Directory]::CreateDirectory($target)
foreach($artifact in $plan){$to=Within $target $artifact.destination_name;[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($to));[IO.File]::Copy($artifact.source,$to,$false);Pin $artifact.source $artifact.sha256;Pin $to $artifact.sha256}
$encoding=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $target '.gitattributes'),"* -text whitespace=cr-at-eol`n*.ps1 whitespace=cr-at-eol,-blank-at-eof`n",$encoding)
$audit=[ordered]@{schema_version=1;imported_utc=[DateTime]::UtcNow.ToString('o');run=$run;source_commit=$commit;source_archive_sha256=$pins.archive;helper_binary_sha256=$pins.binary;terminal_utc=$journal.updated;cases=10;raw_captures=$rawCount;passed=$true;cleanup_complete=$true;xml_projections_match=$true;xml_bytes_identical=($sdk.output_after.sha256 -ceq $reference.output_after.sha256);artifacts=@($plan.ToArray());verified_retained_artifacts=@($retained.ToArray());historical_failures_modified=$false;coverage_states_changed=$false;staging_preserved=$true}
[IO.File]::WriteAllText((Join-Path $target 'import-audit.json'),($audit|ConvertTo-Json -Depth 12),$encoding)
$readme=@"
# Server 2025 online clone configuration: completed v3 matrix

All ten ordered cases passed, and the host reached terminal success at
$($journal.updated). The matrix contains missing-group SDK/reference rejection,
direct membership setup, excluded-application SDK/reference rejection, SDK
online generation, SDK and reference existing-file rejection, reference online
generation, and membership removal. Every child and all three host jobs have
known completion, with no recorded uncertainty or error.

The SDK returned its typed existing-output error on the second online call.
Both SDK and reference collision checks left the existing file's bytes,
timestamps and ACL unchanged. The generated SDK and reference XML files both
validate against the captured Microsoft schema and match in namespace, order
and values. Their formatting bytes differ; byte-for-byte parity is not claimed.

Final evidence verifies removal of both owned cloning files and direct group
membership, restoration of the original 28 exclusions, and matching original
membership views on both DCs. No VM was cloned or restarted. Guest staging and
original host evidence are preserved.

Executed SDK source was $commit, the reviewed PR83 head subsequently squash
merged as 90f22fe9558f02c93fd9f8a1fb1a9ba306e05d77. The source commit recorded here
is the commit actually archived and built, not a substituted merge commit.
The helper executable SHA-256 is $($pins.binary). This build includes the
LDAP cursor thread-ownership fix. The prior failed-v1 and failed-v2 attempts
and their separate recoveries remain unchanged in the parent directory.

This qualifies the recorded Server 2025 matrix, not all of issue #55. Other
roles, supported versions, restricted access, nested groups, prerequisite
failures, path aliases and concurrent publication still require separate
evidence. Coverage qualification states were not promoted by this import.

The import independently checks all $rawCount raw captures against their
digests and original capture envelope, per-case results against raw child
streams, both XML documents against the retained schema, and final restoration
against the original baseline. Import-audit.json lists every copied artifact.
Verified transport envelopes, source archive and executable remain on H: with
their original paths and hashes recorded. Go snapshots use .go.txt filenames;
.gitattributes preserves captured bytes and original trailing blank lines.
The importer loads only pinned validation function ASTs and never executes a
lab harness or changes AD, VM state, ticket state or qualification metadata.
"@
[IO.File]::WriteAllText((Join-Path $target 'README.md'),$readme,$encoding)
[pscustomobject]@{target=$target;copied_artifacts=$plan.Count;raw_captures=$rawCount;cases=10;passed=$true;cleanup_complete=$true;xml_projections_match=$true}|ConvertTo-Json
