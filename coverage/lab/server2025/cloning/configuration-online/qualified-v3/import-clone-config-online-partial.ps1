#Requires -Version 5.1
# Preserve two known failed qualifications and their separate successful recoveries.
# No harness execution, VM/AD action, or coverage qualification state change.
[CmdletBinding()]
param([switch]$ValidateOnly)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T215735Z-b4707e3f'
$target=Join-Path $PSScriptRoot 'work-clone-config-qualification\coverage\lab\server2025\cloning\configuration-online'
$commit='c72c7b0a4a785f177a70f26729b7d9ffff140a46'
$pins=[ordered]@{build='8C1A3E99029AEADEDEE39904707E95B5C5C45599590A2BBF1EE0C61869E19579';helper_build='AC7334366C218A2A708DCAAFDB9776A5557D5E293170482321AE789CF594D219';archive='79728F456A61AF3F646931DA1A128E072E782D26B50A0453B1D3D6C49BFA9DEE';binary='9D2F0D3A3548E8CD719E741A46AB246B3E2AAF24430554F6EC1370DAD21C5D8F';helper_source='F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1';baseline='12280A1773B53B317BDEC242362B79DC8E9AF44BAC7ECA8555822B5868B63A23';process_support='2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D';schema='A061F397D27B26563E6B4C7D611F707F5A3CA4A5B9CBD3353CB2CDC7BA9D7F35'}
$runs=@(
    [ordered]@{name='failed-v1';directory='server2025-online-qualification-v1';suffix='v1';passed=$false;host='3C4415147AB6C08A468BEE3CD00919701461F6F406D676683C7ABCC8AEC0A125';guest='3025A2F740BE1764DF1A13F2C266554B68BAC4DAA9A4889CFA20C3BD8A8AFED1';bootstrap='E823C10B7497834C637F93782EA71FD91FA76035779411C668E96C05CE836CCD';inventory='25A401E6BE5F57DD16AB7CB5887AD747010581AE15A0997F717419B2B9A6C049'},
    [ordered]@{name='failed-v2';directory='server2025-online-qualification-v2';suffix='v2';passed=$false;host='7B6CB02A7094A40D8347BA471BBF2572F94EDDBBD4F1231B255F00BA49CA0EDB';guest='87E2DB53A47A6EEAB20DE0C7704DA0338407F45108B977CB98447977267AD2EB';bootstrap='9028C554B2AFAF9602E1B780846F32EB597374CA1CE8A124EE3DCC1A57AD076B';inventory='69BA8CE559775192047F61105499AB23917721188C588F29A9BE1D6B4E2FCF68'}
)
$recoveries=@(
    [ordered]@{name='recovery-v1';run='recovery-6bc48c5377d742e18dec31809c04c840';prior_index=0;prior_summary='6EF6FC734F7B201F1DC1DABD2A8892843531F7DCB1B1433AFF30744FEC28E506';prior_journal='DA7085FA7AC990CA539960C8A6E093E6107299BF1A4A7087B88ED57E1EB344AE';host='B0B7DD2E4C95A8BEF908F651BBA12875D7DD35CFE2543AF3DE317A10A502ACDF';guest='5DAF9928FE8A53BA34C9746EA7B1EEC17E7DF1DB51199ED1AC176EE9F434C8C6';test_directory=$PSScriptRoot;test_prefix='clone-config-recovery-checks-';test_suffix='-revised.json';checks=40},
    [ordered]@{name='recovery-v2';run='recovery-ad01335ea4824dc09d4b2db267f9fe4a';prior_index=1;prior_summary='6BBB302CDC5BAD56C85EB34624A42EA148E1BD271C7D3941E8B6F64EFDCD661A';prior_journal='1ECB5B7DAD255D719D1E6B4831CA16AEE0A13F3FFA672232635C569F0544B20A';host='C123A853F89D58865D3F6F768FA1E903C5370B1983506019C8B04415E8243CE4';guest='EF847233E06D70023DEE13842D7C2147AF4204C3DA309C9A4458669D28880FC5';test_directory=(Join-Path $PSScriptRoot 'clone-online-v2');test_prefix='recovery-checks-';test_suffix='.json';checks=41}
)
$recoveryResults=[Collections.Generic.List[object]]::new()
$plan=[Collections.Generic.List[object]]::new();$retained=[Collections.Generic.List[object]]::new();$results=[Collections.Generic.List[object]]::new()
$destinations=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
function Unlinked([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Evidence path traverses a reparse point.'}
    }
    return $full
}
function Within([string]$Root,[string]$Relative) {
    if(-not $Relative -or [IO.Path]::IsPathRooted($Relative) -or $Relative -match '(^|[\\/])\.\.?([\\/]|$)' -or $Relative.Contains(':')) {throw 'Invalid evidence name.'}
    $full=Unlinked (Join-Path $Root $Relative)
    if(-not $full.StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Evidence escaped its root.'}
    return $full
}
function Digest([string]$Path) {return (Get-FileHash -LiteralPath (Unlinked $Path) -Algorithm SHA256).Hash}
function Bytes-Digest([byte[]]$Bytes) {$h=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-','')}finally{$h.Dispose()}}
function Read-Json([string]$Path) {return Get-Content -LiteralPath (Unlinked $Path) -Raw|ConvertFrom-Json}
function Pin([string]$Path,[string]$Expected) {if($Expected -cnotmatch '^[A-F0-9]{64}$' -or (Digest $Path) -cne $Expected){throw "Evidence digest differs: $Path"}}
function Bool($Actual,[bool]$Expected,[string]$Label) {if($Actual -isnot [bool] -or $Actual -ne $Expected){throw "Boolean evidence differs: $Label"}}
function Same($Actual,$Expected,[string]$Label) {if(($Actual|ConvertTo-Json -Depth 40 -Compress) -cne ($Expected|ConvertTo-Json -Depth 40 -Compress)){throw "Corroborating evidence differs: $Label"}}
function Decode-Return([string]$Path) {
    $outer=Read-Json $Path
    if(@($outer.payload).Count -ne 1) {throw 'Return envelope cardinality differs.'}
    $value=$outer.payload[0]
    if($value -isnot [string]) {if($null -eq $value -or $null -eq $value.PSObject.Properties['value'] -or $value.value -isnot [string]) {throw 'Return envelope is not a string.'};$value=$value.value}
    return $value|ConvertFrom-Json
}
function Import-Functions([string]$Path,[string[]]$Names) {
    $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
    if($e.Count){throw 'Pinned validation source does not parse.'}
    foreach($name in $Names){$m=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object Name -ceq $name);if($m.Count -ne 1){throw 'Pinned validation function differs.'};. ([scriptblock]::Create(($m[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name))))}
}
function Add-Artifact([string]$Path,[string]$Name,[string]$Group) {
    $from=Unlinked $Path
    if([IO.Path]::GetExtension($from) -cin @('.exe','.dll','.com','.msi','.zip')){throw 'Executable/archive artifacts stay on the lab volume.'}
    if($Name.EndsWith('.go',[StringComparison]::OrdinalIgnoreCase)){$Name+='.txt'}
    $to=Within $target $Name
    if(-not $destinations.Add($to) -or (Test-Path -LiteralPath $to)){throw 'Destination collision.'}
    $plan.Add([ordered]@{source=$from;source_group=$Group;destination_name=$Name.Replace('\','/');sha256=(Digest $from);bytes=(Get-Item -LiteralPath $from).Length})
}
function Retain-Artifact([string]$Path,[string]$Reason) {$from=Unlinked $Path;$retained.Add([ordered]@{source=$from;sha256=(Digest $from);bytes=(Get-Item -LiteralPath $from).Length;reason=$Reason})}
function Check-Jobs($Journal,[string[]]$Actions,[bool]$Passed) {
    foreach($field in @('terminal','staging_preserved')){Bool $Journal.$field $true $field}
    Bool $Journal.passed $Passed 'host passed';Bool $Journal.cleanup_complete $Passed 'host cleanup';Bool $Journal.guest_uncertain $false 'host uncertainty'
    Same @($Journal.jobs.action) $Actions 'host jobs'
    foreach($job in $Journal.jobs){if($job.state -cne 'Completed' -or $null -ne $job.error){throw 'Host job did not finish cleanly.'};Bool $job.timeout $false 'timeout';Bool $job.removed $true 'job removed'}
    if($Journal.lab_id -cne '60197892-ec9f-4c19-abe8-34dc60d473e5' -or $Journal.vm_id -cne 'a364b1d0-7868-47f1-ab29-a5e80c97aa4b'){throw 'Lab identity differs.'}
    if($Passed -and $null -ne $Journal.error){throw 'Passing host result retains an error.'}
}
function Check-RestoredWorld($World) {
    Bool $World.completed $true 'restored inventory completion'
    if($null -ne $World.error -or $World.computer -cne 'ADSDK25DC1'){throw 'Restored inventory has an error or wrong guest.'}
    Same $World.files $baseline.files 'restored files and ACLs';Same $World.versions $baseline.versions 'reference versions'
    Same @( $World.applications.reference_entries|ForEach-Object {$_.type+':'+$_.name}|Sort-Object -CaseSensitive ) @( $baseline.applications.reference_entries|ForEach-Object {$_.type+':'+$_.name}|Sort-Object -CaseSensitive ) '28 restored exclusions'
    foreach($field in @('server','domain_dn','domain_sid','pdc','source_dn','source_guid','source_sid','group_dn','group_guid','group_sid','dc_functionality','source_read_only')){Same $World.directory.$field $baseline.directory.$field ('restored '+$field)}
    foreach($field in @('direct_member','token_member','reference_member')){Bool $World.directory.$field $false $field}
    Same @($World.directory.group_members) @() 'restored group members'
    Same @($World.directory.source_direct_groups|Sort-Object) @($baseline.directory.source_direct_groups|Sort-Object) 'restored direct groups'
    Same @($World.directory.source_token_groups|Sort-Object) @($baseline.directory.source_token_groups|Sort-Object) 'restored token groups'
    Same @($World.directory.source_reference_groups.sid|Sort-Object) @($baseline.directory.source_reference_groups.sid|Sort-Object) 'restored reference groups'
}
function Check-RestoredReplicas($Views) {
    Same @($Views.server) @('ADSDK25DC1.ad.sdk.test','ADSDK25DC2.ad.sdk.test') 'two restored replicas'
    foreach($view in $Views){if($view.group_guid -cne $baseline.directory.group_guid -or $view.source_guid -cne $baseline.directory.source_guid){throw 'Restored replica GUID differs.'};Same @($view.members) @() 'replica members';Same @($view.direct_groups|Sort-Object) @($baseline.directory.source_direct_groups|Sort-Object) 'replica direct groups';Same @($view.token_groups|Sort-Object) @($baseline.directory.source_token_groups|Sort-Object) 'replica token groups';Same @($view.reference_groups|Sort-Object) @($baseline.directory.source_reference_groups.sid|Sort-Object) 'replica reference groups'}
}
function Check-Capture([string]$Source,$Journal,$Summary) {
    $capture=Decode-Return (Join-Path $Source 'capture-return.json');$map=Read-Json (Join-Path $Source 'captured-evidence.json');$raw=Unlinked (Join-Path $Source 'raw')
    Same $map $Journal.captures 'capture map';Same (Decode-Return (Join-Path $Source 'guest-return.json')) $Summary 'returned and raw outcome'
    if($capture.run -cne $Journal.execution_id){throw 'Capture run differs.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
    foreach($file in @($capture.files)) {
        if(-not (Test-OnlineEvidenceName $file.name) -or -not $seen.Add($file.name) -or $file.length -lt 0 -or $file.length -gt 2097152 -or $file.bytes_base64.Length -gt 2796204){throw 'Capture file identity/size differs.'}
        $path=Within $raw $file.name;$bytes=[Convert]::FromBase64String($file.bytes_base64);$total+=$bytes.Length
        if($bytes.Length -ne $file.length -or $total -gt 33554432 -or (Bytes-Digest $bytes) -cne $file.sha256 -or $map.($file.name) -cne $file.sha256 -or (Get-Item -LiteralPath $path).Length -ne $file.length){throw 'Capture bytes differ.'}
        Pin $path $file.sha256
    }
    $files=@(Get-ChildItem -LiteralPath $raw -File -Force -Recurse)
    if($files.Count -ne $seen.Count -or @($map.PSObject.Properties).Count -ne $seen.Count){throw 'Raw capture file set differs.'}
    foreach($file in $files){$name=(Unlinked $file.FullName).Substring($raw.Length+1).Replace('\','/');if(-not $seen.Contains($name)){throw 'Unrecorded raw file.'}}
    foreach($owner in @('owner.txt','online-cases/owner.txt')){if([IO.File]::ReadAllText((Within $raw $owner)) -cne $Journal.execution_id){throw 'Captured owner differs.'}}
    foreach($case in $Summary.cases) {
        if($case.passed -isnot [bool] -or ($case.passed -and $null -ne $case.error) -or (-not $case.passed -and $null -eq $case.error)){throw 'Case pass/error state is inconsistent.'}
        $prefix='online-cases/'+$case.name+'/'
        foreach($name in @('case.json','result.json','child.requested.json','child.started.json','child.finished.json','child.stdout.txt','child.stderr.txt')){if(-not $seen.Contains($prefix+$name)){throw 'Required case evidence missing.'}}
        Same (Read-Json (Within $raw ($prefix+'result.json'))) $case 'case result';Same (Read-Json (Within $raw ($prefix+'child.finished.json'))) $case.process 'child terminal record'
        foreach($stream in @('stdout','stderr')){if($case.process.($stream+'_sha256') -cne $map.($prefix+'child.'+$stream+'.txt')){throw 'Child stream digest differs.'}}
        if($case.kind -ceq 'sdk'){Same (Read-Json (Within $raw ($prefix+'child.stdout.txt'))) $case.observation 'native wire observation';Bool $case.observation.data.checks_skipped $false 'online checks executed'}
        elseif($case.kind -ceq 'reference'){Same (Read-Json (Within $raw ($prefix+'reference.json'))) $case.observation 'reference observation';Bool $case.observation.completed $true 'reference completion';Bool $case.observation.offline $false 'reference online mode'}
        else {Same (Read-Json (Within $raw ($prefix+'membership.json'))) $case.observation 'membership observation';Bool $case.observation.completed $true 'membership completion';Bool $case.observation.mutation_uncertain $false 'membership certainty'}
        if($case.kind -cne 'membership' -and $case.output_after.exists){Pin (Within $raw ($prefix+'output.xml')) $case.output_after.sha256}
    }
    return $seen.Count
}
function Read-XMLProjection([string]$Path,[string]$SchemaPath) {
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create((Unlinked $Path),$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null
    try{$doc.Load($reader)}finally{$reader.Dispose()}
    $evidence=Read-Json $SchemaPath;$schemas=@($evidence.observation.files|Where-Object {$_.path -match 'DCCloneConfigSchema\.xsd$'})
    if($schemas.Count -ne 1){throw 'Captured schema cardinality differs.'}
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new([string]$schemas[0].text),$settings)
    try{$schema=[Xml.Schema.XmlSchema]::Read($reader,$null)}finally{$reader.Dispose()}
    [void]$doc.Schemas.Add($schema);$doc.Validate($null)
    return Project-OnlineXML $doc.DocumentElement
}

$target=Unlinked $target;$buildRoot=Unlinked $buildRoot
if(Test-Path -LiteralPath $target){throw 'Existing imported evidence is immutable.'}
Pin (Join-Path $buildRoot 'build.json') $pins.build;Pin (Join-Path $buildRoot 'helper-v3\build.json') $pins.helper_build
Pin (Join-Path $buildRoot 'source.zip') $pins.archive;Pin (Join-Path $buildRoot 'helper-v3\clone-config-helper.exe') $pins.binary
$build=Read-Json (Join-Path $buildRoot 'build.json');$helper=Read-Json (Join-Path $buildRoot 'helper-v3\build.json')
if($build.source_commit -cne $commit -or $helper.source_commit -cne $commit -or $build.source_archive_sha256 -cne $pins.archive -or $helper.source_archive_sha256 -cne $pins.archive -or $helper.helper_executable_sha256 -cne $pins.binary -or $build.status -cne 'built'){throw 'Build provenance differs.'}
foreach($property in $helper.source_hashes.PSObject.Properties){Pin (Within (Join-Path $buildRoot 'helper-v3') $property.Name) $property.Value}
$baselinePath=Join-Path $buildRoot 'server2025-online-inventory-v1\inventory.json';Pin $baselinePath $pins.baseline;$baseline=Read-Json $baselinePath
if(-not $baseline.completed -or $null -ne $baseline.error -or @($baseline.applications.reference_entries).Count -ne 28){throw 'Baseline incomplete.'}
Retain-Artifact (Join-Path $buildRoot 'source.zip') 'Verified source archive; retained on H:, not duplicated in Git.'
Retain-Artifact (Join-Path $buildRoot 'helper-v3\clone-config-helper.exe') 'Verified unchanged native executable; binaries are not imported.'
$validator=Join-Path $PSScriptRoot 'clone-online-v2\run-clone-config-online-qualification.ps1';Pin $validator $runs[1].host
Import-Functions $validator @('Get-OnlineCaseNames','Assert-OnlineMatrixState','Test-OnlineEvidenceName')
$guestValidator=Join-Path $PSScriptRoot 'clone-online-v2\guest-clone-config-online-qualification.ps1';Pin $guestValidator $runs[1].guest
Import-Functions $guestValidator @('Project-OnlineXML')
foreach($run in $runs) {
    $source=Unlinked (Join-Path $buildRoot $run.directory);$journal=Read-Json (Join-Path $source 'qualification.json')
    Check-Jobs $journal @('stage','online-qualification','capture') $run.passed
    Same (Read-Json (Join-Path $source 'run-journal.json')) $journal 'terminal host journal'
    $runID='clone-config-reviewed-20261112T215735Z-b4707e3f-online-qualification-server2025-'+$run.suffix
    if($journal.execution_id -cne $runID -or $journal.host_script_sha256 -cne $run.host -or $journal.bootstrap_sha256 -cne $run.bootstrap){throw 'Qualification run or harness identity differs.'}
    foreach($item in @(@('build.json',$pins.build),@('helper-v3-build.json',$pins.helper_build),@('clone-config-helper.go',$pins.helper_source),@('inventory.json',$pins.baseline),@('negative-process-support.ps1',$pins.process_support),@('schema-evidence.json',$pins.schema),@('run-clone-config-online-qualification.ps1',$run.host),@('guest-clone-config-online-qualification.ps1',$run.guest),@('bootstrap-clone-config-online-qualification.ps1',$run.bootstrap),@('inventory-support.ps1',$run.inventory))){Pin (Join-Path $source $item[0]) $item[1]}
    $summary=Read-Json (Join-Path $source 'raw\online-cases\summary.json');Assert-OnlineMatrixState $summary
    $expected=[ordered]@{run=$runID;source_commit=$commit;source_archive_sha256=$pins.archive;build_manifest_sha256=$pins.build;helper_build_manifest_sha256=$pins.helper_build;helper_source_sha256=$pins.helper_source;helper_binary_sha256=$pins.binary;harness_sha256=$run.guest;inventory_sha256=$pins.baseline;process_support_sha256=$pins.process_support;inventory_support_sha256=$run.inventory;schema_evidence_sha256=$pins.schema}
    foreach($key in $expected.Keys){if($summary.$key -cne $expected[$key] -or $journal.identity.$key -cne $expected[$key]){throw "Outcome provenance differs: $key"}}
    Bool $summary.passed $run.passed 'summary passed';Bool $summary.completed $run.passed 'summary complete';Bool $summary.cleanup_complete $run.passed 'summary cleanup'
    if($summary.computer -cne 'ADSDK25DC1'){throw 'Guest identity differs.'}
    if($run.suffix -ceq 'v1') {
        Pin (Join-Path $source 'raw\online-cases\summary.json') '6EF6FC734F7B201F1DC1DABD2A8892843531F7DCB1B1433AFF30744FEC28E506'
        if($summary.phase -cne 'inclusion-created' -or @($summary.cases).Count -ne 5 -or $summary.error.text -cne 'Current inventory is incomplete.' -or $summary.recovery.group_added -ne $true -or $null -eq $summary.recovery.custom_file -or $null -ne $summary.recovery.config_file){throw 'Original failure differs.'}
        foreach($case in $summary.cases){Bool $case.passed $true 'v1 case passed'}
    } else {
        Pin (Join-Path $source 'raw\online-cases\summary.json') '6BBB302CDC5BAD56C85EB34624A42EA148E1BD271C7D3941E8B6F64EFDCD661A'
        if($summary.phase -cne 'before-online-sdk-existing' -or @($summary.cases).Count -ne 7 -or
           $summary.error.text -cne 'Observed online case failed its expectation; retain evidence and recovery state.' -or
           $summary.recovery.group_added -ne $true -or $null -eq $summary.recovery.custom_file -or $null -eq $summary.recovery.config_file){throw 'Second failure differs.'}
        foreach($case in $summary.cases[0..5]){Bool $case.passed $true 'v2 preceding case passed'}
        $success=$summary.cases[5];$failed=$summary.cases[6]
        Bool $failed.passed $false 'v2 collision expectation failed'
        if($success.name -cne 'online-sdk-success' -or $success.process.exit_code -ne 0 -or $success.observation.data.outcome -cne 'written' -or
           $success.observation.error_details.present -ne $false -or $success.observation.data.prerequisites.complete -ne $true -or
           $failed.name -cne 'online-sdk-existing' -or $failed.process.exit_code -ne 1 -or $failed.observation.data.outcome -cne 'not_written' -or
           $failed.observation.error_details.message -cne 'read cloning PDC RootDSE: LDAP attribute enumeration: LDAP status 82' -or
           $failed.observation.error_details.output_exists -ne $false){throw 'Actual online success or LDAP 82 failure differs.'}
        Same $failed.output_before $failed.output_after 'failed call left output unchanged'
        Same $failed.output_after $success.output_after 'existing file belongs to prior successful call'
        Same $failed.output_after $summary.recovery.config_file 'owned configuration recovery record'
        $sdkXML=Read-XMLProjection (Join-Path $source 'raw\online-cases\online-sdk-success\output.xml') (Join-Path $source 'schema-evidence.json')
        $expectedXML=[ordered]@{name='DCCloneConfig';namespace='uri:microsoft.com:schemas:DCCloneConfig';value='';children=@([ordered]@{name='ComputerName';namespace='';value='ADSDK25CLONE';children=@()})}
        Same $sdkXML $expectedXML 'single schema-valid SDK output; no reference success comparison'
    }
    $rawCount=Check-Capture $source $journal $summary
    foreach($file in @(Get-ChildItem -LiteralPath $source -File -Force -Recurse|Sort-Object FullName)) {
        $path=Unlinked $file.FullName;$name=$path.Substring($source.Length+1)
        if($name -cin @('capture-return.json','guest-return.json')){Retain-Artifact $path 'Validated original transport envelope; raw bytes and capture map are imported without base64 duplication.'}
        else {Add-Artifact $path ($run.name+'/'+$name) $run.name}
    }
    $results.Add([ordered]@{name=$run.name;run=$runID;passed=$false;cases=@($summary.cases).Count;passed_cases=@($summary.cases|Where-Object passed).Count;raw_files=$rawCount;terminal_utc=$journal.updated;source=$source})
}

foreach($expected in $recoveries) {
    $recoveryRoot=Unlinked (Join-Path $buildRoot $expected.run);$journal=Read-Json (Join-Path $recoveryRoot 'qualification.json')
    Check-Jobs $journal @('exact-online-recovery') $true;Same (Read-Json (Join-Path $recoveryRoot 'run-journal.json')) $journal 'recovery terminal journal'
    if($journal.execution_id -cne $expected.run -or $journal.phase -cne 'restored' -or $journal.prior_journal_sha256 -cne $expected.prior_journal -or
       $journal.host_script_sha256 -cne $expected.host -or $journal.guest_script_sha256 -cne $expected.guest){throw 'Recovery identity differs.'}
    Pin (Join-Path $recoveryRoot 'recover-clone-config-online.ps1') $expected.host;Pin (Join-Path $recoveryRoot 'recover-clone-config-online-guest.ps1') $expected.guest
    Pin (Join-Path $recoveryRoot 'prior-summary.json') $expected.prior_summary
    Pin (Join-Path $results[$expected.prior_index].source 'run-journal.json') $expected.prior_journal
    $recovery=Read-Json (Join-Path $recoveryRoot 'recovery.json');Same (Decode-Return (Join-Path $recoveryRoot 'guest-return.json')) $recovery 'recovery transport'
    foreach($field in @('completed','passed','cleanup_complete','file_removed','member_removed')){Bool $recovery.$field $true $field}
    foreach($field in @('process_uncertain','publication_uncertain','mutation_uncertain','capture_failed')){Bool $recovery.$field $false $field}
    if($recovery.recovery_id -cne $expected.run -or $recovery.prior_run -cne $results[$expected.prior_index].run -or $recovery.phase -cne 'baseline-restored' -or
       $null -ne $recovery.error -or $recovery.recovery.group_added -ne $false -or $null -ne $recovery.recovery.custom_file -or $null -ne $recovery.recovery.config_file -or $null -ne $recovery.recovery.intent){throw 'Recovery restoration differs.'}
    if($expected.prior_index -eq 0){$shape=@($recovery.snapshots|Where-Object name -ceq 'exclusion-output-shape');if($shape.Count -ne 1 -or -not $shape[0].value.completed -or $shape[0].value.count -ne 1 -or @($shape[0].value.items).Count -ne 1 -or $shape[0].value.items[0].is_null -ne $true -or $null -ne $shape[0].value.error){throw 'Actual explicit-null observation differs.'}}
    $worlds=@($recovery.snapshots|Where-Object name -ceq 'world');if($worlds.Count -lt 1){throw 'Recovery world evidence absent.'};Check-RestoredWorld $worlds[-1].value
    $replicas=@($recovery.snapshots|Where-Object name -ceq 'replicas-restored');if($replicas.Count -ne 1){throw 'Recovery replica evidence absent.'};Check-RestoredReplicas $replicas[0].value
    foreach($file in @(Get-ChildItem -LiteralPath $recoveryRoot -File -Force|Sort-Object Name)){if($file.Name -ceq 'guest-return.json'){Retain-Artifact $file.FullName 'Validated recovery transport; complete recovery.json is imported.'}else{Add-Artifact $file.FullName ($expected.name+'/'+$file.Name) $expected.name}}
    foreach($version in @('ps51','ps7')) {
        $path=Join-Path $expected.test_directory ($expected.test_prefix+$version+$expected.test_suffix);$report=Read-Json $path
        Bool $report.passed $true 'recovery checks';if($report.count -ne $expected.checks -or $report.host_sha256 -cne $expected.host -or $report.guest_sha256 -cne $expected.guest){throw 'Recovery check provenance differs.'}
        Add-Artifact $path ('checks/'+$expected.name+'/'+[IO.Path]::GetFileName($path)) 'offline-checks'
    }
    Add-Artifact (Join-Path $expected.test_directory 'test-clone-config-online-recovery.ps1') ('checks/'+$expected.name+'/test-clone-config-online-recovery.ps1') 'offline-test-source'
    $recoveryResults.Add([ordered]@{name=$expected.name;run=$expected.run;prior_run=$recovery.prior_run;passed=$true;cleanup_complete=$true;terminal_utc=$journal.updated;source=$recoveryRoot})
}

foreach($version in @('ps51','ps7')) {
    foreach($item in @(@(('host-checks-'+$version+'.json'),'host',224),@(('guest-checks-'+$version+'.json'),'guest',84),@(('inventory-checks-'+$version+'-final.json'),'inventory',90))) {
        $path=Join-Path $PSScriptRoot ('clone-online-v2\'+$item[0]);$report=Read-Json $path;Bool $report.passed $true 'offline checks';if($report.checks -ne $item[2]){throw 'Offline check count differs.'}
        if($item[1] -ceq 'host'){if($report.host_sha256 -cne $runs[1].host -or $report.guest_sha256 -cne $runs[1].guest -or $report.bootstrap_sha256 -cne $runs[1].bootstrap){throw 'Host checks reference different scripts.'}}
        elseif($report.guest_sha256 -cne $runs[1].($item[1])){throw 'Guest/inventory checks reference a different script.'}
        Add-Artifact $path ('checks/v2/'+$item[0]) 'offline-checks'
    }
}
foreach($name in @('test-clone-config-online-inventory.ps1','test-clone-config-online-qualification.ps1','test-clone-config-online-qualification-host.ps1')){Add-Artifact (Join-Path $PSScriptRoot ('clone-online-v2\'+$name)) ('checks/v2/'+$name) 'offline-test-source'}
foreach($name in @('clone-config-helper_test.go','helper-tests.log','helper-build.log')){Add-Artifact (Join-Path $buildRoot ('helper-v3\'+$name)) ('build/'+$name) 'helper-build'}
Add-Artifact $PSCommandPath 'import-clone-config-online-partial.ps1' 'importer'
if($ValidateOnly){[pscustomobject]@{validated=$true;copied_artifacts=$plan.Count;retained_on_lab_volume=$retained.Count;runs=@($results.ToArray());recoveries=@($recoveryResults.ToArray());destination_created=$false}|ConvertTo-Json -Depth 6;return}

# All validation precedes destination creation. Existing evidence is never overwritten.
[void][IO.Directory]::CreateDirectory($target)
foreach($artifact in $plan){$to=Within $target $artifact.destination_name;[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($to));[IO.File]::Copy($artifact.source,$to,$false);Pin $artifact.source $artifact.sha256;Pin $to $artifact.sha256}
$encoding=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $target '.gitattributes'),"* -text whitespace=cr-at-eol`n*.ps1 whitespace=cr-at-eol,-blank-at-eof`n",$encoding)
$audit=[ordered]@{schema_version=1;imported_utc=[DateTime]::UtcNow.ToString('o');source_commit=$commit;source_archive_sha256=$pins.archive;helper_binary_sha256=$pins.binary;runs=@($results.ToArray());recoveries=@($recoveryResults.ToArray());artifacts=@($plan.ToArray());verified_retained_artifacts=@($retained.ToArray());full_matrix_passed=$false;reference_success_pair_observed=$false;coverage_states_changed=$false;staging_preserved=$true}
[IO.File]::WriteAllText((Join-Path $target 'import-audit.json'),($audit|ConvertTo-Json -Depth 12),$encoding)
$readme=@"
# Server 2025 online clone configuration partial evidence

This directory preserves two failed qualifications and their separate
successful recoveries. Both original qualification results remain failed.
The intended ten-case matrix was not completed, and no successful online
PowerShell generation was observed. Online SDK/reference parity is not claimed.

| Run | Completed observations | Outcome |
| --- | --- | --- |
| failed-v1 | Five cases passed; inventory then failed after inclusion creation. | Failed; recovered separately in recovery-v1. |
| failed-v2 | Six cases passed, including native online XML generation; seventh case failed with LDAP 82. | Failed; recovered separately in recovery-v2. |

The first run passed missing-group SDK/reference checks, direct membership
addition, and excluded-application SDK/reference checks. After creating the
owned custom inclusion list, the inventory helper failed with
``PropertyNotFoundStrict`` because the reference exclusion cmdlet emitted one
explicit null when no excluded applications remained. Recovery captured that
actual output shape, removed the exact owned list and membership, and verified
the original 28 exclusions, file state and both domain-controller replicas.
No configuration file had been created in that failed run.

The corrected inventory filters only null results before projecting Name and
Type. V2 uses the same SDK helper binary, SHA-256 $($pins.binary), built from SDK
commit $commit. The inventory correction changes the qualification harness.
Offline checks retained here passed in Windows PowerShell 5.1 and PowerShell 7:
90 inventory checks, 84 guest checks, 224 host checks, 40 first-recovery checks,
and 41 second-recovery checks. These checks do not convert the live failures
into passing qualifications.

V2 repeated the first five cases and then successfully called the SDK's online
generation API. Its one retained configuration file is schema-valid and names
ADSDK25CLONE. On the next call, which was intended to test existing-file
rejection, the SDK failed earlier with
``read cloning PDC RootDSE: LDAP attribute enumeration: LDAP status 82``.
The existing configuration's bytes, timestamps and ACL remained unchanged.
This is an unresolved native failure in this evidence snapshot; the call did
not establish the expected existing-output error. Reference existing-file
rejection and reference successful generation were never reached.

Both original runs have known-complete child/host processes and no recorded
process, publication, mutation or capture uncertainty. Their cleanup flags are
false because the test deliberately stopped at the observed failures.
Recovery-v1 reached verified restoration at $($recoveryResults[0].terminal_utc);
recovery-v2 reached verified restoration at $($recoveryResults[1].terminal_utc).
Each recovery removed only its recorded owned files and direct membership,
then verified file absence, original 28 exclusions and original membership
views on both DCs. The second recovery removed both the generated configuration
and custom inclusion list. All guest staging remains preserved.

These are Server 2025 observations from the isolated disposable lab. They do
not prove an actual VM clone/boot, a complete version matrix, every online
prerequisite failure, nested group behavior, reliable repeated online success,
or completion of broader #55/#78. No VM was cloned or restarted.

Every imported artifact is listed with its original location, byte length and
SHA-256 in import-audit.json. Original transport envelopes are verified against
the raw files and capture manifests before import; their hashes and retained
H: locations are recorded instead of duplicating base64 payloads in Git.
Original archives, executables, staging and failed evidence remain on H:.
All copied bytes are preserved; .gitattributes disables text conversion.
Go source snapshots use .go.txt names to avoid SDK package discovery.
The importer performs file validation/copying only and never executes a lab
harness, changes AD, or updates coverage/ticket states.
"@
[IO.File]::WriteAllText((Join-Path $target 'README.md'),$readme,$encoding)
[pscustomobject]@{target=$target;copied_artifacts=$plan.Count;retained_on_lab_volume=$retained.Count;both_qualifications_preserved_failed=$true;both_recoveries_passed=$true;full_matrix_passed=$false}|ConvertTo-Json
