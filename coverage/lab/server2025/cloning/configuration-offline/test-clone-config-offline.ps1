#Requires -Version 5.1
# AST-import helpers only. No wrapper entry point, Hyper-V, AD, or VM calls.
# The only real child processes are benign local Windows PowerShell exits 0/7.
param([string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:checks=0;$processObservations=[Collections.Generic.List[object]]::new()
function Check([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message };$script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $rejected=$false;try { & $Action } catch { $rejected=$true };Check $rejected $Message }
function Clone($Value) { return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json) }
function Import-Functions([string]$Path,[string[]]$Names) {
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count) { throw ($parseErrors | Out-String) }
    foreach($name in $Names) {
        $definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $name)
        if($definition.Count -ne 1) { throw "Expected one function: $name" }
        $code=$definition[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name)
        . ([scriptblock]::Create($code))
    }
    return $ast
}
$hostRunner=Join-Path $PSScriptRoot 'run-clone-config-offline.ps1';$guestRunner=Join-Path $PSScriptRoot 'guest-clone-config-offline.ps1'
$hostAST=Import-Functions $hostRunner @('Assert-UnlinkedPath','Assert-Build','Assert-OwnedControllers','Assert-SwitchPorts','Get-ProfileMutexName','Read-GuestOutcome','Test-EvidenceName','Wait-OwnedJob','Invoke-OwnedGuest','Assert-NewRunDirectory','Save-Capture')
$guestAST=Import-Functions $guestRunner @('Assert-GuestPath','Assert-GuestIdentity','Guest-Hash','Wait-OwnedProcess','Start-OwnedReferenceProcess','Assert-ReferenceSummary','Assert-NoOwnedNativeProcess','Invoke-ReferenceProcess','Get-RawCapture')
foreach($ast in @($hostAST,$guestAST)) {
    $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    foreach($forbidden in @('Start-VM','Stop-VM','Restart-VM','Remove-VM','Set-VM','Set-Acl','Add-ADGroupMember','Remove-ADGroupMember','Remove-Item','Stop-Process','New-ADDCCloneConfigFile')) {
        Check ($forbidden -notin $commands) "Runner contains forbidden direct action $forbidden."
    }
    Check ($ast.Extent.Text -notmatch '\.Kill\(') 'Runner kills an uncertain process.'
}
Check ($hostAST.Extent.Text.Contains('Get-ProfileMutexName $profile')) 'Canonical profile mutex is not acquired.'
Check ($hostAST.Extent.Text.Contains('Assert-OwnedControllers')) 'Current VM guards are missing.'
Check ($guestAST.Extent.Text.Contains('-WindowStyle Hidden')) 'Child process is visible.'
$captureSave=$hostAST.Extent.Text.IndexOf('Save-Capture $captured $outcome',[StringComparison]::Ordinal)
$captureEnvelope=$hostAST.Extent.Text.IndexOf("Write-NewHostJson (Join-Path `$resultRoot 'capture-return.json')",[StringComparison]::Ordinal)
Check ($captureEnvelope -gt 0 -and $captureSave -gt $captureEnvelope) 'Raw capture envelope is not preserved before validation.'

$fixtureRoot=Join-Path $PSScriptRoot ('clone-config-offline-tests-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureRoot)
$powerShell=Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
foreach($expected in @(0,7,7)) {
    $ordinal=$processObservations.Count;$record=[ordered]@{pid=$null;started_utc=$null};$process=$null
    try {
        $process=Start-OwnedReferenceProcess $powerShell ('-NoLogo -NoProfile -NonInteractive -Command "exit '+$expected+'"') (Join-Path $fixtureRoot "exit-$ordinal.stdout.txt") (Join-Path $fixtureRoot "exit-$ordinal.stderr.txt") $record
        Check (Wait-OwnedProcess $process 15) 'Benign child did not exit within its bound.'
        $exitCode=$process.ExitCode
        Check ($null -ne $exitCode -and $exitCode -eq $expected) 'Held-handle child exit evidence is missing or wrong.'
        Check ($record.pid -gt 0 -and $record.started_utc -and $process.HasExited) 'Child identity or exit state is missing.'
        $processObservations.Add([ordered]@{pid=$record.pid;started_utc=$record.started_utc;expected_exit=$expected;actual_exit=$exitCode;has_exited=$process.HasExited})
    } finally { if($null -ne $process) { $process.Dispose() } }
}
$blocked=[pscustomobject]@{calls=0}
$blocked | Add-Member ScriptMethod WaitForExit {param($milliseconds) $this.calls++;return $false}
Check (-not (Wait-OwnedProcess $blocked 0) -and $blocked.calls -eq 0) 'Expired process deadline waited, retried, or claimed completion.'

# Actual path canonicalization; the synthetic link classification never creates a link.
Check ((Assert-UnlinkedPath $fixtureRoot) -ceq ([IO.Path]::GetFullPath($fixtureRoot))) 'Unlinked fixture path failed.'
$script:fakeLink=$fixtureRoot
function Get-Item { param([string]$LiteralPath,[switch]$Force) if($LiteralPath -ceq $script:fakeLink) { return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint} };Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force }
Reject { Assert-UnlinkedPath (Join-Path $fixtureRoot 'child.txt') } 'Host accepted a reparse ancestor.'
Reject { Assert-GuestPath (Join-Path $fixtureRoot 'child.txt') } 'Guest accepted a reparse ancestor.'
$script:fakeLink=''

$ExpectedManifestSHA256='6AB9B1B9129A39BC9C68FB4B00CB38D6DB4A31C4E925BB1C3790431927AD9E29'
$build=[pscustomobject]@{run='clone-config-reviewed-20261112T211528Z-81823b4e';source_commit='4120ce5d13dd49de490cef67d41767ac3b409715';status='built';directory='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T211528Z-81823b4e';source_archive_sha256='1FA1A904FDEE8ED7F49428117C8215989F895E3EBCF7AC3554827248654C2E19';native_executable_sha256='9FC1C95989517E0AC5753747B56FB17931C8ECB387E22083F6B0B60C6D4642B2';reference_harness_sha256='3F68500FEC99CAF5948E4C391B62AD51CCB0A4C65A50C4D52E2E423DC4CCDC45';schema_evidence_sha256='A061F397D27B26563E6B4C7D611F707F5A3CA4A5B9CBD3353CB2CDC7BA9D7F35';test_executable_sha256=('A'*64);builder_sha256=('B'*64);toolchain='fixture';built_utc='2026-11-12T21:15:28Z'}
$artifactPaths=[ordered]@{source_archive='source.zip';native_executable='dccloneconfig.exe';test_executable='dccloning.test.exe';reference_harness='source\scripts\lab\reference-dc-clone-config.ps1';schema_evidence='source\docs\research\dc-cloning-evidence\server2025-readonly.json'}
$script:hashes=@{}
foreach($name in $artifactPaths.Keys) { $path=Join-Path $build.directory $artifactPaths[$name];$build | Add-Member NoteProperty $name $path;$script:hashes[$path]=$build.($name+'_sha256') }
function Assert-UnlinkedPath([string]$Path) { return [IO.Path]::GetFullPath($Path) }
function Get-FileHash { param([string]$LiteralPath,[string]$Algorithm) if($script:hashes.ContainsKey($LiteralPath)) { return [pscustomobject]@{Hash=$script:hashes[$LiteralPath]} };Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256 }
Assert-Build $build;$script:checks++
foreach($field in @('run','source_commit','status','directory','source_archive_sha256','native_executable_sha256','reference_harness_sha256','schema_evidence_sha256','source_archive','native_executable','test_executable','reference_harness','schema_evidence','test_executable_sha256','builder_sha256','toolchain','built_utc')) {
    $bad=Clone $build;$bad.$field=if($field -in @('toolchain','built_utc')){''}else{'invalid'}
    Reject { Assert-Build $bad } "Build accepted altered $field."
}
$script:hashes[$build.native_executable]='C'*64
Reject { Assert-Build $build } 'Build accepted altered executable bytes.'
$script:hashes[$build.native_executable]=$build.native_executable_sha256

# Current owned-machine, switch, disk, and NIC models. No Hyper-V commands load.
$profile='H:\ad-sdk-lab\server2025';$statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml';$stateHash='D'*64;$script:hashes[$statePath]=$stateHash
$script:lab=[pscustomobject]@{id='60197892-ec9f-4c19-abe8-34dc60d473e5';switch_id='18cf982f-8c11-45cd-8581-fc2a00648deb';switch_name='private-fixture';machines=@([pscustomobject]@{role='dc1';id='a364b1d0-7868-47f1-ab29-a5e80c97aa4b';name='ADSDK25DC1'},[pscustomobject]@{role='dc2';id='e9097666-5393-4c38-b80b-68d56c749b98';name='ADSDK25DC2'},[pscustomobject]@{role='member';id='80aa4382-c228-489c-b5f7-007c7feee3ff';name='ADSDK25MEM'})}
$script:originalLab=Clone $script:lab;$script:guardMutation='';$script:vmCalls=0
function Get-Content { param([string]$LiteralPath,[switch]$Raw) if($LiteralPath -ceq $statePath) { return ($script:lab | ConvertTo-Json -Depth 10) };Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -Raw:$Raw }
function Get-VMSwitch { param($Id) return [pscustomobject]@{Id=[guid]$script:lab.switch_id;Name=$script:lab.switch_name;Notes=('ad-sdk-lab:'+$script:lab.id);SwitchType=$(if($script:guardMutation -ceq 'external switch'){'External'}else{'Private'})} }
function Get-VM { param($Id) $script:vmCalls++;$item=@($script:lab.machines | Where-Object id -ceq $Id.ToString())[0];return [pscustomobject]@{Id=$Id;Name=$item.name;Notes=$(if($script:guardMutation -ceq 'owner'){'foreign'}else{'ad-sdk-lab:'+$script:lab.id});State=$(if($script:guardMutation -ceq 'member running' -or $item.role -cne 'member'){'Running'}else{'Off'});Path=(Join-Path $profile $item.name)} }
function Get-VMHardDiskDrive { param($VM) return [pscustomobject]@{Path=$(if($script:guardMutation -ceq 'outside disk'){'H:\foreign\disk.vhdx'}else{Join-Path $VM.Path 'disk.vhdx'})} }
function Get-VMNetworkAdapter { param($VM) $nic=[pscustomobject]@{Id=('Microsoft:'+$VM.Id.ToString()+'\E814B473-C899-4C92-A97B-CCB2D4AF000C');SwitchId=$(if($script:guardMutation -ceq 'wrong NIC'){[guid]::Empty}else{[guid]$script:lab.switch_id})};if($script:guardMutation -ceq 'extra NIC'){return @($nic,$nic)};if($script:guardMutation -ceq 'malformed adapter ID'){$nic.Id='foreign'};return $nic }
function Get-CimInstance {
    param([string]$Namespace,[string]$ClassName,[int]$OperationTimeoutSec,[string]$ErrorAction,[string]$Filter)
    if($Namespace -cne 'root/virtualization/v2' -or $ClassName -cne 'Msvm_EthernetPortAllocationSettingData' -or $OperationTimeoutSec -ne 10 -or $ErrorAction -cne 'Stop' -or $Filter) { throw 'Unexpected or state-filtered topology query.' }
    if($script:guardMutation -ceq 'CIM failure') { throw 'Injected CIM query failure.' }
    $resource='\\SHOCONE\root\virtualization\v2:Msvm_VirtualEthernetSwitch.CreationClassName="Msvm_VirtualEthernetSwitch",Name="'+$script:lab.switch_id+'"'
    $ports=@($script:lab.machines | ForEach-Object {[pscustomobject]@{InstanceID=('Microsoft:'+$_.id+'\E814B473-C899-4C92-A97B-CCB2D4AF000C\C');HostResource=@($resource);EnabledState=$(if($_.role -ceq 'member'){3}else{2})}})
    switch -CaseSensitive ($script:guardMutation) {
        'extra foreign VM' { $ports+=@([pscustomobject]@{InstanceID='Microsoft:ffffffff-ffff-ffff-ffff-ffffffffffff\E814B473-C899-4C92-A97B-CCB2D4AF000C\C';HostResource=@($resource);EnabledState=3}) }
        'missing off member' { $ports=@($ports[0],$ports[1]) }
        'duplicate port' { $ports+=@($ports[0]) }
        'missing resource' { $ports[2].HostResource=$null }
        'malformed resource' { $ports[0].HostResource=@($resource+'garbage') }
        'multiple resources' { $ports[0].HostResource=@($resource,$resource) }
        'nonstring resource' { $ports[0].HostResource=@(42) }
        'foreign host resource' { $ports[0].HostResource=@($resource.Replace('SHOCONE','FOREIGN')) }
        'case differences' { foreach($port in $ports) {$port.InstanceID=$port.InstanceID.ToLowerInvariant();$port.HostResource=@($resource.ToLowerInvariant())} }
        'unrelated allocations' { $ports+=@([pscustomobject]@{InstanceID='unconnected';HostResource=$null;EnabledState=3},[pscustomobject]@{InstanceID='another-switch';HostResource=@($resource.Replace($script:lab.switch_id,'00000000-0000-0000-0000-000000000001'));EnabledState=2}) }
    }
    if($script:guardMutation.StartsWith('management ',[StringComparison]::Ordinal)) {
        $managementResource='\\SHOCONE\root\virtualization\v2:Msvm_ComputerSystem.CreationClassName="Msvm_ComputerSystem",Name="SHOCONE"'
        $management=[pscustomobject]@{InstanceID='opaque-allocation-identity';HostResource=@($managementResource);Parent=$null;EnabledState=3}
        if($script:guardMutation -ceq 'management parent') { $management.Parent='unexpected' }
        if($script:guardMutation -ceq 'management foreign host') { $management.HostResource=@($managementResource.Replace('SHOCONE','FOREIGN')) }
        if($script:guardMutation -ceq 'management multiple resources') { $management.HostResource=@($managementResource,$managementResource) }
        $ports+=@($management)
        if($script:guardMutation -ceq 'management unrelated') { $ports+=@((Clone $management),(Clone $management),(Clone $management)) }
    }
    return $ports
}
function Get-CimAssociatedInstance {
    param($InputObject,[string]$ResultClassName,[int]$OperationTimeoutSec,[string]$ErrorAction)
    if($ResultClassName -cne 'Msvm_VirtualEthernetSwitchSettingData' -or $OperationTimeoutSec -ne 10 -or $ErrorAction -cne 'Stop' -or $InputObject.InstanceID -cne 'opaque-allocation-identity') { throw 'Unexpected management ownership query.' }
    $script:associationCalls++
    if($script:guardMutation -ceq 'management query failure') { throw 'Injected association query failure.' }
    if($script:guardMutation -ceq 'management no owner') { return @() }
    $switchID='9B13F651-2766-4D41-A7C2-1908B7622620'
    if($script:guardMutation -ceq 'management owned switch') { $switchID=$script:lab.switch_id }
    if($script:guardMutation -ceq 'management malformed owner') { $switchID='bad' }
    if($script:guardMutation -ceq 'management empty owner') { $switchID=[guid]::Empty.ToString() }
    $owner=[pscustomobject]@{VirtualSystemIdentifier=$switchID;InstanceID=('Microsoft:'+$switchID)}
    if($script:guardMutation -ceq 'management inconsistent owner') { $owner.InstanceID='Microsoft:other' }
    if($script:guardMutation -ceq 'management multiple owners') { return @($owner,(Clone $owner)) }
    return $owner
}
$script:associationCalls=0
Assert-OwnedControllers;Check ($script:vmCalls -eq 3) 'Not all three owned VMs were guarded.'
foreach($mutation in @('external switch','owner','member running','outside disk','wrong NIC','extra NIC','malformed adapter ID','extra foreign VM','missing off member','duplicate port','missing resource','malformed resource','multiple resources','nonstring resource','foreign host resource','CIM failure')) { $script:guardMutation=$mutation;Reject { Assert-OwnedControllers } "Guard accepted $mutation." };$script:guardMutation=''
foreach($mutation in @('management owned switch','management parent','management foreign host','management multiple resources','management query failure','management no owner','management malformed owner','management empty owner','management inconsistent owner','management multiple owners')) { $script:guardMutation=$mutation;Reject { Assert-OwnedControllers } "Guard accepted $mutation." };$script:guardMutation=''
foreach($mutation in @('case differences','unrelated allocations','management unrelated')) { $script:guardMutation=$mutation;$script:associationCalls=0;Assert-OwnedControllers;$script:checks++;if($mutation -ceq 'management unrelated') { Check ($script:associationCalls -eq 4) 'Not every unrelated management allocation was corroborated.' } };$script:guardMutation=''
foreach($field in @('id','switch_id')) { $script:lab=Clone $script:originalLab;$script:lab.$field=[guid]::Empty.ToString();Reject { Assert-OwnedControllers } "Guard accepted wrong $field." }
$script:lab=Clone $script:originalLab;$script:lab.machines[2].id=$script:lab.machines[0].id;Reject { Assert-OwnedControllers } 'Guard accepted duplicate VM IDs.'
$script:lab=Clone $script:originalLab;$script:hashes[$statePath]='E'*64;Reject { Assert-OwnedControllers } 'Guard accepted changed state bytes.';$script:hashes[$statePath]=$stateHash
Check ((Get-ProfileMutexName $profile) -ceq (Get-ProfileMutexName $profile.ToUpperInvariant())) 'Mutex differs by profile case.'

$executionID=$build.run+'-offline-server2025-v1'
$outcome=[pscustomobject]@{run=$executionID;source_commit=$build.source_commit;native_sha256=$build.native_executable_sha256;reference_sha256=$build.reference_harness_sha256;schema_sha256=$build.schema_evidence_sha256;completed=$true;process_uncertain=$false;passed=$true;pid=42;started_utc='2026-11-12T21:20:00Z';exit_code=0}
$null=Read-GuestOutcome ($outcome | ConvertTo-Json -Compress);$script:checks++
foreach($mutation in @({$bad.completed=$false},{$bad.process_uncertain=$true},{$bad.native_sha256='A'*64},{$bad.pid=0},{$bad.exit_code=$null},{$bad.exit_code=7},{$bad.passed='true'})) {
    $bad=Clone $outcome;$script:guestUncertain=$false;& $mutation
    Reject { Read-GuestOutcome ($bad | ConvertTo-Json -Compress) } 'Host accepted uncertain/mismatched guest completion.'
    Check $script:guestUncertain 'Invalid completion did not freeze further guest work.'
}
function Assert-OwnedControllers { throw 'Should not reach VM guard after uncertainty.' }
$script:guestUncertain=$true
Reject { Invoke-OwnedGuest -Script {} -Arguments @() -TimeoutSeconds 1 -Action 'forbidden-after-timeout' } 'Uncertainty allowed another guest call.'

$script:journalWrites=0;$runState=[ordered]@{jobs=@()}
function Write-RunState { $script:journalWrites++ }
function Wait-Job { param($Job,$Timeout) return $Job }
function Remove-Job { param($Job,$ErrorAction) $script:removed=$true }
function Receive-Job { param($Job,$ErrorAction) return 'completed-payload' }
$job=[pscustomobject]@{Id=42;State='Running';stops=0};$job | Add-Member ScriptMethod StopJobAsync {$this.stops++}
$script:guestUncertain=$false;$script:removed=$false
Reject { Wait-OwnedJob $job 0 'timeout-fixture' } 'Owned job exceeded deadline without failure.'
Check ($script:guestUncertain -and $job.stops -eq 1 -and -not $script:removed -and $runState.jobs[0].timeout) 'Timeout retried, removed a live job, or lost uncertainty.'
$job=[pscustomobject]@{Id=43;State='Completed'};$script:guestUncertain=$false;$script:removed=$false
Check ((@(Wait-OwnedJob $job 1 'completed-fixture'))[0] -ceq 'completed-payload' -and $script:removed) 'Completed owned job did not return/remove correctly.'

foreach($valid in @('owner.txt','guest-process.json','reference.stdout.txt','reference.stderr.txt','results/clone-config-0123456789abcdef0123456789abcdef/summary.json','results/clone-config-0123456789abcdef0123456789abcdef/default/sdk/DCCloneConfig.xml')) { Check (Test-EvidenceName $valid) 'Valid raw evidence name rejected.' }
foreach($badName in @('../escape','C:/escape','results/../escape','results/clone-config-0123456789abcdef0123456789abcdef/default/sdk/DCCloneConfig.xml:stream','results/clone-config-0123456789abcdef0123456789abcdef/unexpected/sdk.json')) { Check (-not (Test-EvidenceName $badName)) 'Unsafe evidence name accepted.' }
$resultRoot=Join-Path $fixtureRoot 'capture';[void][IO.Directory]::CreateDirectory($resultRoot);$runState.captures=[ordered]@{}
function Write-NewHostBytes { param([string]$Path,[byte[]]$Bytes) [IO.File]::WriteAllBytes($Path,$Bytes) }
function Write-NewHostJson { param([string]$Path,$Value) [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 20)) }
$file=[pscustomobject]@{name='owner.txt';length=1;sha256=(Guest-Hash ([byte[]]@(1)));bytes_base64='AQ=='}
foreach($mutation in @({$file.name='../escape'},{$file.length=2097153},{$file.sha256='A'*64})) {
    $file=[pscustomobject]@{name='owner.txt';length=1;sha256=(Guest-Hash ([byte[]]@(1)));bytes_base64='AQ=='};& $mutation
    $capture=[ordered]@{run=$executionID;files=@($file,$file,$file)} | ConvertTo-Json -Depth 8 -Compress
    Reject { Save-Capture $capture $outcome } 'Capture accepted an invalid name/size/hash or duplicate.'
}

# A complete synthetic raw capture exercises the real success validator and
# per-case hash binding, without invoking the reference or touching a guest.
$caseNames=@('default','name-site','v4-dynamic','v4-static','v6-dynamic','v6-static','dual-dynamic','dual-static','four-resolvers','overwrite')
$prefix='results/clone-config-0123456789abcdef0123456789abcdef/'
$rawFiles=[Collections.Generic.List[object]]::new();$cases=[Collections.Generic.List[object]]::new()
function Add-RawFixture([string]$Name,[byte[]]$Bytes) { $rawFiles.Add([ordered]@{name=$Name;length=$Bytes.Length;sha256=(Guest-Hash $Bytes);bytes_base64=[Convert]::ToBase64String($Bytes)}) }
foreach($name in @('owner.txt','guest-process.json','reference.stdout.txt','reference.stderr.txt')) { Add-RawFixture $name ([byte[]]@(1)) }
$xmlBytes=[Text.Encoding]::UTF8.GetBytes('<fixture/>');$xmlHash=Guest-Hash $xmlBytes
foreach($name in $caseNames) {
    foreach($suffix in @('sdk.json','sdk.stderr.txt','reference.streams.txt','sdk/DCCloneConfig.xml','reference/DCCloneConfig.xml')) { Add-RawFixture ($prefix+$name+'/'+$suffix) $xmlBytes }
    $cases.Add([pscustomobject]@{name=$name;passed=$true;error=$null;sdk_sha256=$xmlHash;reference_sha256=$xmlHash})
}
$summary=[pscustomobject]@{computer='ADSDK25DC1';mode='explicit offline only';sdk_sha256=$build.native_executable_sha256;schema_evidence_sha256=$build.schema_evidence_sha256;os_version='fixture';powershell='fixture';module_version='fixture';assembly_version='fixture';assembly_sha256=('A'*64);cases=@($cases.ToArray())}
Add-RawFixture ($prefix+'summary.json') ([Text.Encoding]::UTF8.GetBytes(($summary | ConvertTo-Json -Depth 12 -Compress)))
$identity=[pscustomobject]@{native_sha256=$build.native_executable_sha256;schema_sha256=$build.schema_evidence_sha256}
Assert-ReferenceSummary $summary $identity;$script:checks++
foreach($mutation in @({$bad.cases[0].passed=$false},{$bad.cases[0].passed='true'},{$bad.cases[0].name='invented'},{$bad.cases[0].sdk_sha256='bad'},{$bad.sdk_sha256='A'*64})) {
    $bad=Clone $summary;& $mutation;Reject { Assert-ReferenceSummary $bad $identity } 'Guest accepted invalid reference summary evidence.'
}
$capture=[ordered]@{run=$executionID;files=@($rawFiles.ToArray())} | ConvertTo-Json -Depth 12 -Compress
Save-Capture $capture $outcome;Check ($runState.captures.Count -eq 55) 'Complete raw capture did not bind every hash.'
$bad=Clone $summary;$bad.cases[0].sdk_sha256='B'*64
$rawFiles[$rawFiles.Count-1]=[ordered]@{name=($prefix+'summary.json');length=0;sha256='';bytes_base64=''}
$badBytes=[Text.Encoding]::UTF8.GetBytes(($bad | ConvertTo-Json -Depth 12 -Compress))
$rawFiles[$rawFiles.Count-1].length=$badBytes.Length;$rawFiles[$rawFiles.Count-1].sha256=Guest-Hash $badBytes;$rawFiles[$rawFiles.Count-1].bytes_base64=[Convert]::ToBase64String($badBytes)
$capture=[ordered]@{run=$executionID;files=@($rawFiles.ToArray())} | ConvertTo-Json -Depth 12 -Compress
Reject { Save-Capture $capture $outcome } 'Host accepted a summary XML hash different from captured bytes.'

$record=[ordered]@{passed=$true;checks=$script:checks;collected_utc=[DateTime]::UtcNow.ToString('o');powershell=$PSVersionTable.PSVersion.ToString();scope='offline AST guards/mocks plus benign local Windows PowerShell exit-0/7 children only; no host runner, Hyper-V, AD, or VM execution';host_script_sha256=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $hostRunner -Algorithm SHA256).Hash;guest_script_sha256=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $guestRunner -Algorithm SHA256).Hash;process_observations=@($processObservations.ToArray());fixture_directory=$fixtureRoot}
if($OutputPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($record | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false)) }
$record | ConvertTo-Json -Depth 12
