#Requires -Version 5.1
# Offline only: AST-import selected functions. Never dot-source either runner.
# VM/AD/file ACL operations are mocked; ACL objects below are in memory only.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:checks=0
function Check([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message };$script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $rejected=$false;try { & $Action } catch { $rejected=$true };Check $rejected $Message }
function Import-Functions([string]$Path,[string[]]$Names) {
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count) { throw ($parseErrors | Out-String) }
    foreach($name in $Names) {
        $definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $name)
        if($definition.Count -ne 1) { throw "Expected exactly one function: $name" }
        $code=$definition[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name)
        . ([ScriptBlock]::Create($code))
    }
}
$guest=Join-Path $PSScriptRoot 'guest-cloning-access-cases.ps1';$hostRunner=Join-Path $PSScriptRoot 'run-cloning-access-cases.ps1'
Import-Functions $guest @('Entry-Keys','Same-Entries','Is-Subset','Assert-PositiveInspection','Assert-PositiveGeneration','Assert-KnownPublication','Assert-PositiveNativeGeneration','Test-RegistryDenial','Test-ReadDenial','Test-WriteDenial','Error-Observation','Denial-Probe','Get-Descriptor','Deny-FileRight','Restore-FileSecurity','Write-NewJson','Assert-ObservationAllowed','Complete-DenialCase','Native-Observation','Reference-Observation')
Import-Functions $hostRunner @('Assert-UnlinkedPath','Assert-Build','Assert-OwnedControllers','Assert-CaptureComplete','Get-ProfileMutexName','Write-RunState','Wait-OwnedJob','Invoke-OwnedGuest','Assert-NewRunDirectory','Read-CompletedGuestOutcome')
$fileJobSets=@((Get-Command Invoke-Command).ParameterSets | Where-Object {'VMId' -in $_.Parameters.Name -and 'FilePath' -in $_.Parameters.Name -and 'AsJob' -in $_.Parameters.Name})
Check ($fileJobSets.Count -eq 1) 'This PowerShell version cannot launch the reviewed guest file as a PowerShell Direct job.'
function Clone($Value) { return ($Value | ConvertTo-Json -Depth 16 | ConvertFrom-Json) }
function No-Error { return [pscustomobject]@{present=$false;message='';permission=$false;incomplete=$false;native_error=$null;errno_code=$null} }
$programName='owned program'
$expected=@([pscustomobject]@{type='Service';name='retained'},[pscustomobject]@{type='Program';name=$programName},[pscustomobject]@{type='WoW64Program';name=$programName})
$native=[pscustomobject]@{exit_code=0;error=$null;stderr='';data=[pscustomobject]@{complete=$true;authorization_limited=$true;entries=$expected};error_details=(No-Error)}
$reference=[pscustomobject]@{error=$null;entries=$expected}
Assert-PositiveInspection $native $reference $expected;$script:checks++
Check (Same-Entries $expected @($expected[2],$expected[1],$expected[0])) 'Entry order changed equality.'
Check (-not (Same-Entries $expected @($expected[0],$expected[1]))) 'Missing registry view was accepted.'
Check (-not (Is-Subset @($expected[0],$expected[0]) $expected)) 'Duplicate invented entries were accepted.'
$bad=Clone $native;$bad.exit_code=1;$bad.error_details.present=$true;$bad.data.complete=$false
$badReference=Clone $reference;$badReference.error='injected failure'
Reject { Assert-PositiveInspection $bad $badReference $expected } 'Mutual failures passed a positive inspection.'
$goodGeneration=[pscustomobject]@{exit_code=0;error=$null;stderr='';timed_out=$false;file_observation=[pscustomobject]@{error=$null};error_details=(No-Error);data=[pscustomobject]@{outcome='written';result=[pscustomobject]@{complete=$true;entries=$expected}}}
Assert-PositiveGeneration $goodGeneration $reference $expected $expected $expected;$script:checks++
$badGeneration=Clone $goodGeneration;$badGeneration.exit_code=1;$badGeneration.data.outcome='not_written'
Reject { Assert-PositiveGeneration $badGeneration $badReference $expected $expected $expected } 'Mutual failures passed a positive overwrite.'
Reject { Assert-PositiveGeneration $goodGeneration $reference @() @() $expected } 'Successful status without expected generated entries passed.'
$script:evidenceFailure=$false;$script:ownedProcessUncertain=$false;$script:preserveFixture=$false
Assert-PositiveNativeGeneration $goodGeneration $expected $expected;$script:checks++
foreach($mutation in @(
    {$script:changed.data.outcome='uncertain'},
    {$script:changed.timed_out=$true},
    {$script:changed.error='malformed JSON'},
    {$script:changed.data=$null},
    {$script:changed.data=[pscustomobject]@{}},
    {$script:changed.file_observation.error='capture failed'},
    {$script:evidenceFailure=$true},
    {$script:ownedProcessUncertain=$true}
)) {
    $script:changed=Clone $goodGeneration;$script:preserveFixture=$false;$script:evidenceFailure=$false;$script:ownedProcessUncertain=$false
    & $mutation
    $script:writerReached=$false
    Reject { Assert-KnownPublication $changed;$script:writerReached=$true } 'Unknown write allowed the next writer.'
    Check ($script:preserveFixture -and -not $script:writerReached) 'Unknown publication did not preserve the fixture.'
}
$script:evidenceFailure=$false;$script:ownedProcessUncertain=$false;$script:preserveFixture=$false
Reject { Assert-PositiveNativeGeneration $goodGeneration @() $expected } 'Native schema/contents failure allowed the reference writer.'
Check $script:preserveFixture 'Native positive failure did not preserve captured output.'

$registry=Clone $native;$registry.exit_code=1;$registry.data.complete=$false;$registry.data.entries=@($expected[0],$expected[2])
$registry.error_details=[pscustomobject]@{present=$true;message='localised text';permission=$true;incomplete=$true;native_error=[pscustomobject]@{code=5;operation='RegOpenKeyExW(program)'};errno_code=5}
Check (Test-RegistryDenial $registry $expected $programName) 'Typed native registry denial failed.'
foreach($mutation in @(
    {$script:changed.data.complete=$true},
    {$script:changed.error_details.native_error.code=2},
    {$script:changed.error_details.native_error=$null},
    {$script:changed.error_details.errno_code=2},
    {$script:changed.error_details.permission=$false},
    {$script:changed.error_details.incomplete=$false},
    {$script:changed.data.entries=@($expected[0])},
    {$script:changed.data.entries+=@([pscustomobject]@{type='Service';name='invented'})},
    {$script:changed.data.entries+=$expected[1]}
)) { $script:changed=Clone $registry;& $mutation;Check (-not (Test-RegistryDenial $changed $expected $programName)) 'Invalid partial/typed-error registry observation passed.' }
$read=Clone $registry;$read.data.entries=@();$read.error_details.native_error=$null;$read.error_details.incomplete=$false;$read.error_details.message='read custom inclusion list: owned.xml: permission denied'
Check (Test-ReadDenial $read 'owned.xml') 'Typed file read denial failed.'
$changed=Clone $read;$changed.error_details.errno_code=$null
Check (-not (Test-ReadDenial $changed 'owned.xml')) 'Read stderr wording invented an errno.'
$changed=Clone $read;$changed.data.complete=$true
Check (-not (Test-ReadDenial $changed 'owned.xml')) 'Unreadable custom list was treated as complete.'
$changed=Clone $read;$changed.data.entries=@($expected[0])
Check (-not (Test-ReadDenial $changed 'owned.xml')) 'Read failure invented entries.'
$write=Clone $goodGeneration;$write.exit_code=1;$write.data.outcome='not_written';$write.error_details=Clone $read.error_details;$write.error_details.message='create inclusion temporary file: permission denied'
Check (Test-WriteDenial $write $expected 'HASH' 'HASH') 'Typed generation denial failed.'
Check (-not (Test-WriteDenial $write $expected 'HASH' 'CHANGED')) 'Generation failure changed the seed.'
$changed=Clone $write;$changed.data.outcome='uncertain'
Check (-not (Test-WriteDenial $changed $expected 'HASH' 'HASH')) 'Uncertain publication passed as not written.'
$changed=Clone $write;$changed.error_details.permission=$false
Check (-not (Test-WriteDenial $changed $expected 'HASH' 'HASH')) 'Unrelated failure passed as permission denial.'
Check (Denial-Probe {throw [UnauthorizedAccessException]::new('injected')}).denied 'Typed UnauthorizedAccessException was not recognized.'
Check (-not (Denial-Probe {throw [InvalidOperationException]::new('injected')}).denied) 'Unrelated probe failure counted as access denied.'
Check (-not (Denial-Probe {}).denied) 'Successful probe counted as denied.'
$win32Denied=[ComponentModel.Win32Exception]::new(5)
$win32Probe=Denial-Probe {throw $win32Denied}
Check ($win32Probe.denied -and $win32Probe.error.exceptions[-1].native_error_code -eq 5 -and $win32Probe.error.exceptions[-1].hresult -eq $win32Denied.HResult) 'Typed Win32 status 5 was lost or replaced by its HRESULT.'
Check (-not (Denial-Probe {throw [ComponentModel.Win32Exception]::new(2)}).denied) 'Unrelated typed Win32 status counted as access denied.'
$unrelatedLowWord=[Runtime.InteropServices.COMException]::new('Unrelated HRESULT facility with low word 5',-2146238459)
$unrelatedProbe=Denial-Probe {throw $unrelatedLowWord}
Check (-not $unrelatedProbe.denied -and $unrelatedProbe.error.exceptions[-1].hresult_low_word -eq 5 -and $null -eq $unrelatedProbe.error.exceptions[-1].native_error_code) 'An arbitrary HRESULT low word was treated as native access denied.'
# Exact nested exception types/message/HRESULTs captured by the terminal v1 run.
$registrySecurity=[Security.SecurityException]::new('Requested registry access is not allowed.')
$nestedRegistrySecurity=[Management.Automation.MethodInvocationException]::new('Exception calling "OpenSubKey" with "3" argument(s): "Requested registry access is not allowed."',$registrySecurity)
$genericSecurityProbe=Denial-Probe {throw $nestedRegistrySecurity}
Check (-not $genericSecurityProbe.denied) 'Generic file probe accepted registry-only SecurityException semantics.'
$registrySecurityProbe=Denial-Probe -Action {throw $nestedRegistrySecurity} -RegistryQueryValuesPositiveControl
Check ($registrySecurityProbe.denied -and $registrySecurityProbe.classification -ceq 'RegistryQueryValues.SecurityExceptionAfterPositiveControl') 'Captured nested registry denial was rejected after its fixed-operation positive control.'
Check ($registrySecurityProbe.error.exceptions.Count -eq 2 -and $registrySecurityProbe.error.exceptions[0].type -ceq 'System.Management.Automation.MethodInvocationException' -and $registrySecurityProbe.error.exceptions[0].hresult -eq -2146233087 -and $registrySecurityProbe.error.exceptions[1].type -ceq 'System.Security.SecurityException' -and $registrySecurityProbe.error.exceptions[1].hresult -eq -2146233078 -and $registrySecurityProbe.error.exceptions[1].hresult_low_word -eq 5386 -and $null -eq $registrySecurityProbe.error.exceptions[1].native_error_code) 'Captured registry HRESULT was changed or presented as native error 5.'
$wrongNative=Clone $registry;$wrongNative.error_details.native_error.code=2
Check ($registrySecurityProbe.denied -and -not (Test-RegistryDenial $wrongNative $expected $programName)) 'Registry probe classification replaced the independent SDK NativeError=5 proof.'
Check ((Denial-Probe {}).succeeded -and -not $registrySecurityProbe.succeeded) 'Positive probe control confused success with expected denial.'

# Exercise the real ACL transformation/restoration functions against in-memory mocks.
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
$sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001')
$root='C:\ad-sdk-validation\offline-fixture';$custom=Join-Path $root 'CustomDCCloneAllowList.xml'
$script:mockSecurity=$null;$script:mockApplyFailure=$false;$script:guardCalls=0
function Assert-OwnedFiles { $script:guardCalls++ }
function File-Security([string]$Path) {
    if($Path -cne $root -and $Path -cne $custom) { throw 'Unexpected mock ACL path.' }
    $copy=if($Path -ceq $root){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
    $copy.SetSecurityDescriptorBinaryForm($script:mockSecurity.GetSecurityDescriptorBinaryForm())
    return $copy
}
function Apply-FileSecurity([string]$Path,$Security) {
    if($script:mockApplyFailure) { throw 'Injected restoration failure' }
    if($Path -cne $root -and $Path -cne $custom) { throw 'Unexpected mock ACL application.' }
    $script:mockSecurity=$Security
}
foreach($entry in @(@($custom,[Security.AccessControl.FileSystemRights]::ReadData),@($custom,[Security.AccessControl.FileSystemRights]::WriteData),@($root,[Security.AccessControl.FileSystemRights]::CreateFiles))) {
    $path=$entry[0];$right=$entry[1]
    $script:mockSecurity=if($path -ceq $root){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
    $script:mockSecurity.SetOwner($sid);$script:mockSecurity.SetGroup($sid)
    $script:mockSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
    $original=Get-Descriptor $script:mockSecurity
    Deny-FileRight $path $right
    $rules=@($script:mockSecurity.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))
    $denies=@($rules | Where-Object AccessControlType -eq Deny)
    Check ($denies.Count -eq 1 -and $denies[0].IdentityReference.Value -ceq $sid.Value -and $denies[0].FileSystemRights -eq $right -and $denies[0].InheritanceFlags -eq 'None') 'Deny changed the wrong identity/right or propagated to children.'
    Check (@($rules | Where-Object {$_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ChangePermissions)}).Count -gt 0) 'Restoration rights were lost.'
    Restore-FileSecurity $path $original
    Check ((Get-Descriptor $script:mockSecurity).sddl -ceq $original.sddl) 'Exact original descriptor was not restored.'
    $script:mockApplyFailure=$true
    Reject { Restore-FileSecurity $path $original } 'Restoration failure was silently accepted.'
    $script:mockApplyFailure=$false
}
Check ($script:guardCalls -eq 3) 'Deny did not verify fixture ownership.'

# Durable create-new JSON semantics, within an explicitly owned local test folder.
$testRoot=Join-Path $PSScriptRoot ('cloning-access-offline-'+[guid]::NewGuid().ToString('N'))
function Assert-UnlinkedLocal([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($testRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Offline JSON target escaped owned folder.' }
    return $full
}
$null=New-Item -ItemType Directory -Path $testRoot
try {
    $report=Join-Path $testRoot 'report.json';Write-NewJson $report ([ordered]@{fixture='offline';passed=$true})
    $bytes=[IO.File]::ReadAllText($report)
    Reject { Write-NewJson $report ([ordered]@{overwritten=$true}) } 'Existing durable report was overwritten.'
    Check ([IO.File]::ReadAllText($report) -ceq $bytes) 'Create-new rejection altered the report.'
    $resultRoot=$testRoot;$runStatePath=Join-Path $testRoot 'run-journal.json';$runOwner='offline-owner';$accessRun='offline-execution';$script:guestUncertain=$false
    $runState=[ordered]@{owner=$runOwner;execution_id=$accessRun;phase='prepared';guest_uncertain=$false;updated=$null}
    Write-RunState
    $runState.phase='cases-requested';Write-RunState
    $journal=[IO.File]::ReadAllText($runStatePath) | ConvertFrom-Json
    Check ($journal.phase -ceq 'cases-requested' -and $journal.owner -ceq $runOwner) 'Atomic journal update lost ownership or phase.'
    $journal.owner='different-owner';[IO.File]::WriteAllText($runStatePath,($journal | ConvertTo-Json))
    $beforeJournal=[IO.File]::ReadAllText($runStatePath)
    Reject { Write-RunState } 'Journal ownership change was overwritten.'
    Check ($script:guestUncertain -and [IO.File]::ReadAllText($runStatePath) -ceq $beforeJournal) 'Journal failure did not preserve evidence and block guest work.'
} finally {
    foreach($path in @($report,$runStatePath)) { $full=Assert-UnlinkedLocal $path;if(Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Force } }
    [IO.Directory]::Delete($testRoot,$false)
}

# The host guard sees only mocks. These functions never access Hyper-V or H:.
$profile='H:\ad-sdk-lab\server2025';$statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml';$stateHash='STATE'
Check ((Get-ProfileMutexName $profile) -ceq (Get-ProfileMutexName $profile.ToUpperInvariant())) 'Profile mutex identity is not case stable.'
Check ((Get-ProfileMutexName $profile).StartsWith('Global\GoSDKActiveDirectoryLab_')) 'Qualification does not share the canonical lab mutex namespace.'
$ExpectedHelperSHA256='A'*64;$ExpectedAccessExecutableSHA256='B'*64
$script:stateHashNow=$stateHash;$script:linkedPath=$null;$script:vmCalls=0
function Test-Path { param($LiteralPath) return $LiteralPath -ceq $script:linkedPath -or $LiteralPath -ceq $script:existingRunPath }
function Get-Item { param($LiteralPath,[switch]$Force) return [pscustomobject]@{Attributes=$(if($LiteralPath -ceq $script:linkedPath){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Directory})} }
function Get-Content { param($LiteralPath,[switch]$Raw) if($LiteralPath -cne $statePath) {throw 'Unexpected mock state read'};return ($script:fakeState | ConvertTo-Json -Depth 8) }
function Get-FileHash { param($LiteralPath) if($LiteralPath -ceq $statePath){return [pscustomobject]@{Hash=$script:stateHashNow}};if(-not $script:hashes.ContainsKey($LiteralPath)){throw 'Unexpected mock hash path'};return [pscustomobject]@{Hash=$script:hashes[$LiteralPath]} }
function Get-VMSwitch { param($Id) return $script:fakeSwitch }
function Get-VM { param($Id) $script:vmCalls++;return $script:fakeVMs[$Id.ToString()] }
function Get-VMHardDiskDrive { param($VM) return $script:fakeDisks[$VM.Id.ToString()] }
function Get-VMNetworkAdapter { param($VM) return $script:fakeAdapters[$VM.Id.ToString()] }
function Reset-Guard {
    $script:stateHashNow=$stateHash;$script:linkedPath=$null;$script:existingRunPath=$null;$script:vmCalls=0
    $script:fakeState=[pscustomobject]@{id='60197892-ec9f-4c19-abe8-34dc60d473e5';switch_id='18cf982f-8c11-45cd-8581-fc2a00648deb';switch_name='owned-private';configured=$false;machines=@([pscustomobject]@{id='a364b1d0-7868-47f1-ab29-a5e80c97aa4b';name='ADSDK25DC1';role='dc1'},[pscustomobject]@{id='e9097666-5393-4c38-b80b-68d56c749b98';name='ADSDK25DC2';role='dc2'},[pscustomobject]@{id='80aa4382-c228-489c-b5f7-007c7feee3ff';name='ADSDK25MEM';role='member'})}
    $script:fakeSwitch=[pscustomobject]@{Id=[guid]$fakeState.switch_id;Name=$fakeState.switch_name;Notes="ad-sdk-lab:$($fakeState.id)";SwitchType='Private'}
    $script:fakeVMs=@{};$script:fakeDisks=@{};$script:fakeAdapters=@{}
    foreach($machine in $fakeState.machines) {
        $script:fakeVMs[$machine.id]=[pscustomobject]@{Id=[guid]$machine.id;Name=$machine.name;Notes="ad-sdk-lab:$($fakeState.id)";State=$(if($machine.role -ceq 'member'){'Off'}else{'Running'});Path=(Join-Path $profile $machine.name)}
        $script:fakeDisks[$machine.id]=@([pscustomobject]@{Path=(Join-Path $profile ($machine.name+'\disk.vhdx'))})
        $script:fakeAdapters[$machine.id]=@([pscustomobject]@{SwitchId=[guid]$fakeState.switch_id})
    }
}
Reset-Guard
Assert-OwnedControllers
Check ($script:vmCalls -eq 3) 'Guard did not accept both running controllers and the owned powered-off member.'
$primary='a364b1d0-7868-47f1-ab29-a5e80c97aa4b';$secondary='e9097666-5393-4c38-b80b-68d56c749b98';$member='80aa4382-c228-489c-b5f7-007c7feee3ff'
foreach($mutation in @(
    {$script:stateHashNow='CHANGED'},
    {$script:fakeState.id='other-lab'},
    {$script:fakeState.machines[0].name='other-vm'},
    {$script:fakeState.machines[1].role='unrelated'},
    {$script:fakeState.machines[1].id=$primary},
    {$script:fakeState.machines[1].id=[guid]::NewGuid().ToString()},
    {$script:fakeState.machines[2].id=[guid]::NewGuid().ToString()},
    {$script:fakeState.machines[2].name='different-member'},
    {$script:fakeState.machines=@($fakeState.machines[0],$fakeState.machines[1])},
    {$script:fakeSwitch.SwitchType='External'},
    {$script:fakeSwitch.Notes='other-owner'},
    {$script:fakeVMs[$primary].State='Off'},
    {$script:fakeVMs[$secondary].State='Off'},
    {$script:fakeVMs[$member].State='Running'},
    {$script:fakeVMs[$member].Notes='other-owner'},
    {$script:fakeVMs[$secondary].Notes='other-owner'},
    {$script:fakeVMs[$primary].Path='H:\unrelated'},
    {$script:fakeDisks[$secondary]=@()},
    {$script:fakeDisks[$secondary][0].Path='H:\unrelated\disk.vhdx'},
    {$script:fakeDisks[$member][0].Path='H:\unrelated\member.vhdx'},
    {$script:fakeAdapters[$secondary]=@()},
    {$script:fakeAdapters[$primary]+=([pscustomobject]@{SwitchId=[guid]$fakeState.switch_id})},
    {$script:fakeAdapters[$primary][0].SwitchId=[guid]::NewGuid()},
    {$script:linkedPath=$fakeDisks[$secondary][0].Path}
)) { Reset-Guard;& $mutation;Reject { Assert-OwnedControllers } 'Changed lab ownership/topology passed the guard.' }
Reset-Guard
$build=[pscustomobject]@{source_commit='34b043bc69463fe0b4df32bceac3a1050e952a7b';status='built';run='cloning-reviewed';directory='H:\ad-sdk-lab\qualifications\reviewed';native_executable='H:\ad-sdk-lab\qualifications\reviewed\dccloning.exe';native_executable_sha256='929A2560DB4D89713044E0E073546CD8E06448D39393230C5904AA6915AF8248';source_archive_sha256='FE2EA4DEB69C4C47684A1F099F1E5E98E921C28CE8B9C7C99290F85B39F69D67';access_helper='C:\owned-source\cloning-access-helper.go';access_helper_sha256=$ExpectedHelperSHA256;access_executable='H:\ad-sdk-lab\qualifications\reviewed\cloning-access.exe';access_executable_sha256=$ExpectedAccessExecutableSHA256}
$script:hashes=@{};$script:hashes[$build.native_executable]=$build.native_executable_sha256;$script:hashes[$build.access_helper]=$ExpectedHelperSHA256;$script:hashes[$build.access_executable]=$ExpectedAccessExecutableSHA256
Assert-Build $build $build.source_commit;$script:checks++
$changed=Clone $build;$changed.access_executable_sha256='C'*64
Reject { Assert-Build $changed $build.source_commit } 'Unreviewed access binary hash passed.'
$changed=Clone $build;$changed.source_commit='bfc8f8adf6af90fc5ca93c5aee6ae7a58ce8a876'
Reject { Assert-Build $changed $build.source_commit } 'Different SDK source passed.'
$captures=[ordered]@{'native-access.json'=('A'*64);'access-observations.json'=('B'*64);'access-acl-snapshots.json'=('C'*64)}
Assert-CaptureComplete $captures;$script:checks++
$captures.Remove('access-acl-snapshots.json')
Reject { Assert-CaptureComplete $captures } 'Missing ACL evidence permitted cleanup.'
$captures['access-acl-snapshots.json']='bad'
Reject { Assert-CaptureComplete $captures } 'Invalid evidence hash permitted cleanup.'

# Recovery must checkpoint the actual denial observations before changing an ACL.
# These callbacks are in-memory event probes, never filesystem/registry writers.
function Write-Checkpoint([string]$Label) {
    $script:recoveryEvents+=@('checkpoint')
    $script:capturedCase=Clone $script:caseUnderTest
    if($script:checkpointFailure) { $script:evidenceFailure=$true;$script:preserveFixture=$true;throw 'Injected checkpoint failure' }
}
function Assert-CaseRestored { $script:recoveryEvents+=@('observe');return [ordered]@{hashes_and_descriptors_restored=$true} }
function Reset-Recovery {
    $script:ownedProcessUncertain=$false;$script:evidenceFailure=$false;$script:preserveFixture=$false;$script:checkpointFailure=$false
    $script:recoveryEvents=@();$script:capturedCase=$null
    $script:caseUnderTest=[ordered]@{name='offline-denial';probe=[ordered]@{denied=$true};native=[ordered]@{stdout='raw native';stderr='native error'};reference=[ordered]@{error='raw reference error'};restored=$null}
}
Reset-Recovery
Complete-DenialCase $caseUnderTest @({$script:recoveryEvents+=@('restore-file')},{$script:recoveryEvents+=@('restore-directory')})
Check (($recoveryEvents -join ',') -ceq 'checkpoint,restore-file,restore-directory,observe') 'Denial evidence was not durable before restoration and observers.'
Check ($capturedCase.probe.denied -and $capturedCase.native.stdout -ceq 'raw native' -and $capturedCase.reference.error -ceq 'raw reference error' -and -not $capturedCase.recovery.attempted) 'Pre-restoration checkpoint omitted raw denial observations.'
Reset-Recovery;$script:checkpointFailure=$true
Reject { Complete-DenialCase $caseUnderTest @({$script:recoveryEvents+=@('restore-file')},{$script:recoveryEvents+=@('restore-directory')}) } 'Capture failure allowed qualification to continue.'
Check (($recoveryEvents -join ',') -ceq 'checkpoint,restore-file,restore-directory' -and $caseUnderTest.recovery.acls_restored -and $caseUnderTest.recovery.observers_skipped) 'Capture failure skipped owned ACL recovery or launched observers.'
Reset-Recovery;$script:ownedProcessUncertain=$true
Reject { Complete-DenialCase $caseUnderTest @({$script:recoveryEvents+=@('unsafe-restore')}) } 'Unknown live child allowed ACL restoration.'
Check (($recoveryEvents -join ',') -ceq 'checkpoint' -and $caseUnderTest.recovery.deferred_for_live_child -and -not $caseUnderTest.recovery.acls_restored) 'Live child uncertainty incorrectly certified ACL recovery.'
Reset-Recovery
Reject { Complete-DenialCase $caseUnderTest @({$script:recoveryEvents+=@('failed-restore');throw 'Injected ACL recovery failure'},{$script:recoveryEvents+=@('other-restore')}) } 'Failed ACL restoration was accepted.'
Check (($recoveryEvents -join ',') -ceq 'checkpoint,failed-restore,other-restore' -and -not $caseUnderTest.recovery.acls_restored) 'Independent ACL recovery stopped early or launched fresh observers.'
foreach($fault in @('evidence','child','preserve')) {
    Reset-Recovery
    switch($fault) { 'evidence' {$script:evidenceFailure=$true};'child' {$script:ownedProcessUncertain=$true};'preserve' {$script:preserveFixture=$true} }
    Reject { Assert-ObservationAllowed } 'Uncertain state permitted new inventory observers.'
    Reject { Reference-Observation } 'Reference observer bypassed preservation state.'
    Reject { Native-Observation } 'Native observer bypassed preservation state.'
}

# Bounded owned-job tests: no actual jobs, sessions, or remoting calls are made.
function Write-RunState {
    $script:journalWrites++
    $runState.guest_uncertain=$script:guestUncertain
    $script:jobEvents+=@('journal:'+([string]$script:guestUncertain))
    if($script:journalWrites -eq $script:journalFailureAt) { $script:guestUncertain=$true;throw 'Injected journal failure' }
}
function Wait-Job { param($Job,[int]$Timeout) $script:jobWaits+=@($Timeout);if($script:completeDuringWait) {$Job.State='Completed'} }
function Receive-Job { param($Job,$ErrorAction) $script:receivedJobs+=@($Job.Id);if($script:receiveFailure){throw 'Injected receive failure'};return 'owned-job-output' }
function Remove-Job { param($Job,$ErrorAction) $script:removedJobs+=@($Job.Id) }
function Invoke-Command {
    param($VMId,$Credential,$ScriptBlock,$ArgumentList,[switch]$AsJob,$ErrorAction,$FilePath)
    if($VMId.ToString() -cne 'a364b1d0-7868-47f1-ab29-a5e80c97aa4b' -or -not $AsJob) { throw 'Unexpected or synchronous mock guest invocation.' }
    $script:guestLaunches++
    if($script:launchFailure){throw 'Injected guest launch failure'}
    return $script:fakeJob
}
function Reset-Job([string]$State='Completed') {
    Reset-Guard
    $script:guestUncertain=$false;$script:stopConfirms=$true;$script:completeDuringWait=$false;$script:receiveFailure=$false;$script:launchFailure=$false
    $script:journalWrites=0;$script:journalFailureAt=-1;$script:guestLaunches=0;$script:jobEvents=@();$script:jobWaits=@();$script:stoppedJobs=@();$script:removedJobs=@();$script:receivedJobs=@()
    $script:runState=[ordered]@{phase='prepared';guest_uncertain=$false;jobs=@()}
    $script:machine=[pscustomobject]@{id='a364b1d0-7868-47f1-ab29-a5e80c97aa4b'};$script:credential='offline-mock'
    $script:fakeJob=[pscustomobject]@{Id=73;State=$State}
    $script:fakeJob | Add-Member -MemberType ScriptMethod -Name StopJobAsync -Value {
        $script:stoppedJobs+=@($this.Id);$script:jobEvents+=@('stop')
        if($script:stopConfirms) { $this.State='Stopped' }
    }
}
Reset-Job
$output=@(Invoke-OwnedGuest -Script {throw 'Must never execute offline'} -Arguments @('owned') -TimeoutSeconds 10 -Action 'stage')
Check ($output.Count -eq 1 -and $output[0] -ceq 'owned-job-output' -and $guestLaunches -eq 1 -and $removedJobs[0] -eq 73 -and -not $script:guestUncertain) 'Completed owned job was not received and removed.'
Reset-Job 'Running';$script:completeDuringWait=$true
$output=@(Wait-OwnedJob $fakeJob 10 'capture')
Check ($output.Count -eq 1 -and $jobWaits.Count -eq 1 -and $jobWaits[0] -eq 2 -and $stoppedJobs.Count -eq 0) 'Owned job did not use bounded polling.'
foreach($action in @('stage','cases','capture-native-access.json','cleanup')) {
    Reset-Job 'Running'
    Reject { Invoke-OwnedGuest -Script {} -Arguments @() -TimeoutSeconds 0 -Action $action } 'Guest operation timeout was accepted.'
    Check ($script:guestUncertain -and $runState.jobs[0].timeout -and $stoppedJobs.Count -eq 1 -and $stoppedJobs[0] -eq 73 -and $removedJobs.Count -eq 1 -and $jobWaits[0] -eq 5) 'Timeout did not preserve uncertainty or bound cancellation to the owned job.'
    $firstUncertainJournal=[Array]::IndexOf($jobEvents,'journal:True');$stopEvent=[Array]::IndexOf($jobEvents,'stop')
    Check ($firstUncertainJournal -ge 0 -and $firstUncertainJournal -lt $stopEvent) 'Timeout uncertainty was not journaled before cancellation.'
    Reject { Invoke-OwnedGuest -Script {} -Arguments @() -TimeoutSeconds 10 -Action 'forbidden-follow-up' } 'A follow-up guest action overlapped uncertain work.'
    Check ($guestLaunches -eq 1) 'Uncertain guest action was replayed or followed by cleanup/capture.'
}
Reset-Job 'Running';$script:stopConfirms=$false
Reject { Wait-OwnedJob $fakeJob 0 'cases' } 'Unconfirmed guest cancellation passed.'
Check ($script:guestUncertain -and $removedJobs.Count -eq 0 -and $fakeJob.State -ceq 'Running') 'Unconfirmed owned job was deleted or uncertainty cleared.'
Reset-Job 'Failed'
Reject { Wait-OwnedJob $fakeJob 10 'cases' } 'Failed guest job passed.'
Check ($script:guestUncertain -and $removedJobs.Count -eq 1 -and $receivedJobs.Count -eq 0) 'Failed job did not block further guest work.'
Reset-Job;$script:receiveFailure=$true
Reject { Wait-OwnedJob $fakeJob 10 'capture' } 'Job output failure passed.'
Check ($script:guestUncertain -and $runState.jobs[0].error) 'Capture failure did not mark guest evidence uncertain.'
Reset-Job 'Running';$script:journalFailureAt=1
Reject { Wait-OwnedJob $fakeJob 10 'cases' } 'Journal failure allowed a running guest job to continue unchecked.'
Check ($script:guestUncertain -and $stoppedJobs.Count -eq 1 -and $jobWaits[0] -eq 5) 'Journal failure did not bound cancellation of the owned job.'
Reset-Job;$script:launchFailure=$true
Reject { Invoke-OwnedGuest -Script {} -Arguments @() -TimeoutSeconds 10 -Action 'stage' } 'Guest launch failure passed.'
Check ($script:guestUncertain -and $guestLaunches -eq 1) 'Guest launch failure allowed replay.'
Reset-Guard
$replayPath='H:\ad-sdk-lab\qualifications\reviewed\server2025-native-access-v2';$script:existingRunPath=$replayPath
Reject { Assert-NewRunDirectory $replayPath } 'Existing terminal or interrupted access run was replayed.'
Check ($script:vmCalls -eq 0) 'Replay guard touched a VM.'
$accessRun='offline-access-run';$ExpectedSourceCommit='34b043bc69463fe0b4df32bceac3a1050e952a7b'
$guestResult=[ordered]@{run=$accessRun;sdk_source_commit=$ExpectedSourceCommit;native_executable_sha256=$ExpectedAccessExecutableSHA256;helper_source_sha256=$ExpectedHelperSHA256;passed=$false;process_uncertain=$false;cleanup=[ordered]@{safe_to_remove_files=$false;acl_recovery_deferred=$false}}
$script:guestUncertain=$false
$result=Read-CompletedGuestOutcome ($guestResult | ConvertTo-Json -Depth 6)
Check (-not $script:guestUncertain -and -not $result.passed) 'A settled failed case could not retain its raw reports.'
foreach($payload in @('not JSON','{}',(($guestResult | ConvertTo-Json -Depth 6)+"`n"+($guestResult | ConvertTo-Json -Depth 6)))) {
    $script:guestUncertain=$false
    Reject { Read-CompletedGuestOutcome $payload } 'Malformed completed guest output permitted follow-up remoting.'
    Check $script:guestUncertain 'Malformed completed output did not block overlap with an unknown child.'
}
$guestResult.cleanup.acl_recovery_deferred=$true;$script:guestUncertain=$false
Reject { Read-CompletedGuestOutcome ($guestResult | ConvertTo-Json -Depth 6) } 'Guest-reported live child permitted follow-up capture or cleanup.'
Check $script:guestUncertain 'Guest-reported child uncertainty was lost.'
$guestResult.cleanup.acl_recovery_deferred=$false
foreach($invalidProcessState in @('missing','false')) {
    $invalidResult=Clone $guestResult
    if($invalidProcessState -ceq 'missing') { $invalidResult.PSObject.Properties.Remove('process_uncertain') }
    else { $invalidResult.process_uncertain=$invalidProcessState }
    $script:guestUncertain=$false
    Reject { Read-CompletedGuestOutcome ($invalidResult | ConvertTo-Json -Depth 6) } 'Missing or nonboolean final process state permitted capture.'
    Check $script:guestUncertain 'Invalid final process state did not block subsequent remoting.'
}

# Execute the actual outer guest finally block with inert ACL/registry mocks.
# Both late observer sites run after acl_recovery_deferred was initially false.
$tokens=$null;$parseErrors=$null
$guestAst=[Management.Automation.Language.Parser]::ParseFile($guest,[ref]$tokens,[ref]$parseErrors)
$outerTry=@($guestAst.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
Check ($parseErrors.Count -eq 0 -and $outerTry.Count -eq 1) 'Could not isolate actual guest finalization for the late-observer regression.'
$finallyText=$outerTry[0].Finally.Extent.Text
$actualFinally=[scriptblock]::Create($finallyText.Substring(1,$finallyText.Length-2))
foreach($latePhase in @('final-fixture','baseline')) {
    & {
        param($Phase,$FinallyBlock)
        $script:ownedProcessUncertain=$false;$script:preserveFixture=$false;$script:evidenceFailure=$false;$script:publishedFinal=$null
        $keyHandle=$null;$keyOriginal=$null;$snapshots=[ordered]@{custom_file='saved-file';directory='saved-directory'}
        $cleanupErrors=@();$checkpointWritten=$false;$overrideCreated=$false;$baselineCaptured=$true;$denialStarted=$true;$created=@();$parameters='mock-parameters';$stage='C:\ad-sdk-validation\offline'
        $record=Clone $guestResult
        # Ordered maps permit the production finally block to append its fields.
        $record=[ordered]@{run=$record.run;sdk_source_commit=$record.sdk_source_commit;native_executable_sha256=$record.native_executable_sha256;helper_source_sha256=$record.helper_source_sha256;passed=$true;before=@();error=$null;positive=@(1,2,3,4);cases=@([ordered]@{passed=$true},[ordered]@{passed=$true},[ordered]@{passed=$true});cleanup=[ordered]@{acl_restored=$false;override_absent=$false;registry_keys_absent=$false;baseline_restored=$false;safe_to_remove_files=$true;errors=@()}}
        function Restore-FileSecurity { param($Path,$Saved) }
        function Assert-CaseRestored {
            if($Phase -ceq 'final-fixture') { $script:ownedProcessUncertain=$true;throw 'Injected unconfirmed final fixture observer' }
            return [ordered]@{hashes_and_descriptors_restored=$true}
        }
        function Native-Observation { $script:ownedProcessUncertain=$true;throw 'Injected unconfirmed final baseline observer' }
        function Get-Item {
            param($LiteralPath)
            $item=[pscustomobject]@{}
            $item | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { return @() }
            return $item
        }
        function Write-NewJson {
            param($Path,$Value)
            if([IO.Path]::GetFileName($Path) -ceq 'native-access.json') { $script:publishedFinal=Clone $Value }
        }
        . $FinallyBlock
        Check ($script:ownedProcessUncertain -and -not $publishedFinal.cleanup.acl_recovery_deferred -and $publishedFinal.process_uncertain) 'Late observer uncertainty was omitted from final JSON or confused with ACL recovery deferral.'
        Check (-not $publishedFinal.passed -and -not $publishedFinal.cleanup.safe_to_remove_files) 'Late process uncertainty incorrectly certified a passing or cleanup-safe result.'
        $script:guestUncertain=$false
        Reject { Read-CompletedGuestOutcome ($publishedFinal | ConvertTo-Json -Depth 12) } 'Host accepted an unsettled final observer and permitted capture.'
        $launchesBefore=$script:guestLaunches
        Reject { Invoke-OwnedGuest -Script {} -Arguments @() -TimeoutSeconds 10 -Action 'forbidden-late-capture' } 'Capture overlapped a late unconfirmed observer.'
        Check ($script:guestUncertain -and $script:guestLaunches -eq $launchesBefore) 'Late observer uncertainty failed to block actual guest invocation.'
    } $latePhase $actualFinally
}

[pscustomobject]@{passed=$true;checks=$script:checks;powershell=$PSVersionTable.PSVersion.ToString();executed_vm_ad_registry_or_acl_operations=$false} | ConvertTo-Json
