#Requires -Version 5.1
param(
    [Parameter(Mandatory)][ValidateSet('2016','2019','2022')][string]$ServerVersion,
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceCommit,
    [ValidateRange(30,600)][int]$ReadinessTimeoutSeconds=300,
    [ValidateRange(60,1800)][int]$CaseTimeoutSeconds=900
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-UnlinkedPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Qualification path traverses a reparse point.' }
    }
    return $full
}
function Get-OwnedProfile([string]$Version) {
    switch($Version) {
        '2016' { return [pscustomobject]@{lab='a2518a5c-a379-4038-befa-401ce9e001ba';vm='a226a078-8981-40f1-abf7-491169f67dff';name='ADSDK16DC1';switch='2257600b-655d-4446-a15c-16768022a466'} }
        '2019' { return [pscustomobject]@{lab='11e4d1b5-351a-47eb-b017-9506047ea119';vm='0948377a-c824-4d96-b70e-5a669697a8bc';name='ADSDK19DC1';switch='827d4d01-6cab-48ae-b739-de336e8b1ca8'} }
        '2022' { return [pscustomobject]@{lab='295b3c9e-58dc-4f7d-a735-c661783ebecc';vm='c7ef31ca-30de-47d0-ba1c-7bce83fc031e';name='ADSDK22DC1';switch='5aaa5748-f395-4ac6-81d1-a71c7c301626'} }
        default { throw 'Unapproved server profile.' }
    }
}
function New-ProfileMutex([string]$Name) { return [Threading.Mutex]::new($false,$Name) }
function Enter-ProfileMutex([string]$LabRoot) {
    # Identical naming and abandoned-owner handling to scripts/lab/lab.ps1.
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { $lockName=[BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes(([IO.Path]::GetFullPath($LabRoot)).ToLowerInvariant()))).Replace('-','') } finally { $hasher.Dispose() }
    $mutex=New-ProfileMutex ("Global\GoSDKActiveDirectoryLab_"+$lockName)
    $held=$false
    try {
        try { $held=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held=$true }
        if(-not $held) { throw 'Another lab action is running for this profile.' }
        return $mutex
    } catch { $mutex.Dispose();throw }
}
function Exit-ProfileMutex($Mutex) {
    try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() }
}
function Assert-OwnedController([string[]]$AllowedStates=@('Off','Running')) {
    $null=Assert-UnlinkedPath $statePath
    $current=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if($current.id -cne $expected.lab -or $current.switch_id -cne $expected.switch -or
       $current.root -ine $profile -or $current.server_version -cne $ServerVersion -or $current.configured -ne $true -or
       $current.switch_name -cne $state.switch_name) { throw 'Owned configured lab state differs.' }
    $controllers=@($current.machines | Where-Object role -eq 'dc1')
    if($controllers.Count -ne 1 -or $controllers[0].id -cne $expected.vm -or $controllers[0].name -cne $expected.name) { throw 'Controller manifest identity differs.' }
    $switch=Get-VMSwitch -Id ([guid]$expected.switch)
    if($switch.Id.ToString() -cne $expected.switch -or $switch.Name -cne $state.switch_name -or
       $switch.Notes -cne "ad-sdk-lab:$($expected.lab)" -or $switch.SwitchType -ne 'Private') { throw 'Private switch ownership differs.' }
    $vm=Get-VM -Id ([guid]$expected.vm)
    if($vm.Id.ToString() -cne $expected.vm -or $vm.Name -cne $expected.name -or
       $vm.Notes -cne "ad-sdk-lab:$($expected.lab)" -or $vm.State.ToString() -notin $AllowedStates) { throw 'Owned controller identity or state differs.' }
    $paths=@($vm.Path)+@(Get-VMHardDiskDrive -VM $vm | ForEach-Object {$_.Path})
    if($paths.Count -lt 2) { throw 'Expected owned controller disk is missing.' }
    foreach($path in $paths) {
        $full=Assert-UnlinkedPath $path
        if(-not $full.StartsWith($profile+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Controller path or disk lies outside owned profile.' }
    }
    $adapters=@(Get-VMNetworkAdapter -VM $vm)
    if($adapters.Count -ne 1 -or $adapters[0].SwitchId.ToString() -cne $expected.switch) { throw 'Controller network isolation differs.' }
    return $vm
}
function Write-RunState {
    $null=Assert-UnlinkedPath $runStatePath
    if(Test-Path -LiteralPath $runStatePath) {
        $previous=Get-Content -LiteralPath $runStatePath -Raw | ConvertFrom-Json
        if($previous.execution_id -cne $executionId -or $previous.owner -cne $runOwner) { throw 'Qualification journal ownership changed.' }
    }
    $runState.updated=[DateTime]::UtcNow.ToString('o')
    $temporary=$runStatePath+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($runState | ConvertTo-Json -Depth 12))
        $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
    } finally { $stream.Dispose() }
    if(Test-Path -LiteralPath $runStatePath) { [IO.File]::Replace($temporary,$runStatePath,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$runStatePath) }
}
function Wait-OwnedJob($Job,[int]$TimeoutSeconds,[string]$Action,[switch]$Guest) {
    $entry=[ordered]@{id=$Job.Id;action=$Action;started=[DateTime]::UtcNow.ToString('o');state='running';timeout=$false;removed=$false}
    $runState.jobs+=@($entry);Write-RunState
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try {
        while($Job.State -notin @('Completed','Failed','Stopped') -and $watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            $null=Wait-Job -Job $Job -Timeout 2
        }
        if($Job.State -notin @('Completed','Failed','Stopped')) {
            $entry.timeout=$true
            if($Guest) { $script:guestUncertain=$true }
            # Stop only this runner's job. Never wait without a deadline or
            # delete its staging after a possibly still-active remote command.
            if($Job.PSObject.Methods['StopJobAsync']) { $Job.StopJobAsync();$null=Wait-Job -Job $Job -Timeout 5 }
            throw "Owned $Action job exceeded its deadline; no action retry."
        }
        if($Job.State -ne 'Completed') { throw "Owned $Action job ended in state $($Job.State)." }
        return @(Receive-Job -Job $Job -ErrorAction Stop)
    } catch {
        if($Guest -and $Action -ne 'readiness') { $script:guestUncertain=$true }
        throw
    } finally {
        $entry.state=$Job.State.ToString()
        if($Job.State -in @('Completed','Failed','Stopped')) { Remove-Job -Job $Job;$entry.removed=$true }
        Write-RunState
    }
}
function Invoke-OwnedGuest([ScriptBlock]$Script,[object[]]$Arguments,[int]$TimeoutSeconds,[string]$Action) {
    $null=Assert-OwnedController @('Running')
    $runState.phase='guest-'+$Action+'-requested';Write-RunState
    $job=Invoke-Command -VMId ([guid]$expected.vm) -Credential $credential -ScriptBlock $Script -ArgumentList $Arguments -AsJob
    return @(Wait-OwnedJob $job $TimeoutSeconds $Action -Guest)
}
function Start-OwnedController {
    if($runState.start_requested) { throw 'A controller start was already requested; preserve journal and review manually.' }
    $vm=Assert-OwnedController @('Off','Running')
    if($runState.original_power -eq 'Running') {
        if($vm.State -ne 'Running') { throw 'Originally running controller changed power state.' }
        return
    }
    if($runState.original_power -ne 'Off' -or $vm.State -ne 'Off') { throw 'Controller power changed before startup.' }
    $runState.phase='memory-change-requested';Write-RunState
    $vm=Assert-OwnedController @('Off')
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 4GB
    $runState.memory_fixed_4gb=$true
    # Persist before issuing Start-VM so interrupted execution cannot retry it.
    $runState.start_requested=$true;$runState.phase='start-requested';Write-RunState
    $vm=Assert-OwnedController @('Off')
    $job=Start-VM -VM $vm -AsJob
    $null=Wait-OwnedJob $job 60 'start'
    $null=Assert-OwnedController @('Running')
    $runState.phase='running';Write-RunState
}
function Restore-OwnedPower {
    if($runState.original_power -ne 'Off' -or -not $runState.start_requested) { return }
    $vm=Assert-OwnedController @('Off','Running','Starting','Stopping')
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($vm.State -in @('Starting','Stopping') -and $watch.Elapsed.TotalSeconds -lt 60) {
        Start-Sleep -Seconds 2
        $vm=Assert-OwnedController @('Off','Running','Starting','Stopping')
    }
    if($vm.State -eq 'Off') { $runState.power_restored=$true;return }
    if($vm.State -ne 'Running') { throw 'Controller did not reach a state permitting graceful shutdown; no hard power-off.' }
    $runState.phase='graceful-stop-requested';Write-RunState
    $vm=Assert-OwnedController @('Running')
    $job=Stop-VM -VM $vm -AsJob -Confirm:$false
    $null=Wait-OwnedJob $job 120 'graceful-stop'
    $null=Assert-OwnedController @('Off')
    $runState.power_restored=$true
}
function Wait-OwnedReadiness {
    $watch=[Diagnostics.Stopwatch]::StartNew();$lastError=$null
    while($watch.Elapsed.TotalSeconds -lt $ReadinessTimeoutSeconds) {
        try {
            $remaining=[Math]::Max(1,[int]($ReadinessTimeoutSeconds-$watch.Elapsed.TotalSeconds))
            $ready=@(Invoke-OwnedGuest {
                param($Computer)
                $ErrorActionPreference='Stop'
                if($env:COMPUTERNAME -cne $Computer) { throw 'Readiness computer differs.' }
                $role=(Get-CimInstance Win32_ComputerSystem -Property DomainRole).DomainRole
                $service=Get-Service -Name NTDS
                Import-Module ActiveDirectory
                $command=Get-Command Get-ADDCCloningExcludedApplicationList -ErrorAction Stop
                [pscustomobject]@{ready=($role -in @(4,5) -and $service.Status -eq 'Running');computer=$env:COMPUTERNAME;module=$command.Module.Version.ToString()}
            } @($expected.name) ([Math]::Min(15,$remaining)) 'readiness')
            if($ready.Count -eq 1 -and $ready[0].ready) { $runState.readiness=$ready[0];return }
        } catch { $lastError=$_.Exception.Message }
        # A timed-out remote readiness job must not overlap the fixture job.
        if($script:guestUncertain) { throw 'Readiness job ownership is uncertain; no fixture action will start.' }
        Start-Sleep -Seconds 2
    }
    throw "Controller readiness deadline expired: $lastError"
}
function Collect-GuestReport {
    if($runState.capture_attempted) { throw 'Guest report capture already attempted; preserve its first result.' }
    $runState.capture_attempted=$true;Write-RunState
    $capture=@(Invoke-OwnedGuest {
        param($Directory,$Run)
        $ErrorActionPreference='Stop'
        if([IO.Path]::GetFileName($Directory) -cne $Run -or -not ([IO.Path]::GetFullPath($Directory)).StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Capture staging path differs.' }
        for($cursor=$Directory;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked capture directory.' } }
        if([IO.File]::ReadAllText((Join-Path $Directory 'owner.txt')) -cne $Run) { throw 'Capture staging owner differs.' }
        $path=Join-Path $Directory 'reference.json'
        if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked guest report.' }
        $source=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $copy=[IO.MemoryStream]::new()
        try { $source.CopyTo($copy);$bytes=$copy.ToArray() } finally { $source.Dispose();$copy.Dispose() }
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','') } finally { $sha.Dispose() }
        [pscustomobject]@{bytes=[Convert]::ToBase64String($bytes);sha256=$hash}
    } @($target,$executionId) 30 'capture')
    if($capture.Count -ne 1) { throw 'Guest report capture cardinality differs.' }
    $bytes=[Convert]::FromBase64String($capture[0].bytes)
    $reference=Join-Path $resultRoot 'reference.json'
    $file=[IO.File]::Open($reference,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($bytes,0,$bytes.Length);$file.Flush($true) } finally { $file.Dispose() }
    if((Get-FileHash -LiteralPath $reference).Hash -cne $capture[0].sha256) { throw 'Captured guest report hash differs; preserve guest staging.' }
    $script:data=[Text.UTF8Encoding]::new($false,$true).GetString($bytes) | ConvertFrom-Json
    if($data.computer -cne $expected.name -or $data.server_version -cne $ServerVersion -or $data.native_executable_sha256 -cne $build.native_executable_sha256) { throw 'Captured guest report identity differs.' }
    $runState.reference_sha256=$capture[0].sha256;$runState.report_captured=$true
    Write-RunState
}

# All verification below is read-only until the new result directory/journal
# exists. An existing journal, including an interrupted one, blocks a new run.
$expected=Get-OwnedProfile $ServerVersion
$profile=Assert-UnlinkedPath ('H:\ad-sdk-lab\server'+$ServerVersion)
$operationMutex=$null
try {
$operationMutex=Enter-ProfileMutex $profile
$statePath=Assert-UnlinkedPath (Join-Path $profile 'state.json')
$null=Assert-UnlinkedPath $ManifestPath
$build=Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if($ExpectedSourceCommit -cne '34b043bc69463fe0b4df32bceac3a1050e952a7b' -or $build.source_commit -cne $ExpectedSourceCommit -or $build.status -cne 'built') { throw 'Immutable reviewed build source differs.' }
$buildRoot=Assert-UnlinkedPath $build.directory
if(-not $buildRoot.StartsWith('H:\ad-sdk-lab\qualifications\',[StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($buildRoot) -cne $build.run -or $build.run -notmatch '^[A-Za-z0-9-]+$' -or
    ([IO.Path]::GetFullPath($ManifestPath)) -ine (Join-Path $buildRoot 'build.json') -or
    ([IO.Path]::GetFullPath($build.native_executable)) -ine (Join-Path $buildRoot 'dccloning.exe')) { throw 'Immutable build paths differ.' }
$archive=Assert-UnlinkedPath (Join-Path $buildRoot 'source.zip')
$null=Assert-UnlinkedPath $build.native_executable
if($build.native_executable_sha256 -cne '929A2560DB4D89713044E0E073546CD8E06448D39393230C5904AA6915AF8248' -or
   (Get-FileHash -LiteralPath $build.native_executable).Hash -cne $build.native_executable_sha256 -or
   (Get-FileHash -LiteralPath $archive).Hash -cne $build.source_archive_sha256) { throw 'Reviewed binary or source archive hash differs.' }
$guest=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'guest-cloning-version-cases.ps1')
$sourceHash=(Get-FileHash -LiteralPath $guest).Hash;$hostHash=(Get-FileHash -LiteralPath $PSCommandPath).Hash
$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
Import-Module Hyper-V
$initial=Assert-OwnedController @('Off','Running')
$credentialPath=Assert-UnlinkedPath (Join-Path $profile 'credential.clixml')
$saved=Import-Clixml -LiteralPath $credentialPath
$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
$executionId=$build.run+'-server'+$ServerVersion+'-version-cases'
$resultRoot=Assert-UnlinkedPath (Join-Path $buildRoot ('server'+$ServerVersion+'-version-cases'))
if(Test-Path -LiteralPath $resultRoot) { throw 'Qualification output/journal exists; preserve terminal or interrupted state. No automatic replay.' }
$null=New-Item -ItemType Directory -Path $resultRoot
$snapshot=Join-Path $resultRoot 'guest-cloning-version-cases.ps1'
Copy-Item -LiteralPath $guest -Destination $snapshot
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $resultRoot 'run-cloning-version-cases.ps1')
Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $resultRoot 'build.json')
if((Get-FileHash -LiteralPath $snapshot).Hash -cne $sourceHash -or (Get-FileHash -LiteralPath (Join-Path $resultRoot 'run-cloning-version-cases.ps1')).Hash -cne $hostHash) { throw 'Qualification source snapshots differ.' }
$runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'qualification.json'
$runState=[ordered]@{
    schema_version=2;owner=$runOwner;execution_id=$executionId;run=$build.run;server_version=$ServerVersion;phase='prepared';terminal=$false
    source_commit=$build.source_commit;runtime_commit='bfc8f8adf6af90fc5ca93c5aee6ae7a58ce8a876';source_archive_sha256=$build.source_archive_sha256
    binary_sha256=$build.native_executable_sha256;guest_script_sha256=$sourceHash;host_script_sha256=$hostHash
    lab_id=$expected.lab;vm_id=$expected.vm;switch_id=$expected.switch;computer=$expected.name
    original_power=$initial.State.ToString();start_requested=$false;memory_fixed_4gb=$false;power_restored=($initial.State -eq 'Running')
    jobs=@();readiness=$null;capture_attempted=$false;report_captured=$false;reference_sha256=$null;guest_staging=$null;staging_cleanup=$false
    guest_uncertain=$false;passed=$false;error=$null;capture_error=$null;cleanup_error=$null;power_error=$null;updated=$null
}
Write-RunState
$target='C:\ad-sdk-validation\'+$executionId
$created=$false;$data=$null;$script:guestUncertain=$false
try {
    Start-OwnedController
    Wait-OwnedReadiness
    $binaryBytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($build.native_executable))
    $guestBytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($snapshot))
    $runState.guest_staging=$target;Write-RunState
    $null=Invoke-OwnedGuest {
        param($Directory,$Run,$Binary,$BinaryHash,$Script,$ScriptHash)
        $ErrorActionPreference='Stop'
        if([IO.Path]::GetFileName($Directory) -cne $Run -or -not ([IO.Path]::GetFullPath($Directory)).StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $Directory)) { throw 'Unexpected or existing guest staging directory.' }
        for($cursor=$Directory;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked guest staging directory.' } }
        $null=New-Item -ItemType Directory -Path $Directory
        [IO.File]::WriteAllText((Join-Path $Directory 'owner.txt'),$Run)
        [IO.File]::WriteAllBytes((Join-Path $Directory 'dccloning.exe'),[Convert]::FromBase64String($Binary))
        [IO.File]::WriteAllBytes((Join-Path $Directory 'guest-cloning-version-cases.ps1'),[Convert]::FromBase64String($Script))
        if((Get-FileHash -LiteralPath (Join-Path $Directory 'dccloning.exe')).Hash -cne $BinaryHash -or (Get-FileHash -LiteralPath (Join-Path $Directory 'guest-cloning-version-cases.ps1')).Hash -cne $ScriptHash) { throw 'Staged binary or guest source hash differs.' }
    } @($target,$executionId,$binaryBytes,$build.native_executable_sha256,$guestBytes,$sourceHash) 60 'stage'
    $created=$true;$runState.guest_staging=$target;Write-RunState
    $null=Invoke-OwnedGuest {
        param($Directory,$Computer,$BinaryHash,$ScriptHash,$Version,$Run)
        $ErrorActionPreference='Stop'
        $script=Join-Path $Directory 'guest-cloning-version-cases.ps1'
        if((Get-FileHash -LiteralPath $script).Hash -cne $ScriptHash) { throw 'Guest source changed before execution.' }
        & $script -ExpectedComputer $Computer -NativeExecutable (Join-Path $Directory 'dccloning.exe') -ExpectedExecutableSHA256 $BinaryHash -ServerVersion $Version -ReportPath (Join-Path $Directory 'reference.json') -ExpectedRun $Run
    } @($target,$expected.name,$build.native_executable_sha256,$sourceHash,$ServerVersion,$executionId) $CaseTimeoutSeconds 'cases'
    Collect-GuestReport
    if(-not $data.passed -or $data.stage -cne 'finished') { throw 'Guest version qualification did not pass; retained report and staging require review.' }
} catch { $runState.error=$_.Exception.Message }
finally {
    # A single read-only capture may recover a durable checkpoint even when
    # remoting failed. It never permits cleanup or replay of uncertain work.
    if($created -and -not $runState.capture_attempted) {
        try { Collect-GuestReport } catch { $runState.capture_error=$_.Exception.Message }
    }
    if($created -and $runState.report_captured -and $data.passed -and -not $script:guestUncertain -and $null -eq $runState.error) {
        try {
            $null=Invoke-OwnedGuest {
                param($Directory,$Run,$ReportHash,$BinaryHash,$SourceHash)
                $ErrorActionPreference='Stop'
                if([IO.Path]::GetFileName($Directory) -cne $Run -or -not ([IO.Path]::GetFullPath($Directory)).StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Guest cleanup path differs.' }
                for($cursor=$Directory;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked guest cleanup directory.' } }
                if([IO.File]::ReadAllText((Join-Path $Directory 'owner.txt')) -cne $Run) { throw 'Guest staging ownership differs.' }
                $running=@(Get-CimInstance Win32_Process -Filter "Name='dccloning.exe'" | Where-Object {$_.ExecutablePath -eq (Join-Path $Directory 'dccloning.exe')})
                if($running.Count) { throw 'Owned native child is still running; staging files are preserved.' }
                $hashes=@{'reference.json'=$ReportHash;'dccloning.exe'=$BinaryHash;'guest-cloning-version-cases.ps1'=$SourceHash}
                $files=@(Get-ChildItem -LiteralPath $Directory -Force)
                if($files.Count -ne 4) { throw 'Staging artifact inventory changed; preserve all files.' }
                foreach($file in $files) {
                    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Name -notin @('owner.txt','dccloning.exe','guest-cloning-version-cases.ps1','reference.json')) { throw 'Unexpected staging file is preserved.' }
                    if($hashes.ContainsKey($file.Name) -and (Get-FileHash -LiteralPath $file.FullName).Hash -cne $hashes[$file.Name]) { throw 'Staging artifact hash changed; preserve all files.' }
                }
                foreach($file in $files) { Remove-Item -LiteralPath $file.FullName -Force }
                [IO.Directory]::Delete($Directory,$false)
            } @($target,$executionId,$runState.reference_sha256,$build.native_executable_sha256,$sourceHash) 30 'cleanup'
            $runState.staging_cleanup=$true
        } catch { $runState.cleanup_error=$_.Exception.Message }
    }
    try { Restore-OwnedPower } catch { $runState.power_error=$_.Exception.Message }
    $runState.guest_uncertain=$script:guestUncertain
    $runState.passed=($null -eq $runState.error -and $null -eq $runState.capture_error -and $null -eq $runState.cleanup_error -and
        $null -eq $runState.power_error -and $runState.report_captured -and $runState.staging_cleanup -and $runState.power_restored -and -not $script:guestUncertain -and $null -ne $data -and $data.passed)
    $runState.phase=if($runState.passed){'passed'}else{'failed-preserve-for-review'}
    $runState.terminal=$true;Write-RunState
}
[pscustomobject]@{directory=$resultRoot;passed=$runState.passed;original_power=$runState.original_power;power_restored=$runState.power_restored;error=$runState.error;capture_error=$runState.capture_error;cleanup_error=$runState.cleanup_error;power_error=$runState.power_error} | ConvertTo-Json -Depth 5
if(-not $runState.passed) { throw 'Version qualification failed; preserve terminal journal and guest artifacts. No automatic replay.' }
} finally {
    if($operationMutex) { Exit-ProfileMutex $operationMutex }
}
