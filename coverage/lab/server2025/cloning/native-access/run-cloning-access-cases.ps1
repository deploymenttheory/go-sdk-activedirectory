#Requires -Version 5.1
# Prepared helper; execution is deliberately separate from offline tests.
# Extend the archived 34b build manifest with access_helper (source path),
# access_helper_sha256, access_executable (<build.directory>\cloning-access.exe),
# and access_executable_sha256. Supply both independently reviewed SHA256 pins.
# The normal CLI/archive pins remain provenance checks; this run executes only
# the separately built public-API access helper. No VM start/stop is performed.
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceCommit,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedHelperSHA256,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedAccessExecutableSHA256,
    [ValidateRange(60,1800)][int]$CaseTimeoutSeconds=900,
    [ValidateRange(30,600)][int]$CaptureTimeoutSeconds=300
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
function Assert-Build($Build,[string]$Commit) {
    if($Commit -cne '34b043bc69463fe0b4df32bceac3a1050e952a7b' -or $Build.source_commit -cne $Commit -or $Build.status -cne 'built' -or
        $Build.native_executable_sha256 -cne '929A2560DB4D89713044E0E073546CD8E06448D39393230C5904AA6915AF8248' -or
        $Build.source_archive_sha256 -cne 'FE2EA4DEB69C4C47684A1F099F1E5E98E921C28CE8B9C7C99290F85B39F69D67' -or
        $Build.run -notmatch '^[a-zA-Z0-9-]+$') { throw 'Reviewed archive or binary identity differs.' }
    $directory=Assert-UnlinkedPath $Build.directory
    if(-not $directory.StartsWith('H:\ad-sdk-lab\qualifications\',[StringComparison]::OrdinalIgnoreCase) -or
        (Assert-UnlinkedPath $Build.native_executable) -cne (Join-Path $directory 'dccloning.exe')) { throw 'Build artifact path differs.' }
    if((Get-FileHash -LiteralPath $Build.native_executable).Hash -cne $Build.native_executable_sha256) { throw 'Native artifact hash differs.' }
    if($Build.access_helper_sha256 -cne $ExpectedHelperSHA256 -or $Build.access_executable_sha256 -cne $ExpectedAccessExecutableSHA256 -or
        (Assert-UnlinkedPath $Build.access_executable) -cne (Join-Path $directory 'cloning-access.exe') -or
        (Get-FileHash -LiteralPath (Assert-UnlinkedPath $Build.access_helper)).Hash -cne $ExpectedHelperSHA256 -or
        (Get-FileHash -LiteralPath $Build.access_executable).Hash -cne $ExpectedAccessExecutableSHA256) { throw 'Reviewed access helper identity differs.' }
}
function Assert-OwnedControllers {
    foreach($path in @($statePath,$credentialPath)) { $null=Assert-UnlinkedPath $path }
    if((Get-FileHash -LiteralPath $statePath).Hash -cne $stateHash) { throw 'Owned lab state changed.' }
    $current=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if($current.id -cne '60197892-ec9f-4c19-abe8-34dc60d473e5' -or $current.switch_id -cne '18cf982f-8c11-45cd-8581-fc2a00648deb' -or
        @($current.machines).Count -ne 3 -or @($current.machines | Select-Object -ExpandProperty id -Unique).Count -ne 3) { throw 'Disposable lab identity or topology differs.' }
    $expectedMachines=@(
        [pscustomobject]@{role='dc1';id='a364b1d0-7868-47f1-ab29-a5e80c97aa4b';name='ADSDK25DC1';power='Running'},
        [pscustomobject]@{role='dc2';id='e9097666-5393-4c38-b80b-68d56c749b98';name='ADSDK25DC2';power='Running'},
        [pscustomobject]@{role='member';id='80aa4382-c228-489c-b5f7-007c7feee3ff';name='ADSDK25MEM';power='Off'}
    )
    foreach($expected in $expectedMachines) {
        $matches=@($current.machines | Where-Object role -ceq $expected.role)
        if($matches.Count -ne 1 -or $matches[0].id -cne $expected.id -or $matches[0].name -cne $expected.name) { throw 'Owned machine manifest identity differs.' }
    }
    $switch=Get-VMSwitch -Id ([guid]$current.switch_id)
    if($switch.Id.ToString() -cne $current.switch_id -or $switch.Name -cne $current.switch_name -or $switch.Notes -cne "ad-sdk-lab:$($current.id)" -or $switch.SwitchType -ne 'Private') { throw 'Private switch ownership differs.' }
    # Validate the powered-off member as well, without starting or using it.
    # The configured flag may remain false because member provisioning is separate.
    foreach($owned in $expectedMachines) {
        $vm=Get-VM -Id ([guid]$owned.id)
        if($vm.Id.ToString() -cne $owned.id -or $vm.Name -cne $owned.name -or $vm.Notes -cne "ad-sdk-lab:$($current.id)" -or $vm.State -ne $owned.power) { throw 'Owned controllers must remain running and the member must remain off.' }
        $disks=@(Get-VMHardDiskDrive -VM $vm)
        if($disks.Count -lt 1) { throw 'Owned controller disk is missing.' }
        $paths=@($vm.Path)+@($disks | ForEach-Object {$_.Path})
        foreach($property in @('ConfigurationLocation','SnapshotFileLocation','SmartPagingFilePath')) { if($vm.PSObject.Properties[$property] -and $vm.$property) { $paths+=@($vm.$property) } }
        foreach($path in $paths) {
            if(-not $path -or -not (Assert-UnlinkedPath $path).StartsWith($profile+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Controller path or disk lies outside owned profile.' }
        }
        $adapters=@(Get-VMNetworkAdapter -VM $vm)
        if($adapters.Count -ne 1 -or $adapters[0].SwitchId.ToString() -cne $current.switch_id) { throw 'Controller network isolation differs.' }
    }
}
function Write-NewHostJson([string]$Path,$Value) {
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 24))
    Write-NewHostBytes $Path $bytes
}
function Write-NewHostBytes([string]$Path,[byte[]]$Bytes) {
    $full=Assert-UnlinkedPath $Path
    if(-not $full.StartsWith($resultRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Report escaped qualification output.' }
    if(Test-Path -LiteralPath $full) { throw 'Existing host evidence is preserved.' }
    $pending=$full+'.pending-'+[guid]::NewGuid().ToString('N')
    $stream=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Move($pending,$full)
}
function Assert-CaptureComplete($Captures) {
    foreach($name in @('native-access.json','access-observations.json','access-acl-snapshots.json')) {
        if(-not $Captures.Contains($name) -or $Captures[$name] -notmatch '^[A-F0-9]{64}$') { throw 'Raw evidence capture is incomplete; guest files are preserved.' }
    }
}
function Get-ProfileMutexName([string]$Profile) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { $name=[BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Profile.ToLowerInvariant()))).Replace('-','') } finally { $hasher.Dispose() }
    return 'Global\GoSDKActiveDirectoryLab_'+$name
}
function Write-RunState {
    try {
        $full=Assert-UnlinkedPath $runStatePath
        if(-not $full.StartsWith($resultRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Journal escaped qualification output.' }
        if(Test-Path -LiteralPath $full) {
            $previous=Get-Content -LiteralPath $full -Raw | ConvertFrom-Json
            if($previous.owner -cne $runOwner -or $previous.execution_id -cne $accessRun) { throw 'Run journal ownership changed.' }
        }
        $runState.updated=[DateTime]::UtcNow.ToString('o');$runState.guest_uncertain=$script:guestUncertain
        $pending=$full+'.pending-'+[guid]::NewGuid().ToString('N')
        $stream=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($runState | ConvertTo-Json -Depth 16));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
        if(Test-Path -LiteralPath $full) { [IO.File]::Replace($pending,$full,[NullString]::Value) }
        else { [IO.File]::Move($pending,$full) }
    } catch { $script:guestUncertain=$true;throw }
}
function Wait-OwnedJob($Job,[int]$TimeoutSeconds,[string]$Action) {
    $entry=[ordered]@{id=$Job.Id;action=$Action;started=[DateTime]::UtcNow.ToString('o');state='running';timeout=$false;removed=$false;error=$null}
    $runState.jobs+=@($entry)
    $watch=[Diagnostics.Stopwatch]::StartNew();$stopRequested=$false
    try {
        Write-RunState
        while($Job.State -notin @('Completed','Failed','Stopped') -and $watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) { $null=Wait-Job -Job $Job -Timeout 2 }
        if($Job.State -notin @('Completed','Failed','Stopped')) {
            $entry.timeout=$true;$script:guestUncertain=$true
            # Persist uncertainty before requesting bounded cancellation of only
            # this owned job. Stopping remoting never proves guest termination.
            Write-RunState
            if($Job.PSObject.Methods['StopJobAsync']) { $stopRequested=$true;$Job.StopJobAsync();$null=Wait-Job -Job $Job -Timeout 5 }
            throw "Owned $Action job exceeded its deadline; no retry, capture, or cleanup may overlap it."
        }
        if($Job.State -ne 'Completed') { throw "Owned $Action job ended in state $($Job.State)." }
        return @(Receive-Job -Job $Job -ErrorAction Stop)
    } catch {
        $script:guestUncertain=$true;$entry.error=$_.Exception.Message
        if(-not $stopRequested -and $Job.State -notin @('Completed','Failed','Stopped') -and $Job.PSObject.Methods['StopJobAsync']) {
            try { $stopRequested=$true;$Job.StopJobAsync();$null=Wait-Job -Job $Job -Timeout 5 }
            catch { $entry.cancellation_error=$_.Exception.Message }
        }
        throw
    }
    finally {
        $entry.state=$Job.State.ToString()
        if($Job.State -in @('Completed','Failed','Stopped')) {
            try { Remove-Job -Job $Job -ErrorAction Stop;$entry.removed=$true } catch { $script:guestUncertain=$true;$entry.error=$_.Exception.Message }
        }
        Write-RunState
    }
}
function Invoke-OwnedGuest {
    param([scriptblock]$Script,[object[]]$Arguments,[int]$TimeoutSeconds,[string]$Action,[string]$FilePath='')
    if($script:guestUncertain) { throw 'Prior guest work or evidence is uncertain; no further guest command is permitted.' }
    Assert-OwnedControllers
    $runState.phase='guest-'+$Action+'-requested';Write-RunState
    try {
        if($FilePath) { $job=Invoke-Command -VMId ([guid]$machine.id) -Credential $credential -FilePath $FilePath -ArgumentList $Arguments -AsJob -ErrorAction Stop }
        else { $job=Invoke-Command -VMId ([guid]$machine.id) -Credential $credential -ScriptBlock $Script -ArgumentList $Arguments -AsJob -ErrorAction Stop }
        return @(Wait-OwnedJob $job $TimeoutSeconds $Action)
    } catch { $script:guestUncertain=$true;throw }
}
function Assert-NewRunDirectory([string]$Path) {
    $full=Assert-UnlinkedPath $Path
    if(Test-Path -LiteralPath $full) { throw 'Access qualification output/journal already exists; preserve it and do not replay interrupted work.' }
    return $full
}
function Read-CompletedGuestOutcome($Payload) {
    try {
        $values=@($Payload | ConvertFrom-Json -ErrorAction Stop)
        if($values.Count -ne 1) { throw 'Completed guest result cardinality differs.' }
        $value=$values[0]
        if($value.run -cne $accessRun -or $value.native_executable_sha256 -cne $ExpectedAccessExecutableSHA256 -or
            $value.helper_source_sha256 -cne $ExpectedHelperSHA256 -or $value.sdk_source_commit -cne $ExpectedSourceCommit -or
            $value.passed -isnot [bool] -or $value.process_uncertain -isnot [bool] -or $value.cleanup.safe_to_remove_files -isnot [bool] -or $value.cleanup.acl_recovery_deferred -isnot [bool]) { throw 'Completed guest result identity or recovery evidence differs.' }
        if($value.process_uncertain) { throw 'Guest final process ownership is uncertain; no capture or cleanup may start.' }
        if($value.cleanup.acl_recovery_deferred) { throw 'Guest reported an unconfirmed live native child.' }
        return $value
    } catch { $script:guestUncertain=$true;throw }
}

$profile='H:\ad-sdk-lab\server2025';$operationMutex=$null;$mutexHeld=$false
try {
    # Same per-profile mutex as scripts/lab/lab.ps1, before state or guest actions.
    $operationMutex=[Threading.Mutex]::new($false,(Get-ProfileMutexName $profile))
    try { $mutexHeld=$operationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld=$true }
    if(-not $mutexHeld) { throw 'Another lab action is running for this profile.' }
$null=Assert-UnlinkedPath $ManifestPath
$build=Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
Assert-Build $build $ExpectedSourceCommit
$statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml'
foreach($path in @($statePath,$credentialPath)) { $null=Assert-UnlinkedPath $path }
$stateHash=(Get-FileHash -LiteralPath $statePath).Hash
$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$guest=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'guest-cloning-access-cases.ps1')
$sourceHash=(Get-FileHash -LiteralPath $guest).Hash;$hostHash=(Get-FileHash -LiteralPath $PSCommandPath).Hash
Import-Module Hyper-V
Assert-OwnedControllers
$machine=@($state.machines | Where-Object role -ceq 'dc1')[0]
# One-off v2 qualification preserves the first terminal run and its evidence.
$accessRun=$build.run+'-access-qualification-v2'
$resultRoot=Assert-NewRunDirectory (Join-Path $build.directory 'server2025-native-access-v2')
$null=New-Item -ItemType Directory -Path $resultRoot
$target='C:\ad-sdk-validation\'+$accessRun+'-access'
$runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'run-journal.json';$script:guestUncertain=$false
$runState=[ordered]@{schema_version=1;owner=$runOwner;execution_id=$accessRun;phase='prepared';terminal=$false;guest_staging=$target;stage_requested=$false;stage_completed=$false;guest_result_validated=$false;guest_uncertain=$false;jobs=@();captures=[ordered]@{};staging_cleanup=$false;passed=$false;error=$null;updated=$null;lab_id=$state.id;vm_id=$machine.id;source_commit=$build.source_commit;guest_script_sha256=$sourceHash;host_script_sha256=$hostHash}
Write-RunState
$snapshot=Join-Path $resultRoot 'guest-cloning-access-cases.ps1'
Copy-Item -LiteralPath $guest -Destination $snapshot
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $resultRoot 'run-cloning-access-cases.ps1')
if((Get-FileHash -LiteralPath $snapshot).Hash -cne $sourceHash -or (Get-FileHash -LiteralPath (Join-Path $resultRoot 'run-cloning-access-cases.ps1')).Hash -cne $hostHash) { throw 'Helper snapshot differs.' }
Write-NewHostJson (Join-Path $resultRoot 'build-manifest.json') $build
Copy-Item -LiteralPath $build.access_helper -Destination (Join-Path $resultRoot 'cloning-access-helper.go')
if((Get-FileHash -LiteralPath (Join-Path $resultRoot 'cloning-access-helper.go')).Hash -cne $ExpectedHelperSHA256) { throw 'Access helper source snapshot differs.' }
$saved=Import-Clixml -LiteralPath $credentialPath;$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
$created=$false;$data=$null;$failure=$null;$cleanupFailure=$null;$captureErrors=@();$captures=[ordered]@{};$stagingCleanup=$false
try {
    Assert-Build $build $ExpectedSourceCommit
    $binaryBytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($build.access_executable))
    $runState.stage_requested=$true;Write-RunState
    $null=Invoke-OwnedGuest -Arguments @($target,$accessRun,$binaryBytes,$build.access_executable_sha256) -TimeoutSeconds 60 -Action 'stage' -Script {
        param($Directory,$Run,$Binary,$BinaryHash)
        $ErrorActionPreference='Stop'
        $full=[IO.Path]::GetFullPath($Directory)
        if([IO.Path]::GetFileName($full) -cne ($Run+'-access') -or -not $full.StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $full)) { throw 'Unexpected or existing guest staging directory.' }
        for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked guest staging directory.' } }
        $null=New-Item -ItemType Directory -Path $full
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Run)
        $stream=[IO.File]::Open((Join-Path $full 'owner.txt'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
        $bytes=[Convert]::FromBase64String($Binary)
        $executable=Join-Path $full 'dccloning.exe'
        $stream=[IO.File]::Open($executable,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
        if((Get-FileHash -LiteralPath $executable).Hash -cne $BinaryHash) { throw 'Staged access helper hash differs.' }
    }
    $created=$true;$runState.stage_completed=$true;Write-RunState
    if((Get-FileHash -LiteralPath $snapshot).Hash -cne $sourceHash) { throw 'Guest helper changed before execution.' }
    $payload=Invoke-OwnedGuest -FilePath $snapshot -Arguments @($machine.name,"$target\dccloning.exe",$build.access_executable_sha256,$accessRun,$ExpectedHelperSHA256) -TimeoutSeconds $CaseTimeoutSeconds -Action 'cases'
    try {
        Write-NewHostJson (Join-Path $resultRoot 'guest-return.json') ([ordered]@{payload=@($payload)})
        $data=Read-CompletedGuestOutcome $payload
        Write-NewHostJson (Join-Path $resultRoot 'reference.json') $data
        $runState.guest_result_validated=$true;Write-RunState
    } catch { $script:guestUncertain=$true;throw }
} catch { $failure=$_ }
finally {
        if($created -and $runState.guest_result_validated -and -not $script:guestUncertain) {
            $captureWatch=[Diagnostics.Stopwatch]::StartNew()
            $evidenceNames=@('native-access.json','access-observations.json','access-acl-snapshots.json')
            try {
                $extraNames=@(Invoke-OwnedGuest -Arguments @($target,$accessRun) -TimeoutSeconds ([Math]::Min(30,$CaptureTimeoutSeconds)) -Action 'list-evidence' -Script {
                    param($Directory,$Run)
                    $ErrorActionPreference='Stop'
                    $full=[IO.Path]::GetFullPath($Directory)
                    if([IO.Path]::GetFileName($full) -cne ($Run+'-access') -or -not $full.StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence directory differs.' }
                    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked evidence directory.' } }
                    if([IO.File]::ReadAllText((Join-Path $full 'owner.txt')) -cne $Run) { throw 'Evidence owner differs.' }
                    foreach($file in @(Get-ChildItem -LiteralPath $full -Force)) {
                        if($file.Name -match '^access-(checkpoint|native)-[0-9]{4}\.json$') {
                            if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked or unexpected evidence entry.' }
                            [string]$file.Name
                        }
                    }
                })
                if($extraNames.Count -gt 128) { throw 'Unexpected evidence inventory size; retain guest staging.' }
                $evidenceNames+=@($extraNames | ForEach-Object {([string]$_).ToCharArray() -join ''})
            } catch { $captureErrors+=@($_.Exception.Message) }
            foreach($name in $evidenceNames) {
                if($script:guestUncertain) { break }
                try {
                    $remaining=[int][Math]::Floor($CaptureTimeoutSeconds-$captureWatch.Elapsed.TotalSeconds)
                    if($remaining -lt 1) { $script:guestUncertain=$true;throw 'Aggregate evidence capture deadline expired; no further guest command will start.' }
                    $capture=@(Invoke-OwnedGuest -Arguments @($target,$accessRun,$name) -TimeoutSeconds ([Math]::Min(30,$remaining)) -Action ('capture-'+$name) -Script {
                        param($Directory,$Run,$Name)
                        $ErrorActionPreference='Stop'
                        $full=[IO.Path]::GetFullPath($Directory)
                        if([IO.Path]::GetFileName($full) -cne ($Run+'-access') -or -not $full.StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase) -or
                            ($Name -notin @('native-access.json','access-observations.json','access-acl-snapshots.json') -and $Name -notmatch '^access-(checkpoint|native)-[0-9]{4}\.json$')) { throw 'Evidence source differs.' }
                        $path=Join-Path $full $Name
                        for($cursor=$path;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked guest evidence.' } }
                        if([IO.File]::ReadAllText((Join-Path $full 'owner.txt')) -cne $Run) { throw 'Evidence owner differs.' }
                        $bytes=[IO.File]::ReadAllBytes($path)
                        $hasher=[Security.Cryptography.SHA256]::Create()
                        try { $hash=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','') } finally { $hasher.Dispose() }
                        [pscustomobject]@{sha256=$hash;bytes_base64=[Convert]::ToBase64String($bytes)}
                    })
                    if($capture.Count -ne 1 -or $capture[0].sha256 -notmatch '^[A-F0-9]{64}$') { throw 'Captured evidence envelope differs.' }
                    $rawHash=([string]$capture[0].sha256).ToCharArray() -join ''
                    $destination=Join-Path $resultRoot $name
                    if(Test-Path -LiteralPath $destination) { throw 'Existing captured report is preserved.' }
                    Write-NewHostBytes $destination ([Convert]::FromBase64String($capture[0].bytes_base64))
                    if((Get-FileHash -LiteralPath $destination).Hash -cne $rawHash) { throw 'Raw report hash differs; guest files are preserved.' }
                    $captures[$name]=$rawHash
                    $runState.captures[$name]=$rawHash;Write-RunState
                } catch { $captureErrors+=@($_.Exception.Message) }
            }
            try {
                if($script:guestUncertain) { throw 'Guest work or capture is uncertain; cleanup is prohibited.' }
                Assert-CaptureComplete $captures
                if($captureErrors.Count) { throw 'Evidence capture failed; guest staging is preserved.' }
                $raw=Get-Content -LiteralPath (Join-Path $resultRoot 'native-access.json') -Raw | ConvertFrom-Json
                if($raw.run -cne $accessRun -or $raw.native_executable_sha256 -cne $build.access_executable_sha256 -or $raw.helper_source_sha256 -cne $ExpectedHelperSHA256 -or -not $raw.cleanup.safe_to_remove_files) { throw 'Guest restoration is not verified; staging is preserved.' }
                $data=$raw
                # Durably bind the raw hashes before any guest file is deleted.
                Write-NewHostJson (Join-Path $resultRoot 'captured-evidence.json') $captures
                $null=Invoke-OwnedGuest -Arguments @($target,$accessRun,($captures | ConvertTo-Json -Compress)) -TimeoutSeconds 60 -Action 'cleanup' -Script {
                    param($Directory,$Run,$CapturedJson)
                    $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
                    $full=[IO.Path]::GetFullPath($Directory)
                    if([IO.Path]::GetFileName($full) -cne ($Run+'-access') -or -not $full.StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup path escaped staging.' }
                    $paths=@($full,(Join-Path $full 'owner.txt'),(Join-Path $full 'dccloning.exe'),(Join-Path $full 'native-access.json'),(Join-Path $full 'access-observations.json'),(Join-Path $full 'access-acl-snapshots.json'))
                    foreach($path in $paths) { for($cursor=$path;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked cleanup path.' } } }
                    if([IO.File]::ReadAllText((Join-Path $full 'owner.txt')) -cne $Run) { throw 'Guest staging ownership differs.' }
                    $captured=$CapturedJson | ConvertFrom-Json
                    $capturedNames=@($captured.PSObject.Properties | ForEach-Object {$_.Name})
                    foreach($name in $capturedNames) {
                        if($name -notin @('native-access.json','access-observations.json','access-acl-snapshots.json') -and $name -notmatch '^access-(checkpoint|native)-[0-9]{4}\.json$') { throw 'Unexpected captured evidence name.' }
                        $path=Join-Path $full $name
                        if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked captured evidence.' }
                        if((Get-FileHash -LiteralPath $path).Hash -cne $captured.$name) { throw 'Captured guest report changed.' }
                    }
                    $report=Get-Content -LiteralPath (Join-Path $full 'native-access.json') -Raw | ConvertFrom-Json
                    $acl=Get-Content -LiteralPath (Join-Path $full 'access-acl-snapshots.json') -Raw | ConvertFrom-Json
                    if($report.run -cne $Run -or -not $report.cleanup.safe_to_remove_files -or $acl.fixture -cne $report.fixture) { throw 'Cleanup authorization evidence differs.' }
                    $running=@(Get-CimInstance Win32_Process -Filter "Name='dccloning.exe'" | Where-Object {$_.ExecutablePath -eq (Join-Path $full 'dccloning.exe')})
                    if($running.Count) { throw 'Owned native child remains; staging is preserved.' }
                    $fixture=Join-Path $full 'fixture';$custom=Join-Path $fixture 'CustomDCCloneAllowList.xml'
                    $stageChildren=@(Get-ChildItem -LiteralPath $full -Force)
                    if($stageChildren.Count -ne $capturedNames.Count+3) { throw 'Unexpected staging child is preserved.' }
                    $allowedFiles=@('owner.txt','dccloning.exe')+$capturedNames
                    foreach($child in $stageChildren) { if(($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($child.PSIsContainer -and $child.Name -cne 'fixture') -or (-not $child.PSIsContainer -and $child.Name -notin $allowedFiles)) { throw 'Unexpected staging child is preserved.' } }
                    if($acl.directory_path -cne $fixture -or $acl.custom_file_path -cne $custom -or [IO.File]::ReadAllText((Join-Path $fixture 'owner.txt')) -cne $report.fixture) { throw 'Fixture ownership differs.' }
                    $fixtureChildren=@(Get-ChildItem -LiteralPath $fixture -Force)
                    if($fixtureChildren.Count -ne 3) { throw 'Unexpected fixture child is preserved.' }
                    foreach($child in $fixtureChildren) { if($child.PSIsContainer -or ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $child.Name -notin @('owner.txt','unrelated.txt','CustomDCCloneAllowList.xml')) { throw 'Unexpected fixture child is preserved.' } }
                    $sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
                    if([IO.Directory]::GetAccessControl($fixture,$sections).GetSecurityDescriptorSddlForm($sections) -cne $acl.directory.sddl -or
                        [IO.File]::GetAccessControl($custom,$sections).GetSecurityDescriptorSddlForm($sections) -cne $acl.custom_file.sddl -or
                        (Get-FileHash -LiteralPath $custom).Hash -cne $acl.custom_sha256 -or
                        (Get-FileHash -LiteralPath (Join-Path $fixture 'unrelated.txt')).Hash -cne $acl.sentinel_sha256 -or
                        (Get-FileHash -LiteralPath (Join-Path $env:windir 'System32\DefaultDCCloneAllowList.xml')).Hash -cne $acl.default_sha256) { throw 'Restored fixture descriptor or content changed.' }
                    # All paths were validated above. Delete only the exact owned children, without recursion.
                    foreach($child in $fixtureChildren) { Remove-Item -LiteralPath $child.FullName -Force }
                    [IO.Directory]::Delete($fixture,$false)
                    foreach($child in @($stageChildren | Where-Object {-not $_.PSIsContainer})) { Remove-Item -LiteralPath $child.FullName -Force }
                    [IO.Directory]::Delete($full,$false)
                    if(Test-Path -LiteralPath $full) { throw 'Staging directory remains.' }
                }
                $stagingCleanup=$true
            } catch { $cleanupFailure=$_ }
        }
}
$passed=($null -eq $failure -and $null -eq $cleanupFailure -and -not $script:guestUncertain -and $captureErrors.Count -eq 0 -and $stagingCleanup -and $null -ne $data -and $data.passed)
$record=[ordered]@{schema_version=2;run=$accessRun;timestamp=[DateTime]::UtcNow.ToString('o');source_commit=$build.source_commit;source_archive_sha256=$build.source_archive_sha256;baseline_cli_sha256=$build.native_executable_sha256;access_binary_sha256=$build.access_executable_sha256;access_helper_sha256=$ExpectedHelperSHA256;guest_script_sha256=$sourceHash;host_script_sha256=$hostHash;lab_state_sha256=$stateHash;lab_id=$state.id;vm_id=$machine.id;raw_report_sha256=$captures;staging_cleanup=$stagingCleanup;guest_uncertain=$script:guestUncertain;passed=[bool]$passed;error=$(if($failure){$failure.Exception.Message}else{$null});cleanup_error=$(if($cleanupFailure){$cleanupFailure.Exception.Message}else{$null});capture_errors=$captureErrors}
Write-NewHostJson (Join-Path $resultRoot 'qualification.json') $record
$runState.passed=$passed;$runState.staging_cleanup=$stagingCleanup;$runState.error=$record.error;$runState.cleanup_error=$record.cleanup_error;$runState.capture_errors=$captureErrors
$runState.phase=if($passed){'passed'}else{'failed-preserve-for-review'};$runState.terminal=$true;Write-RunState
[pscustomobject]@{directory=$resultRoot;passed=$passed;cases=$(if($data){@($data.cases).Count}else{0});error=$record.error;cleanup_error=$record.cleanup_error;capture_errors=$captureErrors} | ConvertTo-Json -Depth 6
if(-not $passed) { throw 'Access qualification failed; inspect retained evidence. No automatic retry.' }
} finally {
    if($mutexHeld) { $operationMutex.ReleaseMutex() }
    if($operationMutex) { $operationMutex.Dispose() }
}
