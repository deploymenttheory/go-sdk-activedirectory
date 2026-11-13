#Requires -Version 5.1
# PREPARED ONLY: bounded Server 2025 Offline XML comparison of frozen 4120ce5.
# This runner preserves all guest staging; it contains no cleanup/retry path.
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedManifestSHA256,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedGuestScriptSHA256,
    [ValidateRange(60,600)][int]$ProcessTimeoutSeconds=300,
    [ValidateRange(30,180)][int]$CaptureTimeoutSeconds=120
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
    $expectedPorts=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
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
        $adapterID=[string]$adapters[0].Id
        if(-not $adapterID.StartsWith('Microsoft:'+$owned.id+'\',[StringComparison]::OrdinalIgnoreCase) -or
            -not $expectedPorts.Add($adapterID+'\C')) { throw 'Owned adapter identity is missing or duplicated.' }
    }
    Assert-SwitchPorts $expectedPorts $current.switch_id
}
function Assert-SwitchPorts($ExpectedPorts,[string]$SwitchID) {
    # Query configured allocations in every state, including the powered-off
    # member. Avoid Get-VMNetworkAdapter -All, which fails on an unrelated host
    # object. Microsoft defines HostResource as one assigned resource and
    # InstanceID as the port allocation identity:
    # https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/msvm-ethernetportallocationsettingdata
    # On this verified host, allocation InstanceID equals adapter.Id + '\C'.
    $canonical='\\SHOCONE\root\virtualization\v2:Msvm_VirtualEthernetSwitch.CreationClassName="Msvm_VirtualEthernetSwitch",Name="'+$SwitchID+'"'
    $localManagement='\\SHOCONE\root\virtualization\v2:Msvm_ComputerSystem.CreationClassName="Msvm_ComputerSystem",Name="SHOCONE"'
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $allocations=@(Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_EthernetPortAllocationSettingData -OperationTimeoutSec 10 -ErrorAction Stop)
    foreach($allocation in $allocations) {
        if($null -eq $allocation.HostResource) { continue } # Unconnected allocation.
        $resources=@($allocation.HostResource)
        if($resources.Count -eq 0) { continue }
        if($resources.Count -ne 1 -or $resources[0] -isnot [string]) { throw 'Configured port has malformed or multiple host resources.' }
        if([string]::Equals($resources[0],$localManagement,[StringComparison]::OrdinalIgnoreCase)) {
            # Corroborate management-OS ownership through the CIM association;
            # do not infer an owning switch by parsing the allocation InstanceID.
            if($null -ne $allocation.Parent) { throw 'Management-OS allocation parent is ambiguous.' }
            $owners=@(Get-CimAssociatedInstance -InputObject $allocation -ResultClassName Msvm_VirtualEthernetSwitchSettingData -OperationTimeoutSec 10 -ErrorAction Stop)
            $managementSwitch=[guid]::Empty
            if($owners.Count -ne 1 -or $owners[0].VirtualSystemIdentifier -isnot [string] -or
                -not [guid]::TryParse($owners[0].VirtualSystemIdentifier,[ref]$managementSwitch) -or
                $managementSwitch -eq [guid]::Empty -or
                -not [string]::Equals($owners[0].InstanceID,'Microsoft:'+$owners[0].VirtualSystemIdentifier,[StringComparison]::OrdinalIgnoreCase)) { throw 'Management-OS allocation has no unambiguous associated switch.' }
            if($managementSwitch -eq [guid]$SwitchID) { throw 'Owned switch has a management-OS connection.' }
            continue
        }
        if($resources[0] -notmatch '^\\\\[^\\"]+\\root\\virtualization\\v2:Msvm_VirtualEthernetSwitch\.CreationClassName="Msvm_VirtualEthernetSwitch",Name="([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})"$') { throw 'Configured port has an unrecognized host resource.' }
        $resourceSwitch=$Matches[1]
        if(-not [string]::Equals($resourceSwitch,$SwitchID,[StringComparison]::OrdinalIgnoreCase)) { continue }
        if(-not [string]::Equals($resources[0],$canonical,[StringComparison]::OrdinalIgnoreCase) -or
            $allocation.InstanceID -isnot [string] -or -not $ExpectedPorts.Contains($allocation.InstanceID) -or
            -not $seen.Add($allocation.InstanceID)) { throw 'Owned switch has a foreign, malformed, or duplicate configured port.' }
    }
    if($ExpectedPorts.Count -ne 3 -or -not $seen.SetEquals($ExpectedPorts)) { throw 'Owned switch configured membership is incomplete.' }
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
            if($previous.owner -cne $runOwner -or $previous.execution_id -cne $executionID) { throw 'Run journal ownership changed.' }
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
    if(Test-Path -LiteralPath $full) { throw 'Clone configuration output/journal already exists; preserve it and do not replay interrupted work.' }
    return $full
}
function Assert-Build($Build) {
    if($ExpectedManifestSHA256 -cne '6AB9B1B9129A39BC9C68FB4B00CB38D6DB4A31C4E925BB1C3790431927AD9E29' -or
        $Build.source_commit -cne '4120ce5d13dd49de490cef67d41767ac3b409715' -or $Build.status -cne 'built' -or
        $Build.run -cne 'clone-config-reviewed-20261112T211528Z-81823b4e' -or
        $Build.source_archive_sha256 -cne '1FA1A904FDEE8ED7F49428117C8215989F895E3EBCF7AC3554827248654C2E19' -or
        $Build.native_executable_sha256 -cne '9FC1C95989517E0AC5753747B56FB17931C8ECB387E22083F6B0B60C6D4642B2' -or
        $Build.reference_harness_sha256 -cne '3F68500FEC99CAF5948E4C391B62AD51CCB0A4C65A50C4D52E2E423DC4CCDC45' -or
        $Build.schema_evidence_sha256 -cne 'A061F397D27B26563E6B4C7D611F707F5A3CA4A5B9CBD3353CB2CDC7BA9D7F35') { throw 'Reviewed immutable build identity differs.' }
    $directory=Assert-UnlinkedPath $Build.directory
    if($directory -cne (Join-Path 'H:\ad-sdk-lab\qualifications' $Build.run)) { throw 'Immutable build directory differs.' }
    $paths=[ordered]@{source_archive='source.zip';native_executable='dccloneconfig.exe';test_executable='dccloning.test.exe';reference_harness='source\scripts\lab\reference-dc-clone-config.ps1';schema_evidence='source\docs\research\dc-cloning-evidence\server2025-readonly.json'}
    foreach($name in $paths.Keys) {
        $hashName=$name+'_sha256'
        if($Build.$hashName -notmatch '^[A-F0-9]{64}$' -or (Assert-UnlinkedPath $Build.$name) -cne (Join-Path $directory $paths[$name]) -or
            (Get-FileHash -LiteralPath $Build.$name -Algorithm SHA256).Hash -cne $Build.$hashName) { throw 'Immutable artifact path or hash differs.' }
    }
    if($Build.builder_sha256 -notmatch '^[A-F0-9]{64}$' -or -not $Build.toolchain -or -not $Build.built_utc) { throw 'Build provenance is incomplete.' }
}
function Read-GuestOutcome($Payload) {
    try {
        $values=@($Payload | ConvertFrom-Json -ErrorAction Stop)
        if($values.Count -ne 1) { throw 'Guest outcome cardinality differs.' }
        $value=$values[0]
        if($value.run -cne $executionID -or $value.source_commit -cne $build.source_commit -or
            $value.native_sha256 -cne $build.native_executable_sha256 -or $value.reference_sha256 -cne $build.reference_harness_sha256 -or
            $value.schema_sha256 -cne $build.schema_evidence_sha256 -or $value.process_uncertain -isnot [bool] -or
            $value.completed -isnot [bool] -or $value.passed -isnot [bool] -or -not $value.completed -or $value.process_uncertain -or
            $value.pid -le 0 -or -not $value.started_utc -or $null -eq $value.exit_code -or
            ($value.passed -and $value.exit_code -ne 0)) { throw 'Guest process completion or payload identity is uncertain.' }
        return $value
    } catch { $script:guestUncertain=$true;throw }
}
function Test-EvidenceName([string]$Name) {
    if($Name -cin @('owner.txt','guest-process.json','reference.stdout.txt','reference.stderr.txt')) { return $true }
    return $Name -cmatch '^results/clone-config-[a-f0-9]{32}/(summary\.json|(default|name-site|v4-dynamic|v4-static|v6-dynamic|v6-static|dual-dynamic|dual-static|four-resolvers|overwrite)/(sdk\.json|sdk\.stderr\.txt|reference\.streams\.txt|sdk/DCCloneConfig\.xml|reference/DCCloneConfig\.xml))$'
}
function Save-Capture($Payload,$Outcome) {
    $values=@($Payload | ConvertFrom-Json -ErrorAction Stop)
    if($values.Count -ne 1 -or $values[0].run -cne $executionID) { throw 'Capture envelope identity differs.' }
    $files=@($values[0].files)
    if($files.Count -lt 3 -or $files.Count -gt 128) { throw 'Capture cardinality is outside its bound.' }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $total=0L;$summaryNames=@()
    foreach($file in $files) {
        if(-not (Test-EvidenceName $file.name) -or -not $seen.Add($file.name) -or $file.sha256 -notmatch '^[A-F0-9]{64}$' -or
            $file.length -lt 0 -or $file.length -gt 2097152 -or $file.bytes_base64.Length -gt 2796204) { throw 'Captured file identity or size differs.' }
        $bytes=[Convert]::FromBase64String($file.bytes_base64)
        $total+=$bytes.Length
        if($bytes.Length -ne $file.length -or $total -gt 16777216) { throw 'Capture exceeds its byte bound.' }
        $hasher=[Security.Cryptography.SHA256]::Create()
        try { $hash=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','') } finally { $hasher.Dispose() }
        if($hash -cne $file.sha256) { throw 'Captured raw hash differs.' }
        $destination=Assert-UnlinkedPath (Join-Path (Join-Path $resultRoot 'raw') ($file.name.Replace('/','\')))
        if(-not $destination.StartsWith((Join-Path $resultRoot 'raw')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Capture destination escaped.' }
        $parent=Assert-UnlinkedPath ([IO.Path]::GetDirectoryName($destination))
        [void][IO.Directory]::CreateDirectory($parent)
        Write-NewHostBytes $destination $bytes
        $runState.captures[$file.name]=$hash
        if($file.name.EndsWith('/summary.json',[StringComparison]::Ordinal)) { $summaryNames+=@($file.name) }
    }
    foreach($name in @('owner.txt','guest-process.json','reference.stdout.txt','reference.stderr.txt')) { if(-not $seen.Contains($name)) { throw 'Mandatory raw diagnostic is missing.' } }
    if($Outcome.passed) {
        if($summaryNames.Count -ne 1) { throw 'Successful reference run must have exactly one raw summary.' }
        $prefix=$summaryNames[0].Substring(0,$summaryNames[0].Length-'summary.json'.Length)
        foreach($case in @('default','name-site','v4-dynamic','v4-static','v6-dynamic','v6-static','dual-dynamic','dual-static','four-resolvers','overwrite')) {
            foreach($suffix in @('sdk.json','sdk.stderr.txt','reference.streams.txt','sdk/DCCloneConfig.xml','reference/DCCloneConfig.xml')) {
                if(-not $seen.Contains($prefix+$case+'/'+$suffix)) { throw 'Successful run is missing raw per-case evidence.' }
            }
        }
        $summary=Get-Content -LiteralPath (Join-Path (Join-Path $resultRoot 'raw') ($summaryNames[0].Replace('/','\'))) -Raw | ConvertFrom-Json
        if($summary.computer -cne 'ADSDK25DC1' -or $summary.mode -cne 'explicit offline only' -or
            $summary.sdk_sha256 -cne $build.native_executable_sha256 -or $summary.schema_evidence_sha256 -cne $build.schema_evidence_sha256 -or
            @($summary.cases).Count -ne 10) { throw 'Captured summary provenance differs.' }
        $caseNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach($case in $summary.cases) {
            if(-not $caseNames.Add($case.name) -or $case.passed -isnot [bool] -or -not $case.passed -or $case.error -or
                -not $runState.captures.Contains($prefix+$case.name+'/sdk/DCCloneConfig.xml') -or
                -not $runState.captures.Contains($prefix+$case.name+'/reference/DCCloneConfig.xml') -or
                $case.sdk_sha256 -cne $runState.captures[$prefix+$case.name+'/sdk/DCCloneConfig.xml'] -or
                $case.reference_sha256 -cne $runState.captures[$prefix+$case.name+'/reference/DCCloneConfig.xml']) { throw 'Captured per-case status or XML hash differs.' }
        }
    }
    Write-NewHostJson (Join-Path $resultRoot 'captured-evidence.json') $runState.captures
}

$profile='H:\ad-sdk-lab\server2025';$operationMutex=$null;$mutexHeld=$false;$runState=$null
try {
    $operationMutex=[Threading.Mutex]::new($false,(Get-ProfileMutexName $profile))
    try { $mutexHeld=$operationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld=$true }
    if(-not $mutexHeld) { throw 'Another lab action is running for this profile.' }
    $ManifestPath=Assert-UnlinkedPath $ManifestPath
    if((Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash -cne $ExpectedManifestSHA256) { throw 'Reviewed manifest hash differs.' }
    $build=Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    Assert-Build $build
    if($ManifestPath -cne (Join-Path $build.directory 'build.json')) { throw 'Supply the immutable build manifest itself.' }
    $statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml'
    foreach($path in @($statePath,$credentialPath)) { $null=Assert-UnlinkedPath $path }
    $stateHash=(Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash
    $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $guest=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'guest-clone-config-offline.ps1')
    if((Get-FileHash -LiteralPath $guest -Algorithm SHA256).Hash -cne $ExpectedGuestScriptSHA256) { throw 'Reviewed guest launcher hash differs.' }
    Import-Module Hyper-V -ErrorAction Stop
    Assert-OwnedControllers
    $machine=@($state.machines | Where-Object role -ceq 'dc1')[0]
    $executionID=$build.run+'-offline-server2025-v1'
    $resultRoot=Assert-NewRunDirectory (Join-Path $build.directory 'server2025-clone-config-offline-v1')
    [void][IO.Directory]::CreateDirectory($resultRoot)
    $target='C:\ad-sdk-validation\'+$executionID
    $runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'run-journal.json';$script:guestUncertain=$false
    $runState=[ordered]@{schema_version=1;owner=$runOwner;execution_id=$executionID;phase='prepared';terminal=$false;guest_staging=$target;guest_uncertain=$false;jobs=@();captures=[ordered]@{};passed=$false;error=$null;updated=$null;lab_id=$state.id;vm_id=$machine.id;source_commit=$build.source_commit;manifest_sha256=$ExpectedManifestSHA256;guest_script_sha256=$ExpectedGuestScriptSHA256;host_script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;staging_preserved=$true}
    Write-RunState
    $snapshot=Join-Path $resultRoot 'guest-clone-config-offline.ps1'
    Write-NewHostBytes $snapshot ([IO.File]::ReadAllBytes($guest))
    Write-NewHostBytes (Join-Path $resultRoot 'run-clone-config-offline.ps1') ([IO.File]::ReadAllBytes($PSCommandPath))
    Write-NewHostBytes (Join-Path $resultRoot 'build.json') ([IO.File]::ReadAllBytes($ManifestPath))
    Write-NewHostBytes (Join-Path $resultRoot 'reference-dc-clone-config.ps1') ([IO.File]::ReadAllBytes($build.reference_harness))
    $saved=Import-Clixml -LiteralPath $credentialPath;$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
    $payload=[ordered]@{run=$executionID;source_commit=$build.source_commit;native_sha256=$build.native_executable_sha256;reference_sha256=$build.reference_harness_sha256;schema_sha256=$build.schema_evidence_sha256;native=[Convert]::ToBase64String([IO.File]::ReadAllBytes($build.native_executable));reference=[Convert]::ToBase64String([IO.File]::ReadAllBytes($build.reference_harness));schema=[Convert]::ToBase64String([IO.File]::ReadAllBytes($build.schema_evidence))}
    Assert-Build $build
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedGuestScriptSHA256) { throw 'Guest launcher snapshot differs.' }
    $null=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Stage',$target,$executionID,($payload | ConvertTo-Json -Compress),$ProcessTimeoutSeconds) -TimeoutSeconds 60 -Action 'stage'
    $identity=[ordered]@{run=$executionID;source_commit=$build.source_commit;native_sha256=$build.native_executable_sha256;reference_sha256=$build.reference_harness_sha256;schema_sha256=$build.schema_evidence_sha256} | ConvertTo-Json -Compress
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedGuestScriptSHA256) { throw 'Guest launcher snapshot differs before process start.' }
    $returned=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Run',$target,$executionID,$identity,$ProcessTimeoutSeconds) -TimeoutSeconds ($ProcessTimeoutSeconds+45) -Action 'offline-reference'
    Write-NewHostJson (Join-Path $resultRoot 'guest-return.json') ([ordered]@{payload=@($returned)})
    $outcome=Read-GuestOutcome $returned
    $runState.phase='process-completed';Write-RunState
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedGuestScriptSHA256) { throw 'Guest launcher snapshot differs before capture.' }
    $captured=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Capture',$target,$executionID,$identity,$ProcessTimeoutSeconds) -TimeoutSeconds $CaptureTimeoutSeconds -Action 'capture'
    # Preserve the received envelope as data before parsing or validating names;
    # unexpected artifacts remain recoverable without creating unsafe paths.
    Write-NewHostJson (Join-Path $resultRoot 'capture-return.json') ([ordered]@{payload=@($captured)})
    Save-Capture $captured $outcome
    $runState.passed=[bool]$outcome.passed
    if(-not $runState.passed) { throw 'Reference comparison failed; raw evidence and guest staging are retained.' }
} catch {
    if($null -ne $runState) { $runState.error=$_.Exception.Message }
    throw
} finally {
    try {
        if($null -ne $runState) {
            $runState.terminal=$true;$runState.phase=if($runState.passed){'passed-staging-preserved'}else{'failed-preserve-for-review'}
            Write-RunState
            Write-NewHostJson (Join-Path $resultRoot 'qualification.json') $runState
        }
    } finally {
        if($mutexHeld) { $operationMutex.ReleaseMutex() }
        if($operationMutex) { $operationMutex.Dispose() }
    }
}
[pscustomobject]@{directory=$resultRoot;passed=$runState.passed;staging_preserved=$true} | ConvertTo-Json
