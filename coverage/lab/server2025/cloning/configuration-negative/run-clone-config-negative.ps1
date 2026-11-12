#Requires -Version 5.1
# PREPARE ONLY. Bounded negative Offline qualification of frozen SDK 4120ce5.
# The host stages the actual guest file; children reuse that file by -File.
# All guest files are retained. No cleanup, retry, or VM lifecycle operations.
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$HelperManifestPath,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedGuestScriptSHA256,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedBootstrapSHA256,
    [ValidateRange(1,300)][int]$ProcessTimeoutSeconds=60,
    [ValidateRange(60,1800)][int]$RunTimeoutSeconds=900,
    [ValidateRange(30,300)][int]$CaptureTimeoutSeconds=180
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$ExpectedManifestSHA256='6AB9B1B9129A39BC9C68FB4B00CB38D6DB4A31C4E925BB1C3790431927AD9E29'
$ExpectedHelperManifestSHA256='0D9B53AF8EDDD7E942144158D6BE56E343B5A4C2F576A0D4D79CA7F594907C75'
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
function Assert-NegativeBuild($Build,$Helper) {
    Assert-Build $Build
    if($Helper.source_commit -cne $Build.source_commit -or $Helper.source_archive_sha256 -cne $Build.source_archive_sha256 -or
        (Assert-UnlinkedPath $Helper.directory) -cne (Join-Path $Build.directory 'helper-v2') -or
        $Helper.helper_source_sha256 -cne 'F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1' -or
        $Helper.helper_executable_sha256 -cne '6E2DB3902038DF408192E3137CF541F86F2D43E99E3F455BA01C884140D4BEC9' -or
        $Helper.helper_tests_sha256 -cne 'AFB460A86DF41804BE206DB8ED8906231BD33EF7A67EED0EF9FC48904B4AE512' -or
        $Helper.previous_build_preserved -isnot [bool] -or -not $Helper.previous_build_preserved -or
        $null -ne $Helper.guest_execution -or -not $Helper.built_utc) { throw 'Separate helper-v2 provenance differs.' }
    foreach($pair in @(@('clone-config-helper.go','helper_source_sha256'),@('clone-config-helper.exe','helper_executable_sha256'),@('clone-config-helper_test.go','helper_tests_sha256'))) {
        $path=Assert-UnlinkedPath (Join-Path $Helper.directory $pair[0])
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $Helper.($pair[1])) { throw 'Immutable helper-v2 artifact hash differs.' }
    }
}
function Get-NegativeCaseNames {
    return @('control-v4-static','control-four-v6-dns','dynamic-with-static-fields','static-missing-address','static-missing-mask','static-missing-dns','static-empty-dns','malformed-ipv4-address','broadcast-address','broadcast-gateway','noncontiguous-mask','dynamic-with-gateway','five-v4-dns','five-v6-dns','static-without-family','static-v4-dns-only','broadcast-dns','malformed-v4-dns','malformed-v6-dns')
}
function Assert-NegativeMatrixState($Summary) {
    $names=Get-NegativeCaseNames;$cases=@($Summary.cases)
    if($Summary.completed -isnot [bool] -or $Summary.passed -isnot [bool] -or $null -eq $Summary.cases -or $cases.Count -gt $names.Count -or
        $Summary.process_uncertain -isnot [bool] -or $Summary.process_uncertain -or $Summary.publication_uncertain -isnot [bool] -or $Summary.publication_uncertain -or
        $Summary.capture_failed -isnot [bool] -or $Summary.capture_failed -or
        ($Summary.completed -and $cases.Count -ne $names.Count) -or
        (-not $Summary.completed -and ($Summary.passed -or $null -eq $Summary.error)) -or
        ($Summary.passed -and $null -ne $Summary.error)) { throw 'Matrix is not a full result or a known stopped failure.' }
    for($index=0;$index -lt $cases.Count;$index++) {
        $case=$cases[$index]
        if($case.name -cne $names[$index] -or $case.passed -isnot [bool] -or ($Summary.passed -and -not $case.passed)) { throw 'Negative case sequence or success state differs.' }
        $partialLast=(-not $Summary.completed -and $index -eq $cases.Count-1 -and -not $case.passed)
        if($null -eq $case.sdk_process -and ($null -ne $case.reference_process -or $null -ne $case.sdk_file) -or
            $null -eq $case.reference_process -and $null -ne $case.reference) { throw 'Negative child/observation order is inconsistent.' }
        foreach($process in @($case.sdk_process,$case.reference_process)) {
            if($null -eq $process) { if(-not $partialLast) { throw 'A completed case is missing a child result.' };continue }
            if($process.completed -isnot [bool] -or -not $process.completed -or $process.process_uncertain -isnot [bool] -or $process.process_uncertain -or
                $process.pid -le 0 -or -not $process.started_utc -or $null -eq $process.exit_code) { throw 'An attempted negative child has uncertain completion.' }
        }
        if(($Summary.completed -or $case.passed) -and ($null -eq $case.sdk_file -or $null -eq $case.reference)) { throw 'Completed case lacks output observations.' }
    }
}
function Read-NegativeOutcome($Payload) {
    try {
        $values=@($Payload | ConvertFrom-Json -ErrorAction Stop)
        if($values.Count -ne 1) { throw 'Negative guest outcome cardinality differs.' }
        $value=$values[0]
        if($value.schema_version -ne 1 -or $value.run -cne $executionID -or $value.computer -cne 'ADSDK25DC1' -or $value.mode -cne 'explicit Offline only' -or
            $value.source_commit -cne $build.source_commit -or $value.source_archive_sha256 -cne $build.source_archive_sha256 -or
            $value.build_manifest_sha256 -cne $ExpectedManifestSHA256 -or $value.helper_build_manifest_sha256 -cne $ExpectedHelperManifestSHA256 -or
            $value.helper_source_sha256 -cne $helperBuild.helper_source_sha256 -or $value.helper_binary_sha256 -cne $helperBuild.helper_executable_sha256 -or
            $value.harness_sha256 -cne $ExpectedGuestScriptSHA256 -or $value.staging_preserved -isnot [bool] -or -not $value.staging_preserved) { throw 'Negative outcome identity or preservation evidence differs.' }
        Assert-NegativeMatrixState $value
        return $value
    } catch { $script:guestUncertain=$true;throw }
}
function Test-NegativeEvidenceName([string]$Name) {
    if($Name -cin @('owner.txt','negative-cases/owner.txt','negative-cases/started.json','negative-cases/summary.json')) { return $true }
    $parts=$Name.Split('/')
    if($parts.Count -lt 3 -or $parts[0] -cne 'negative-cases' -or $parts[1] -cnotin (Get-NegativeCaseNames)) { return $false }
    $suffix=$parts[2..($parts.Count-1)] -join '/'
    return $suffix -cmatch '^(case\.json|options\.json|before\.json|sdk-observed\.json|observations\.json|result\.json|reference\.json|reference\.streams\.txt|(sdk|reference-child)\.(requested|started|finished)\.json|(sdk|reference-child)\.(stdout|stderr)\.txt|(sdk|reference)/DCCloneConfig\.xml)$'
}
function Save-NegativeCapture($Payload,$Outcome) {
    $values=@($Payload | ConvertFrom-Json -ErrorAction Stop)
    if($values.Count -ne 1 -or $values[0].run -cne $executionID) { throw 'Negative capture envelope identity differs.' }
    $files=@($values[0].files)
    if($files.Count -lt 4 -or $files.Count -gt 512) { throw 'Negative capture file count is outside its bound.' }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
    foreach($file in $files) {
        if(-not (Test-NegativeEvidenceName $file.name) -or -not $seen.Add($file.name) -or $file.sha256 -notmatch '^[A-F0-9]{64}$' -or
            $file.length -lt 0 -or $file.length -gt 2097152 -or $file.bytes_base64.Length -gt 2796204) { throw 'Negative raw file identity or size differs.' }
        $bytes=[Convert]::FromBase64String($file.bytes_base64);$total+=$bytes.Length
        if($bytes.Length -ne $file.length -or $total -gt 33554432) { throw 'Negative capture byte bound exceeded.' }
        $hasher=[Security.Cryptography.SHA256]::Create()
        try { $hash=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','') } finally { $hasher.Dispose() }
        if($hash -cne $file.sha256) { throw 'Negative capture raw hash differs.' }
        $destination=Assert-UnlinkedPath (Join-Path (Join-Path $resultRoot 'raw') ($file.name.Replace('/','\')))
        if(-not $destination.StartsWith((Join-Path $resultRoot 'raw')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Negative capture escaped host evidence.' }
        $parent=Assert-UnlinkedPath ([IO.Path]::GetDirectoryName($destination));[void][IO.Directory]::CreateDirectory($parent)
        Write-NewHostBytes $destination $bytes
        $runState.captures[$file.name]=$hash
    }
    foreach($name in @('owner.txt','negative-cases/owner.txt','negative-cases/started.json','negative-cases/summary.json')) { if(-not $seen.Contains($name)) { throw 'Mandatory negative run evidence is missing.' } }
    $rawRoot=Join-Path $resultRoot 'raw'
    foreach($owner in @('owner.txt','negative-cases\owner.txt')) { if([IO.File]::ReadAllText((Join-Path $rawRoot $owner)) -cne $executionID) { throw 'Captured negative owner differs.' } }
    $summary=Get-Content -LiteralPath (Join-Path $rawRoot 'negative-cases\summary.json') -Raw | ConvertFrom-Json
    $validated=Read-NegativeOutcome ($summary | ConvertTo-Json -Depth 32 -Compress)
    if(($validated | ConvertTo-Json -Depth 32 -Compress) -cne ($Outcome | ConvertTo-Json -Depth 32 -Compress)) { throw 'Captured summary differs from the returned process outcome.' }
    foreach($case in $Outcome.cases) {
        $prefix='negative-cases/'+$case.name+'/'
        foreach($suffix in @('case.json','options.json','before.json')) {
            if(-not $seen.Contains($prefix+$suffix)) { throw 'Negative case preparation evidence is missing.' }
        }
        foreach($pair in @(@($case.sdk_process,'sdk'),@($case.reference_process,'reference-child'))) {
            $process=$pair[0];$stem=$pair[1]
            foreach($suffix in @('.requested.json','.started.json','.finished.json','.stdout.txt','.stderr.txt')) {
                if(($null -ne $process) -ne $seen.Contains($prefix+$stem+$suffix)) { throw 'Raw child attempt status differs from its summary.' }
            }
            if($null -eq $process) { continue }
            if($process.stdout_sha256 -cne $runState.captures[$prefix+$stem+'.stdout.txt'] -or $process.stderr_sha256 -cne $runState.captures[$prefix+$stem+'.stderr.txt']) { throw 'Negative child stream hashes differ from raw capture.' }
            $finished=Get-Content -LiteralPath (Join-Path $rawRoot (($prefix+$stem+'.finished.json').Replace('/','\'))) -Raw | ConvertFrom-Json
            if(($finished | ConvertTo-Json -Depth 32 -Compress) -cne ($process | ConvertTo-Json -Depth 32 -Compress)) { throw 'Raw child completion differs from the validated summary.' }
        }
        if($null -ne $case.sdk_file -and -not $seen.Contains($prefix+'sdk-observed.json')) { throw 'SDK observation evidence is missing.' }
        $referenceFile=$null
        if($null -ne $case.reference) {
            foreach($suffix in @('observations.json','reference.json')) { if(-not $seen.Contains($prefix+$suffix)) { throw 'Reference observation evidence is missing.' } }
            if($null -ne $case.reference.streams_sha256 -and
                (-not $seen.Contains($prefix+'reference.streams.txt') -or $case.reference.streams_sha256 -cne $runState.captures[$prefix+'reference.streams.txt'])) { throw 'Reference cmdlet stream hash differs.' }
            $referenceFile=$case.reference.file
        }
        foreach($pair in @(@($case.sdk_file,'sdk'),@($referenceFile,'reference'))) {
            $file=$pair[0];$name=$prefix+$pair[1]+'/DCCloneConfig.xml'
            if($null -eq $file) { if($Outcome.completed) { throw 'Full matrix lacks file observations.' };continue }
            if($file.exists -isnot [bool] -or $file.exists -ne $seen.Contains($name) -or ($file.exists -and $file.sha256 -cne $runState.captures[$name])) { throw 'Negative XML presence or raw hash differs.' }
        }
        if($seen.Contains($prefix+'result.json')) {
            $caseResult=Get-Content -LiteralPath (Join-Path $rawRoot (($prefix+'result.json').Replace('/','\'))) -Raw | ConvertFrom-Json
            if(($caseResult | ConvertTo-Json -Depth 32 -Compress) -cne ($case | ConvertTo-Json -Depth 32 -Compress)) { throw 'Negative per-case result differs from summary.' }
        } elseif($Outcome.completed -or $case.name -cne $Outcome.cases[-1].name) { throw 'Completed negative case result is missing.' }
        if($Outcome.completed -and (-not $seen.Contains($prefix+'reference.streams.txt') -or $null -eq $case.reference.streams_sha256)) { throw 'Full matrix reference stream evidence is missing.' }
    }
    Write-NewHostJson (Join-Path $resultRoot 'captured-evidence.json') $runState.captures
}

$profile='H:\ad-sdk-lab\server2025';$operationMutex=$null;$mutexHeld=$false;$runState=$null
try {
    $operationMutex=[Threading.Mutex]::new($false,(Get-ProfileMutexName $profile))
    try { $mutexHeld=$operationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld=$true }
    if(-not $mutexHeld) { throw 'Another lab action is running for this profile.' }
    $ManifestPath=Assert-UnlinkedPath $ManifestPath;$HelperManifestPath=Assert-UnlinkedPath $HelperManifestPath
    if((Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash -cne $ExpectedManifestSHA256 -or
        (Get-FileHash -LiteralPath $HelperManifestPath -Algorithm SHA256).Hash -cne $ExpectedHelperManifestSHA256) { throw 'Negative qualification manifest bytes differ.' }
    $build=Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json;$helperBuild=Get-Content -LiteralPath $HelperManifestPath -Raw | ConvertFrom-Json
    Assert-NegativeBuild $build $helperBuild
    if($ManifestPath -cne (Join-Path $build.directory 'build.json') -or $HelperManifestPath -cne (Join-Path $helperBuild.directory 'build.json')) { throw 'Supply both immutable manifests from their build directories.' }
    $statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml'
    foreach($path in @($statePath,$credentialPath)) { $null=Assert-UnlinkedPath $path }
    $stateHash=(Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash;$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $guest=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1')
    $bootstrap=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'bootstrap-clone-config-negative.ps1')
    if((Get-FileHash -LiteralPath $guest -Algorithm SHA256).Hash -cne $ExpectedGuestScriptSHA256 -or
        (Get-FileHash -LiteralPath $bootstrap -Algorithm SHA256).Hash -cne $ExpectedBootstrapSHA256) { throw 'Reviewed negative guest/bootstrap source differs.' }
    Import-Module Hyper-V -ErrorAction Stop
    Assert-OwnedControllers
    $machine=@($state.machines | Where-Object role -ceq 'dc1')[0]
    $executionID=$build.run+'-negative-server2025-v1';$target='C:\ad-sdk-validation\'+$executionID
    $resultRoot=Assert-NewRunDirectory (Join-Path $build.directory 'server2025-clone-config-negative-v1');[void][IO.Directory]::CreateDirectory($resultRoot)
    $runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'run-journal.json';$script:guestUncertain=$false
    $runState=[ordered]@{schema_version=1;owner=$runOwner;execution_id=$executionID;phase='prepared';terminal=$false;guest_staging=$target;guest_uncertain=$false;jobs=@();captures=[ordered]@{};passed=$false;error=$null;updated=$null;lab_id=$state.id;vm_id=$machine.id;source_commit=$build.source_commit;manifest_sha256=$ExpectedManifestSHA256;helper_manifest_sha256=$ExpectedHelperManifestSHA256;guest_script_sha256=$ExpectedGuestScriptSHA256;bootstrap_sha256=$ExpectedBootstrapSHA256;host_script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;staging_preserved=$true}
    Write-RunState
    $snapshot=Join-Path $resultRoot 'bootstrap-clone-config-negative.ps1'
    $source=Join-Path $helperBuild.directory 'clone-config-helper.go';$native=Join-Path $helperBuild.directory 'clone-config-helper.exe'
    foreach($pair in @(@($bootstrap,$snapshot),@($guest,(Join-Path $resultRoot 'guest-clone-config-negative.ps1')),@($PSCommandPath,(Join-Path $resultRoot 'run-clone-config-negative.ps1')),@($ManifestPath,(Join-Path $resultRoot 'build.json')),@($HelperManifestPath,(Join-Path $resultRoot 'helper-v2-build.json')),@($source,(Join-Path $resultRoot 'clone-config-helper.go')))) { Write-NewHostBytes $pair[1] ([IO.File]::ReadAllBytes($pair[0])) }
    $identity=[ordered]@{run=$executionID;source_commit=$build.source_commit;guest_sha256=$ExpectedGuestScriptSHA256;helper_sha256=$helperBuild.helper_executable_sha256;source_sha256=$helperBuild.helper_source_sha256;build_sha256=$ExpectedManifestSHA256;helper_build_sha256=$ExpectedHelperManifestSHA256}
    $payload=[ordered]@{};foreach($key in $identity.Keys) { $payload[$key]=$identity[$key] }
    foreach($pair in @(@('guest',$guest),@('helper',$native),@('source',$source),@('build',$ManifestPath),@('helper_build',$HelperManifestPath))) { $payload[$pair[0]]=[Convert]::ToBase64String([IO.File]::ReadAllBytes($pair[1])) }
    $saved=Import-Clixml -LiteralPath $credentialPath;$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
    Assert-NegativeBuild $build $helperBuild
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedBootstrapSHA256) { throw 'Negative bootstrap snapshot differs.' }
    $null=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Stage',$target,$executionID,($payload | ConvertTo-Json -Compress),$ProcessTimeoutSeconds) -TimeoutSeconds 60 -Action 'stage'
    $identityJson=$identity | ConvertTo-Json -Compress
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedBootstrapSHA256) { throw 'Negative bootstrap changed before run.' }
    $returned=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Run',$target,$executionID,$identityJson,$ProcessTimeoutSeconds) -TimeoutSeconds $RunTimeoutSeconds -Action 'negative-cases'
    Write-NewHostJson (Join-Path $resultRoot 'guest-return.json') ([ordered]@{payload=@($returned)})
    $outcome=Read-NegativeOutcome $returned
    $runState.phase='negative-processes-completed';Write-RunState
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedBootstrapSHA256) { throw 'Negative bootstrap changed before capture.' }
    $captured=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Capture',$target,$executionID,$identityJson,$ProcessTimeoutSeconds) -TimeoutSeconds $CaptureTimeoutSeconds -Action 'capture'
    Write-NewHostJson (Join-Path $resultRoot 'capture-return.json') ([ordered]@{payload=@($captured)})
    Save-NegativeCapture $captured $outcome
    $runState.passed=[bool]$outcome.passed
    if(-not $runState.passed) { throw 'Negative qualification failed; raw evidence and all guest files are preserved.' }
} catch {
    if($null -ne $runState) { $runState.error=$_.Exception.Message }
    throw
} finally {
    try {
        if($null -ne $runState) {
            $runState.terminal=$true;$runState.phase=if($runState.passed){'passed-staging-preserved'}else{'failed-preserve-for-review'}
            Write-RunState;Write-NewHostJson (Join-Path $resultRoot 'qualification.json') $runState
        }
    } finally {
        if($mutexHeld) { $operationMutex.ReleaseMutex() };if($operationMutex) { $operationMutex.Dispose() }
    }
}
[pscustomobject]@{directory=$resultRoot;passed=$runState.passed;staging_preserved=$true} | ConvertTo-Json
