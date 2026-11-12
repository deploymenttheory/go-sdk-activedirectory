#Requires -Version 5.1
# PREPARE ONLY. Full online qualification has explicit temporary AD/file mutations
# solely inside the reviewed guest. This host never performs AD or VM mutations.
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedGuestScriptSHA256,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedBootstrapSHA256,
    [ValidateRange(1,300)][int]$ProcessTimeoutSeconds=60,
    [ValidateRange(1,300)][int]$ReplicationTimeoutSeconds=90,
    [ValidateRange(120,3600)][int]$RunTimeoutSeconds=1800,
    [ValidateRange(30,300)][int]$CaptureTimeoutSeconds=180
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest

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

function Get-OnlinePins {
    return [ordered]@{
        build_root='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T215735Z-b4707e3f'
        run='clone-config-reviewed-20261112T215735Z-b4707e3f-online-qualification-server2025-v1'
        source_commit='c72c7b0a4a785f177a70f26729b7d9ffff140a46'
        source_archive_sha256='79728F456A61AF3F646931DA1A128E072E782D26B50A0453B1D3D6C49BFA9DEE'
        build_manifest_sha256='8C1A3E99029AEADEDEE39904707E95B5C5C45599590A2BBF1EE0C61869E19579'
        helper_build_manifest_sha256='AC7334366C218A2A708DCAAFDB9776A5557D5E293170482321AE789CF594D219'
        helper_source_sha256='F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1'
        helper_binary_sha256='9D2F0D3A3548E8CD719E741A46AB246B3E2AAF24430554F6EC1370DAD21C5D8F'
        inventory_sha256='12280A1773B53B317BDEC242362B79DC8E9AF44BAC7ECA8555822B5868B63A23'
        process_support_sha256='2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D'
        inventory_support_sha256='25A401E6BE5F57DD16AB7CB5887AD747010581AE15A0997F717419B2B9A6C049'
        schema_evidence_sha256='A061F397D27B26563E6B4C7D611F707F5A3CA4A5B9CBD3353CB2CDC7BA9D7F35'
    }
}
function Get-OnlinePayloads {
    return @(
        @('guest','guest-clone-config-online-qualification.ps1','harness_sha256',1048576),
        @('helper','clone-config-helper.exe','helper_binary_sha256',33554432),
        @('source','clone-config-helper.go','helper_source_sha256',1048576),
        @('build','build.json','build_manifest_sha256',1048576),
        @('helper_build','helper-v3-build.json','helper_build_manifest_sha256',1048576),
        @('inventory','inventory.json','inventory_sha256',2097152),
        @('process_support','negative-process-support.ps1','process_support_sha256',1048576),
        @('inventory_support','inventory-support.ps1','inventory_support_sha256',1048576),
        @('schema','schema-evidence.json','schema_evidence_sha256',4194304)
    )
}
function Assert-OnlineIdentity($Identity) {
    $pins=Get-OnlinePins
    foreach($name in $pins.Keys) {
        if($name -ceq 'build_root') { continue }
        if($Identity.$name -isnot [string] -or $Identity.$name -cne $pins[$name]) { throw 'Online qualification identity differs.' }
    }
    if($Identity.harness_sha256 -isnot [string] -or $Identity.harness_sha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'Online guest digest is missing.' }
}
function Get-OnlineCaseNames {
    return @('missing-group-sdk','missing-group-reference','add-direct-membership','excluded-apps-sdk','excluded-apps-reference','online-sdk-success','online-sdk-existing','online-reference-existing','online-reference-success','remove-direct-membership')
}
function Assert-OnlineMatrixState($Summary) {
    $names=Get-OnlineCaseNames;$cases=@($Summary.cases)
    foreach($name in @('completed','passed','cleanup_complete','staging_preserved','process_uncertain','publication_uncertain','mutation_uncertain','capture_failed')) {
        if($Summary.$name -isnot [bool]) { throw 'Online outcome contains an untyped safety state.' }
    }
    if(-not $Summary.staging_preserved -or $Summary.process_uncertain -or $Summary.publication_uncertain -or $Summary.mutation_uncertain -or $Summary.capture_failed -or
        $null -eq $Summary.cases -or $null -eq $Summary.recovery -or $cases.Count -gt $names.Count -or
        ($Summary.completed -and $cases.Count -ne $names.Count) -or
        (-not $Summary.completed -and ($Summary.passed -or $null -eq $Summary.error)) -or
        ($Summary.passed -and (-not $Summary.completed -or -not $Summary.cleanup_complete -or $null -ne $Summary.error))) { throw 'Online outcome is uncertain or is not a known terminal result.' }
    for($index=0;$index -lt $cases.Count;$index++) {
        $case=$cases[$index];$name=$names[$index]
        $kind=if($name -in @('add-direct-membership','remove-direct-membership')){'membership'}elseif($name -like '*-sdk*'){'sdk'}else{'reference'}
        if($case.name -cne $name -or $case.kind -cne $kind -or $case.passed -isnot [bool] -or ($Summary.passed -and -not $case.passed)) { throw 'Online case sequence or success differs.' }
        $partialLast=(-not $Summary.completed -and $index -eq $cases.Count-1 -and -not $case.passed)
        if((-not $case.passed -and -not $partialLast) -or ($case.passed -and $null -ne $case.error)) { throw 'Online work continued after a failed case or success retains an error.' }
        $process=$case.process
        if($null -eq $process) {
            if(-not $partialLast) { throw 'Completed online case lacks its child record.' }
            continue
        }
        if($process.completed -isnot [bool] -or -not $process.completed -or $process.process_uncertain -isnot [bool] -or $process.process_uncertain -or
            $process.pid -le 0 -or -not $process.started_utc -or $null -eq $process.exit_code -or
            $process.stdout_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $process.stderr_sha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'An online child has uncertain completion or missing raw streams.' }
    }
}
function Assert-OnlineOutcome($Summary,$Identity) {
    Assert-OnlineIdentity $Identity
    if($Summary.schema_version -ne 1 -or $Summary.computer -cne 'ADSDK25DC1') { throw 'Online outcome schema or computer differs.' }
    foreach($name in @('run','source_commit','source_archive_sha256','build_manifest_sha256','helper_build_manifest_sha256','helper_source_sha256','helper_binary_sha256','harness_sha256','inventory_sha256','process_support_sha256','inventory_support_sha256','schema_evidence_sha256')) {
        if($Summary.$name -isnot [string] -or $Summary.$name -cne $Identity.$name) { throw 'Online outcome provenance differs.' }
    }
    Assert-OnlineMatrixState $Summary
}

function Assert-OnlineBuild($Paths,$Identity) {
    Assert-OnlineIdentity $Identity
    $pins=Get-OnlinePins
    $expected=[ordered]@{
        guest=(Join-Path $PSScriptRoot 'guest-clone-config-online-qualification.ps1')
        helper=(Join-Path $pins.build_root 'helper-v3\clone-config-helper.exe')
        source=(Join-Path $pins.build_root 'helper-v3\clone-config-helper.go')
        build=(Join-Path $pins.build_root 'build.json')
        helper_build=(Join-Path $pins.build_root 'helper-v3\build.json')
        inventory=(Join-Path $pins.build_root 'server2025-online-inventory-v1\inventory.json')
        process_support=(Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1')
        inventory_support=(Join-Path $PSScriptRoot 'get-clone-config-online-prerequisites.ps1')
        schema=(Join-Path $pins.build_root 'source\docs\research\dc-cloning-evidence\server2025-readonly.json')
    }
    foreach($item in Get-OnlinePayloads) {
        $path=Assert-UnlinkedPath $Paths[$item[0]]
        if($path -cne $expected[$item[0]] -or (Get-Item -LiteralPath $path).Length -gt $item[3] -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $Identity.($item[2])) { throw 'Online source path, size, or digest differs.' }
    }
    $build=Get-Content -LiteralPath $Paths.build -Raw | ConvertFrom-Json
    $helper=Get-Content -LiteralPath $Paths.helper_build -Raw | ConvertFrom-Json
    if($build.source_commit -cne $pins.source_commit -or $build.source_archive_sha256 -cne $pins.source_archive_sha256 -or
        $build.directory -cne $pins.build_root -or $build.status -cne 'built' -or
        $helper.source_commit -cne $pins.source_commit -or $helper.source_archive_sha256 -cne $pins.source_archive_sha256 -or
        $helper.directory -cne (Join-Path $pins.build_root 'helper-v3') -or $helper.helper_executable_sha256 -cne $pins.helper_binary_sha256) { throw 'Frozen online build provenance differs.' }
    $archive=Assert-UnlinkedPath (Join-Path $pins.build_root 'source.zip')
    if($build.source_archive -cne $archive -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -cne $pins.source_archive_sha256) { throw 'Frozen source archive differs.' }
    $inventory=Get-Content -LiteralPath $Paths.inventory -Raw | ConvertFrom-Json
    if($inventory.completed -isnot [bool] -or -not $inventory.completed -or $inventory.readonly -isnot [bool] -or -not $inventory.readonly -or
        $inventory.computer -cne 'ADSDK25DC1' -or $null -ne $inventory.error -or @($inventory.applications.reference_entries).Count -ne 28) { throw 'Pinned prerequisite inventory is incomplete.' }
}
function Read-OnlineOutcome($Payload,$Identity) {
    try {
        $values=@($Payload | ConvertFrom-Json -ErrorAction Stop)
        if($values.Count -ne 1) { throw 'Online guest outcome cardinality differs.' }
        Assert-OnlineOutcome $values[0] $Identity
        return $values[0]
    } catch { $script:guestUncertain=$true;throw }
}
function Test-OnlineEvidenceName([string]$Name) {
    if($Name -cin @('owner.txt','online-cases/owner.txt','online-cases/started.json','online-cases/summary.json','online-cases/inclusion.xml')) { return $true }
    if($Name -cmatch '^online-cases/(events|snapshots)/[0-9]{4}-[a-z0-9-]+\.json$') { return $true }
    $parts=$Name.Split('/')
    if($parts.Count -lt 3 -or $parts[0] -cne 'online-cases' -or $parts[1] -cnotin (Get-OnlineCaseNames)) { return $false }
    $suffix=$parts[2..($parts.Count-1)] -join '/'
    return $suffix -cmatch '^(case\.json|options\.json|child\.(requested|started|finished)\.json|child\.(stdout|stderr)\.txt|result\.json|reference\.json|reference\.streams\.txt|membership\.json|output\.xml|output/DCCloneConfig\.xml)$'
}
function Save-OnlineCapture($Payload,$Outcome,$Identity) {
    $values=@($Payload | ConvertFrom-Json -ErrorAction Stop)
    if($values.Count -ne 1 -or $values[0].run -cne $Identity.run) { throw 'Online capture identity differs.' }
    $files=@($values[0].files)
    if($files.Count -lt 4 -or $files.Count -gt 512) { throw 'Online capture file count is outside its bound.' }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
    foreach($file in $files) {
        if($file.name -isnot [string] -or -not (Test-OnlineEvidenceName $file.name) -or -not $seen.Add($file.name) -or
            $file.sha256 -cnotmatch '^[A-F0-9]{64}$' -or $file.length -lt 0 -or $file.length -gt 2097152 -or
            $file.bytes_base64.Length -gt 2796204) { throw 'Online raw file identity or size differs.' }
        $bytes=[Convert]::FromBase64String($file.bytes_base64);$total+=$bytes.Length
        if($bytes.Length -ne $file.length -or $total -gt 33554432) { throw 'Online capture byte bound exceeded.' }
        $hasher=[Security.Cryptography.SHA256]::Create()
        try { $hash=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','') } finally { $hasher.Dispose() }
        if($hash -cne $file.sha256) { throw 'Online raw evidence digest differs.' }
        $rawRoot=Join-Path $resultRoot 'raw'
        $destination=Assert-UnlinkedPath (Join-Path $rawRoot ($file.name.Replace('/','\')))
        if(-not $destination.StartsWith($rawRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Online raw path escaped evidence.' }
        $parent=Assert-UnlinkedPath ([IO.Path]::GetDirectoryName($destination));[void][IO.Directory]::CreateDirectory($parent)
        Write-NewHostBytes $destination $bytes
        $runState.captures[$file.name]=$hash
    }
    foreach($name in @('owner.txt','online-cases/owner.txt','online-cases/started.json','online-cases/summary.json')) {
        if(-not $seen.Contains($name)) { throw 'Required online recovery evidence is missing.' }
    }
    foreach($name in @('owner.txt','online-cases/owner.txt')) {
        if([IO.File]::ReadAllText((Join-Path $rawRoot $name)) -cne $Identity.run) { throw 'Captured online owner differs.' }
    }
    $summary=Get-Content -LiteralPath (Join-Path $rawRoot 'online-cases/summary.json') -Raw | ConvertFrom-Json
    Assert-OnlineOutcome $summary $Identity
    if(($summary | ConvertTo-Json -Depth 40 -Compress) -cne ($Outcome | ConvertTo-Json -Depth 40 -Compress)) { throw 'Captured online summary differs from returned outcome.' }
    $reported=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($case in $Outcome.cases) {
        $null=$reported.Add($case.name);$prefix='online-cases/'+$case.name+'/'
        if(-not $seen.Contains($prefix+'case.json')) { throw 'Online case definition is missing.' }
        foreach($suffix in @('.requested.json','.started.json','.finished.json','.stdout.txt','.stderr.txt')) {
            if(($null -ne $case.process) -ne $seen.Contains($prefix+'child'+$suffix)) { throw 'Raw online child attempt differs from summary.' }
        }
        if($null -ne $case.process) {
            if($case.process.stdout_sha256 -cne $runState.captures[$prefix+'child.stdout.txt'] -or
                $case.process.stderr_sha256 -cne $runState.captures[$prefix+'child.stderr.txt']) { throw 'Online child streams differ from completion evidence.' }
            $finished=Get-Content -LiteralPath (Join-Path $rawRoot ($prefix+'child.finished.json')) -Raw | ConvertFrom-Json
            if(($finished | ConvertTo-Json -Depth 40 -Compress) -cne ($case.process | ConvertTo-Json -Depth 40 -Compress)) { throw 'Online child completion differs from its summary.' }
            if($case.kind -ceq 'sdk' -and -not $seen.Contains($prefix+'options.json')) { throw 'Online SDK options are missing.' }
        }
        if($null -ne $case.observation -and $case.kind -cne 'sdk') {
            $observedName=if($case.kind -ceq 'reference'){'reference.json'}else{'membership.json'}
            if(-not $seen.Contains($prefix+$observedName)) { throw 'Raw online child observation is missing.' }
            $observed=Get-Content -LiteralPath (Join-Path $rawRoot ($prefix+$observedName)) -Raw | ConvertFrom-Json
            if(($observed | ConvertTo-Json -Depth 40 -Compress) -cne ($case.observation | ConvertTo-Json -Depth 40 -Compress)) { throw 'Raw online child observation differs from summary.' }
            if($case.kind -ceq 'reference' -and (-not $seen.Contains($prefix+'reference.streams.txt') -or $case.observation.streams_sha256 -cne $runState.captures[$prefix+'reference.streams.txt'])) { throw 'Raw reference diagnostics are missing or differ.' }
        }
        if($null -ne $case.output_after -and $case.output_after.exists) {
            if(-not $seen.Contains($prefix+'output.xml') -or $case.output_after.sha256 -cne $runState.captures[$prefix+'output.xml']) { throw 'Published online XML evidence is missing or differs.' }
        }
        if($seen.Contains($prefix+'result.json')) {
            $result=Get-Content -LiteralPath (Join-Path $rawRoot ($prefix+'result.json')) -Raw | ConvertFrom-Json
            if(($result | ConvertTo-Json -Depth 40 -Compress) -cne ($case | ConvertTo-Json -Depth 40 -Compress)) { throw 'Online case result differs from summary.' }
        } elseif($Outcome.completed -or $case.name -cne $Outcome.cases[-1].name) { throw 'Completed online case result is missing.' }
    }
    foreach($name in Get-OnlineCaseNames) {
        if($reported.Contains($name)) { continue }
        foreach($suffix in @('.requested.json','.started.json','.finished.json','.stdout.txt','.stderr.txt')) {
            if($seen.Contains('online-cases/'+$name+'/child'+$suffix)) { throw 'Unreported online child evidence was captured.' }
        }
    }
    Write-NewHostJson (Join-Path $resultRoot 'captured-evidence.json') $runState.captures
}

$pins=Get-OnlinePins
$profile='H:\ad-sdk-lab\server2025';$operationMutex=$null;$mutexHeld=$false;$runState=$null
try {
    $operationMutex=[Threading.Mutex]::new($false,(Get-ProfileMutexName $profile))
    try { $mutexHeld=$operationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld=$true }
    if(-not $mutexHeld) { throw 'Another lab action owns this profile.' }
    $identity=[ordered]@{};foreach($name in $pins.Keys) { if($name -cne 'build_root') { $identity[$name]=$pins[$name] } }
    $identity.harness_sha256=$ExpectedGuestScriptSHA256
    $paths=[ordered]@{
        guest=(Join-Path $PSScriptRoot 'guest-clone-config-online-qualification.ps1')
        helper=(Join-Path $pins.build_root 'helper-v3\clone-config-helper.exe')
        source=(Join-Path $pins.build_root 'helper-v3\clone-config-helper.go')
        build=(Join-Path $pins.build_root 'build.json')
        helper_build=(Join-Path $pins.build_root 'helper-v3\build.json')
        inventory=(Join-Path $pins.build_root 'server2025-online-inventory-v1\inventory.json')
        process_support=(Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1')
        inventory_support=(Join-Path $PSScriptRoot 'get-clone-config-online-prerequisites.ps1')
        schema=(Join-Path $pins.build_root 'source\docs\research\dc-cloning-evidence\server2025-readonly.json')
    }
    Assert-OnlineBuild $paths $identity
    $bootstrap=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'bootstrap-clone-config-online-qualification.ps1')
    if((Get-FileHash -LiteralPath $bootstrap -Algorithm SHA256).Hash -cne $ExpectedBootstrapSHA256) { throw 'Reviewed online bootstrap differs.' }
    $statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml'
    foreach($path in @($statePath,$credentialPath)) { $null=Assert-UnlinkedPath $path }
    $stateHash=(Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash
    $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Import-Module Hyper-V -ErrorAction Stop
    Assert-OwnedControllers
    $machine=@($state.machines | Where-Object role -ceq 'dc1')[0]
    $executionID=$identity.run;$target=Join-Path 'C:\ad-sdk-validation' $executionID
    $resultRoot=Assert-NewRunDirectory (Join-Path $pins.build_root 'server2025-online-qualification-v1')
    [void][IO.Directory]::CreateDirectory($resultRoot)
    $runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'run-journal.json';$script:guestUncertain=$false
    $runState=[ordered]@{schema_version=1;owner=$runOwner;execution_id=$executionID;phase='prepared';terminal=$false;guest_staging=$target;guest_uncertain=$false;jobs=@();captures=[ordered]@{};passed=$false;cleanup_complete=$false;error=$null;updated=$null;lab_id=$state.id;vm_id=$machine.id;identity=$identity;bootstrap_sha256=$ExpectedBootstrapSHA256;host_script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;staging_preserved=$true}
    Write-RunState
    $snapshot=Join-Path $resultRoot 'bootstrap-clone-config-online-qualification.ps1'
    Write-NewHostBytes $snapshot ([IO.File]::ReadAllBytes($bootstrap))
    Write-NewHostBytes (Join-Path $resultRoot 'run-clone-config-online-qualification.ps1') ([IO.File]::ReadAllBytes($PSCommandPath))
    $payload=[ordered]@{};foreach($name in $identity.Keys) { $payload[$name]=$identity[$name] }
    foreach($item in Get-OnlinePayloads) {
        $bytes=[IO.File]::ReadAllBytes($paths[$item[0]])
        $payload[$item[0]]=[Convert]::ToBase64String($bytes)
        if($item[0] -cne 'helper') { Write-NewHostBytes (Join-Path $resultRoot $item[1]) $bytes }
    }
    Assert-OnlineBuild $paths $identity
    $saved=Import-Clixml -LiteralPath $credentialPath;$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedBootstrapSHA256) { throw 'Online bootstrap snapshot differs.' }
    $null=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Stage',$target,$executionID,($payload|ConvertTo-Json -Depth 8 -Compress),$ProcessTimeoutSeconds,$ReplicationTimeoutSeconds) -TimeoutSeconds 60 -Action 'stage'
    $identityJson=$identity|ConvertTo-Json -Compress
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedBootstrapSHA256) { throw 'Online bootstrap changed before run.' }
    $returned=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Run',$target,$executionID,$identityJson,$ProcessTimeoutSeconds,$ReplicationTimeoutSeconds) -TimeoutSeconds $RunTimeoutSeconds -Action 'online-qualification'
    Write-NewHostJson (Join-Path $resultRoot 'guest-return.json') ([ordered]@{payload=@($returned)})
    $outcome=Read-OnlineOutcome $returned $identity
    $runState.phase='known-online-result';$runState.cleanup_complete=$outcome.cleanup_complete;Write-RunState
    if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash -cne $ExpectedBootstrapSHA256) { throw 'Online bootstrap changed before capture.' }
    $captured=Invoke-OwnedGuest -FilePath $snapshot -Arguments @('Capture',$target,$executionID,$identityJson,$ProcessTimeoutSeconds,$ReplicationTimeoutSeconds) -TimeoutSeconds $CaptureTimeoutSeconds -Action 'capture'
    Write-NewHostJson (Join-Path $resultRoot 'capture-return.json') ([ordered]@{payload=@($captured)})
    Save-OnlineCapture $captured $outcome $identity
    $runState.passed=[bool]$outcome.passed
    if(-not $runState.passed) { throw 'Online qualification failed; recovery evidence and all guest staging are preserved.' }
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
[pscustomobject]@{directory=$resultRoot;passed=$runState.passed;cleanup_complete=$runState.cleanup_complete;staging_preserved=$true}|ConvertTo-Json

