#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('New', 'Configure', 'ConfigureLDS', 'TestLDS', 'TestLDSTLS', 'Reference', 'TestConditions', 'TestConnection', 'TestCredentials', 'TestSearch', 'TestLDSSearch', 'Status', 'Stop', 'Remove')][string]$Action,
    [ValidateSet('2016', '2019', '2022', '2025')][string]$ServerVersion = '2025',
    [string]$StorageRoot = 'H:\ad-sdk-lab',
    [string]$IsoPath,
    [ValidateRange(1, 20)][int]$ImageIndex = 1
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V
$labRoot = [IO.Path]::GetFullPath((Join-Path $StorageRoot "server$ServerVersion"))
$statePath = Join-Path $labRoot 'state.json'
$secretPath = Join-Path $labRoot 'credential.clixml'
$script:state = $null
$operationMutex = $null
$mutexHeld = $false

function Assert-LabPath([string]$Path) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($labRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the lab directory: $resolved"
    }
    $parent = $resolved
    while ($parent) {
        if ((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Reparse point is not allowed in a lab path: $parent"
        }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    return $resolved
}

function Write-LabLog([string]$Message) {
    $line = '{0} {1}' -f [DateTime]::UtcNow.ToString('o'), $Message
    Write-Host $line
    Add-Content -LiteralPath (Join-Path $labRoot 'events.log') -Value $line
}

function Save-State {
    $temporary = Assert-LabPath (Join-Path $labRoot 'state.tmp')
    $script:state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $statePath -Force
}

function Get-OwnedSwitch($State) {
    if (-not $State.switch_id) { throw 'The lab switch has not been created.' }
    $switch = Get-VMSwitch -Id ([guid]$State.switch_id)
    if ($switch.Name -ne $State.switch_name -or $switch.Notes -ne "ad-sdk-lab:$($State.id)" -or $switch.SwitchType -ne 'Private') {
        throw 'Lab switch ownership/isolation mismatch.'
    }
    return $switch
}

function Get-OwnedVM($Machine, $State) {
    $null = Get-OwnedSwitch $State
    if (-not $Machine.id) { throw "VM has not been created: $($Machine.name)" }
    $vm = Get-VM -Id ([guid]$Machine.id)
    if ($vm.Name -ne $Machine.name -or $vm.Notes -ne "ad-sdk-lab:$($State.id)") {
        throw "VM ownership does not match the manifest: $($Machine.name)"
    }
    $null = Assert-LabPath $vm.Path
    foreach ($disk in @(Get-VMHardDiskDrive -VM $vm)) { $null = Assert-LabPath $disk.Path }
    $adapters = @(Get-VMNetworkAdapter -VM $vm)
    if ($adapters.Count -ne 1 -or $adapters[0].SwitchId.ToString() -ne $State.switch_id) {
        throw "VM network is not the expected private lab switch: $($Machine.name)"
    }
    return $vm
}

function Assert-LabSwitchUnused($Switch) {
    $switchId = [guid]$Switch.Id
    $instances = @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_VirtualEthernetSwitch -Filter "Name='$switchId'" -ErrorAction Stop)
    if ($instances.Count -ne 1 -or [guid]$instances[0].Name -ne $switchId) {
        throw 'Unable to verify the lab switch through Hyper-V CIM.'
    }
    $ports = @(Get-CimAssociatedInstance -InputObject $instances[0] -Association Msvm_SystemDevice -ResultClassName Msvm_EthernetSwitchPort -ErrorAction Stop)
    if ($ports.Count) { throw 'An adapter outside the removed lab VMs still uses this switch.' }
    # Configured connections also protect stopped VMs, whose live switch ports
    # may not exist. Avoid Get-VMNetworkAdapter -All: an unrelated VM can make
    # host-wide Hyper-V object enumeration fail before it reaches this switch.
    $connections = @(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_EthernetPortAllocationSettingData -ErrorAction Stop)
    foreach ($connection in $connections) {
        foreach ($resource in @($connection.HostResource)) {
            if ([string]::IsNullOrWhiteSpace($resource)) { continue }
            $path = [Management.ManagementPath]::new($resource)
            if ($path.ClassName -ne 'Msvm_VirtualEthernetSwitch') { continue }
            $referencedId = [guid]::Empty
            if ($path.RelativePath -notmatch '(?:\.|,)\s*Name\s*=\s*"([^"]+)"' -or
                -not [guid]::TryParse($Matches[1], [ref]$referencedId)) {
                throw 'Invalid switch reference in a configured Hyper-V connection.'
            }
            if ($referencedId -eq $switchId) { throw 'An adapter outside the removed lab VMs still uses this switch.' }
        }
    }
}

function Get-LabCredential([string]$UserName = 'Administrator') {
    $saved = Import-Clixml -LiteralPath $secretPath
    return [PSCredential]::new($UserName, $saved.Password)
}

function Initialize-Lab {
    if (Test-Path -LiteralPath $statePath) { return }
    if (Test-Path -LiteralPath $labRoot) { throw "Refusing to adopt an existing directory without a lab manifest: $labRoot" }
    $null = Assert-LabPath $statePath
    $null = New-Item -ItemType Directory -Path $labRoot
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $labRoot -AclObject $acl
    $shortVersion = $ServerVersion.Substring(2)
    $script:state = [pscustomobject]@{
        schema_version = 1; id = [guid]::NewGuid().ToString(); root = $labRoot; server_version = $ServerVersion
        domain = 'ad.sdk.test'; netbios = 'ADSDK'; switch_name = "ad-sdk-$ServerVersion"; switch_id = ''
        base_ready = $false; image = $null; configured = $false
        machines = @(
            [pscustomobject]@{name="ADSDK${shortVersion}DC1"; role='dc1'; ip='10.77.23.10'; id=''},
            [pscustomobject]@{name="ADSDK${shortVersion}DC2"; role='dc2'; ip='10.77.23.11'; id=''},
            [pscustomobject]@{name="ADSDK${shortVersion}MEM"; role='member'; ip='10.77.23.20'; id=''}
        )
    }
    $random = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $password = 'Aa9!' + [BitConverter]::ToString($random).Replace('-', '')
    [PSCredential]::new('Administrator', (ConvertTo-SecureString $password -AsPlainText -Force)) | Export-Clixml -LiteralPath $secretPath
    $password = $null
    Save-State
}

function New-BaseDisk {
    if ($script:state.base_ready) { return }
    $basePath = Assert-LabPath (Join-Path $labRoot 'base.vhdx')
    if (Test-Path -LiteralPath $basePath) { throw "Incomplete base disk exists; inspect it before retrying: $basePath" }
    if (-not $IsoPath) { $script:IsoPath = Join-Path $StorageRoot "isos\WindowsServer$ServerVersion-en-us.iso" }
    $iso = Get-DiskImage -ImagePath ([IO.Path]::GetFullPath($IsoPath))
    $wasAttached = $iso.Attached
    try {
        if (-not $wasAttached) { $iso = Mount-DiskImage -ImagePath $iso.ImagePath -PassThru }
        $volume = $iso | Get-Volume
        $wim = '{0}:\sources\install.wim' -f $volume.DriveLetter
        $selected = Get-WindowsImage -ImagePath $wim -Index $ImageIndex
        if ($selected.ImageName -notlike "Windows Server $ServerVersion *" -or $selected.Architecture -ne 9) {
            throw 'The selected image must be an amd64 Windows Server image matching the profile.'
        }
        $script:state.image = [pscustomobject]@{
            iso=$iso.ImagePath; sha256=(Get-FileHash -LiteralPath $iso.ImagePath -Algorithm SHA256).Hash
            index=$ImageIndex; name=$selected.ImageName; version=$selected.Version.ToString()
        }
        Save-State
        Write-LabLog "Applying $($selected.ImageName) to a new base disk."
        $null = New-VHD -Path $basePath -Dynamic -SizeBytes 64GB
        $disk = Mount-VHD -Path $basePath -Passthru | Get-Disk
        try {
            if ($disk.PartitionStyle -ne 'RAW' -or $disk.IsBoot -or $disk.IsSystem) { throw 'The new virtual disk failed safety checks.' }
            $null = Initialize-Disk -Number $disk.Number -PartitionStyle GPT
            $esp = New-Partition -DiskNumber $disk.Number -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -AssignDriveLetter
            $null = Format-Volume -Partition $esp -FileSystem FAT32 -NewFileSystemLabel 'ADSDK-EFI' -Confirm:$false
            $null = New-Partition -DiskNumber $disk.Number -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
            $os = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
            $null = Format-Volume -Partition $os -FileSystem NTFS -NewFileSystemLabel 'ADSDK-OS' -Confirm:$false
            $applyPath = '{0}:\' -f $os.DriveLetter
            $scratch = Join-Path $labRoot 'scratch'
            $null = New-Item -ItemType Directory -Path $scratch -Force
            $null = Expand-WindowsImage -ImagePath $wim -Index $ImageIndex -ApplyPath $applyPath -ScratchDirectory $scratch -LogPath (Join-Path $labRoot 'dism.log')
            # /s targets ONLY this VHDX's EFI partition and avoids host NVRAM changes.
            & bcdboot.exe (Join-Path $applyPath 'Windows') /s ('{0}:' -f $esp.DriveLetter) /f UEFI | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "BCDBoot failed: $LASTEXITCODE" }
        } finally { Dismount-VHD -Path $basePath }
        $script:state.base_ready = $true
        Save-State
        Write-LabLog 'Base disk is ready.'
    } finally { if (-not $wasAttached) { Dismount-DiskImage -ImagePath $iso.ImagePath | Out-Null } }
}

function New-LabMachines {
    if (-not $script:state.switch_id) {
        if (Get-VMSwitch -Name $script:state.switch_name -ErrorAction SilentlyContinue) { throw 'An unowned switch already uses the lab switch name.' }
        $switch = New-VMSwitch -Name $script:state.switch_name -SwitchType Private -Notes "ad-sdk-lab:$($script:state.id)"
        $script:state.switch_id = $switch.Id.ToString()
        Save-State
        Set-VMSwitch -VMSwitch $switch -Notes "ad-sdk-lab:$($script:state.id)"
    }
    $switch = Get-OwnedSwitch $script:state
    foreach ($machine in $script:state.machines) {
        if ($machine.id) { $null = Get-OwnedVM $machine $script:state; continue }
        $existing = Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter "ElementName='$($machine.name)'"
        if ($existing) { throw "An unowned VM already uses the name $($machine.name)." }
        $vmRoot = Assert-LabPath (Join-Path $labRoot $machine.name)
        if (Test-Path -LiteralPath $vmRoot) { throw "Incomplete VM directory exists: $vmRoot" }
        $null = New-Item -ItemType Directory -Path $vmRoot
        $diskPath = Join-Path $vmRoot 'os.vhdx'
        $null = New-VHD -Path $diskPath -ParentPath (Join-Path $labRoot 'base.vhdx') -Differencing
        $disk = Mount-VHD -Path $diskPath -PassThru | Get-Disk
        try {
            $os = Get-Partition -DiskNumber $disk.Number | Where-Object Type -eq 'Basic'
            if (@($os).Count -ne 1) { throw 'Expected exactly one Windows partition in the child disk.' }
            if (-not $os.DriveLetter) { $os | Add-PartitionAccessPath -AssignDriveLetter; $os = Get-Partition -DiskNumber $disk.Number -PartitionNumber $os.PartitionNumber }
            $panther = '{0}:\Windows\Panther' -f $os.DriveLetter
            $null = New-Item -ItemType Directory -Path $panther -Force
            $credential = Get-LabCredential
            $passwordXML = [Security.SecurityElement]::Escape($credential.GetNetworkCredential().Password)
            $template = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'unattend.xml') -Raw
            $answer = $template.Replace('__COMPUTER_NAME__', $machine.name).Replace('__ADMIN_PASSWORD__', $passwordXML)
            [xml]$null = $answer
            [IO.File]::WriteAllText((Join-Path $panther 'Unattend.xml'), $answer, [Text.UTF8Encoding]::new($false))
            $answer = $passwordXML = $null
        } finally { Dismount-VHD -Path $diskPath }
        $vm = New-VM -Name $machine.name -Generation 2 -MemoryStartupBytes 4GB -VHDPath $diskPath -Path $vmRoot -SwitchName $switch.Name
        $machine.id = $vm.Id.ToString()
        Set-VM -VM $vm -Notes "ad-sdk-lab:$($script:state.id)" -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -CheckpointType Disabled
        Save-State
        Set-VMProcessor -VM $vm -Count 2
        Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
        Start-VM -VM $vm
        Write-LabLog "Started $($machine.name) on the private lab switch."
    }
}

try {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $lockName = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($labRoot.ToLowerInvariant()))).Replace('-', '') } finally { $hasher.Dispose() }
    $operationMutex = [Threading.Mutex]::new($false, "Global\GoSDKActiveDirectoryLab_$lockName")
    try { $mutexHeld = $operationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld = $true }
    if (-not $mutexHeld) { throw 'Another lab action is running for this profile.' }
    if ($Action -eq 'New') { Initialize-Lab }
    if (-not (Test-Path -LiteralPath $statePath)) { throw 'Create the lab with -Action New first.' }
    $null = Assert-LabPath $statePath
    $script:state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($script:state.schema_version -ne 1 -or $script:state.root -ne $labRoot -or $script:state.server_version -ne $ServerVersion) { throw 'Lab manifest does not match this profile.' }
    Write-LabLog "Starting action $Action."
    [ordered]@{ok=$null; status='running'; action=$Action; process_id=$PID; time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'last-run.json') -Encoding UTF8
    switch ($Action) {
        'New' { New-BaseDisk; New-LabMachines }
        'Configure' { & (Join-Path $PSScriptRoot 'configure.ps1') -LabState $script:state -Credential (Get-LabCredential) -LabRoot $labRoot; $script:state.configured = $true; Save-State }
        'ConfigureLDS' { & (Join-Path $PSScriptRoot 'configure-lds.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot }
        'TestLDS' { & (Join-Path $PSScriptRoot 'test-lds.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot }
        'TestLDSTLS' { & (Join-Path $PSScriptRoot 'test-lds-tls.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot }
        'Reference' { & (Join-Path $PSScriptRoot 'reference.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot }
        'TestConditions' { & (Join-Path $PSScriptRoot 'test-conditions.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot }
        'TestConnection' { & (Join-Path $PSScriptRoot 'test-connection.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot }
        'TestCredentials' { & (Join-Path $PSScriptRoot 'test-credentials.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot }
        'TestSearch' { & (Join-Path $PSScriptRoot 'test-search.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot }
        'TestLDSSearch' { & (Join-Path $PSScriptRoot 'test-search.ps1') -LabState $script:state -Credential (Get-LabCredential "$($script:state.netbios)\Administrator") -LabRoot $labRoot -LDS }
        'Status' { foreach ($machine in $script:state.machines) { Get-OwnedVM $machine $script:state | Select-Object Name, Id, State, Uptime } }
        'Stop' { foreach ($machine in $script:state.machines) { Get-OwnedVM $machine $script:state | Stop-VM } }
        'Remove' {
            foreach ($machine in $script:state.machines) {
                if (-not $machine.id) { continue }
                $vm = Get-OwnedVM $machine $script:state
                if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
                Remove-VM -VM $vm -Force
                $machine.id = ''
                Save-State
            }
            if ($script:state.switch_id) {
                $switch = Get-OwnedSwitch $script:state
                Assert-LabSwitchUnused $switch
                Remove-VMSwitch -VMSwitch $switch -Force
                $script:state.switch_id = ''
                Save-State
            }
            foreach ($item in @(Get-ChildItem -LiteralPath $labRoot -Force -Recurse)) {
                $null = Assert-LabPath $item.FullName
            }
            # The fixed profile directory is checked before recursive deletion.
            if ([IO.Path]::GetFileName($labRoot) -ne "server$ServerVersion") { throw 'Unexpected removal target.' }
            $null = Assert-LabPath $statePath
            Remove-Item -LiteralPath $labRoot -Recurse -Force
            return
        }
    }
    Write-LabLog "Completed action $Action."
    [ordered]@{ok=$true; status='passed'; action=$Action; time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'last-run.json') -Encoding UTF8
} catch {
    if ($mutexHeld -and (Test-Path -LiteralPath $labRoot)) {
        [ordered]@{ok=$false; status='failed'; action=$Action; error=$_.Exception.Message; line=$_.InvocationInfo.ScriptLineNumber; time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $labRoot 'last-run.json') -Encoding UTF8
    }
    throw
} finally {
    if ($mutexHeld) { $operationMutex.ReleaseMutex() }
    if ($operationMutex) { $operationMutex.Dispose() }
}
