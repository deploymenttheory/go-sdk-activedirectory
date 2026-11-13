#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState, [Parameter(Mandatory)][PSCredential]$Credential, [Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
$domainCredential = [PSCredential]::new("$($LabState.netbios)\Administrator", $Credential.Password)
$dc1 = $LabState.machines | Where-Object role -eq 'dc1'
$dc2 = $LabState.machines | Where-Object role -eq 'dc2'
$member = $LabState.machines | Where-Object role -eq 'member'

foreach ($machine in $LabState.machines) {
    $vm = Get-OwnedVM $machine $LabState
    if ($vm.State -eq 'Off') { Start-VM -VM $vm }
    Write-LabLog "Waiting for initial setup on $($machine.name)."
    $session = Wait-LabGuest $machine @($Credential, $domainCredential)
    try {
        $restartNeeded = Invoke-Command -Session $session -ArgumentList $machine.name, $machine.ip, $machine.role, $LabState.domain -ScriptBlock {
            param($ExpectedName, $Address, $Role, $Domain)
            $ErrorActionPreference = 'Stop'
            $computer = Get-CimInstance Win32_ComputerSystem
            if ($computer.Name -ne $ExpectedName) { throw "Guest name does not match: $($computer.Name)" }
            if ($computer.PartOfDomain -and $computer.Domain -ne $Domain) { throw 'Guest belongs to an unexpected domain.' }
            $adapter = @(Get-NetAdapter | Where-Object Status -eq 'Up')
            if ($adapter.Count -ne 1) { throw 'Expected exactly one connected lab network adapter.' }
            Set-NetIPInterface -InterfaceIndex $adapter[0].ifIndex -AddressFamily IPv4 -Dhcp Disabled
            if (-not (Get-NetIPAddress -InterfaceIndex $adapter[0].ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -eq $Address)) {
                Get-NetIPAddress -InterfaceIndex $adapter[0].ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
                $null = New-NetIPAddress -InterfaceIndex $adapter[0].ifIndex -IPAddress $Address -PrefixLength 24
            }
            Set-DnsClientServerAddress -InterfaceIndex $adapter[0].ifIndex -ServerAddresses @('10.77.23.10', '10.77.23.11')
            $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '0'
            Set-ItemProperty -LiteralPath $winlogon -Name AutoLogonCount -Value 0
            Remove-ItemProperty -LiteralPath $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath 'C:\Windows\Panther\Unattend.xml' -Force -ErrorAction SilentlyContinue
            $features = @('RSAT-AD-PowerShell')
            if ($Role -ne 'member') { $features += 'AD-Domain-Services' }
            $installed = Install-WindowsFeature -Name $features -IncludeManagementTools
            if (-not $installed.Success) { throw 'Windows feature installation failed.' }
            return $installed.RestartNeeded -eq 'Yes'
        }
        if ($restartNeeded) { $session = Restart-LabGuest $machine $session $Credential }
    } finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
}

Write-LabLog "Creating or checking forest $($LabState.domain)."
$session = Wait-LabGuest $dc1 @($Credential, $domainCredential)
try {
    $promoted = Invoke-Command -Session $session -ArgumentList $LabState.domain, $LabState.netbios, $Credential.Password -ScriptBlock {
        param($Domain, $Netbios, $DsrmPassword)
        $ErrorActionPreference = 'Stop'
        if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { return $false }
        Import-Module ADDSDeployment
        $result = Install-ADDSForest -DomainName $Domain -DomainNetbiosName $Netbios -DomainMode WinThreshold -ForestMode WinThreshold -InstallDns -CreateDnsDelegation:$false -SafeModeAdministratorPassword $DsrmPassword -NoRebootOnCompletion -Force
        if ($result.Status -ne 'Success') { throw "Forest promotion failed: $($result.Status)" }
        return $true
    }
    if ($promoted) { $session = Restart-LabGuest $dc1 $session $domainCredential }
} finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
$session = Wait-LabDirectory $dc1 $domainCredential
Remove-PSSession $session
Write-LabLog 'First domain controller is ready.'

Write-LabLog 'Promoting the second writable domain controller.'
$session = Wait-LabGuest $dc2 @($Credential, $domainCredential)
try {
    Wait-LabDomainDiscovery $session $LabState.domain
    $promoted = Invoke-Command -Session $session -ArgumentList $LabState.domain, $domainCredential, $Credential.Password, $dc1.name -ScriptBlock {
        param($Domain, $DomainCredential, $DsrmPassword, $Source)
        $ErrorActionPreference = 'Stop'
        if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { return $false }
        Import-Module ADDSDeployment
        $result = Install-ADDSDomainController -DomainName $Domain -Credential $DomainCredential -ReplicationSourceDC "$Source.$Domain" -InstallDns -CreateDnsDelegation:$false -SafeModeAdministratorPassword $DsrmPassword -NoRebootOnCompletion -Force
        if ($result.Status -ne 'Success') { throw "DC promotion failed: $($result.Status)" }
        return $true
    }
    if ($promoted) { $session = Restart-LabGuest $dc2 $session $domainCredential }
} finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
$session = Wait-LabDirectory $dc2 $domainCredential
Invoke-Command -Session $session -ScriptBlock {
    $adapter = Get-NetAdapter | Where-Object Status -eq 'Up'
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @('10.77.23.11', '10.77.23.10')
}
Remove-PSSession $session
Write-LabLog 'Second domain controller is ready.'

Write-LabLog 'Joining the member server to the domain.'
$localMemberCredential = [PSCredential]::new("$($member.name)\Administrator", $Credential.Password)
$session = Wait-LabGuest $member $localMemberCredential
try {
    Wait-LabDomainDiscovery $session $LabState.domain
    $joined = Invoke-Command -Session $session -ArgumentList $LabState.domain, $domainCredential -ScriptBlock {
        param($Domain, $DomainCredential)
        $ErrorActionPreference = 'Stop'
        if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { return $false }
        Add-Computer -DomainName $Domain -Credential $DomainCredential -Force
        return $true
    }
    if ($joined) { $session = Restart-LabGuest $member $session $localMemberCredential }
    Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        if (-not (Test-ComputerSecureChannel)) { throw 'Member server secure channel validation failed.' }
    }
} finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
Write-LabLog 'Two writable domain controllers and the domain member are configured.'

# Delegated managed service accounts need two prerequisites that the base
# topology does not otherwise create: an effective KDS root key, and the client
# Kerberos opt-in on the member. Both are idempotent.
Write-LabLog 'Preparing delegated managed service account prerequisites.'
# The consuming reference runner gates on the raw key attributes, not on
# Get-KdsRootKey's EffectiveTime: a key counts only once msKds-CreateTime is at
# least ten hours old and msKds-UseStartTime has passed, on BOTH DCs. Check the
# same predicate here so provisioning and the runner cannot disagree.
$kdsProbe = {
    param($Server)
    $ErrorActionPreference = 'Stop'
    $env:ADPS_LoadDefaultDrive = '0'
    Import-Module ActiveDirectory
    $root = Get-ADRootDSE -Server $Server
    $base = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($root.configurationNamingContext)"
    $usable = @(Get-ADObject -LDAPFilter '(objectClass=msKds-ProvRootKey)' -SearchBase $base -Server $Server -Properties 'msKds-CreateTime', 'msKds-UseStartTime' | Where-Object {
            [DateTime]::FromFileTimeUtc([long]$_.'msKds-CreateTime').AddHours(10) -le [DateTime]::UtcNow -and
            [DateTime]::FromFileTimeUtc([long]$_.'msKds-UseStartTime') -le [DateTime]::UtcNow
        } | ForEach-Object { $_.ObjectGUID.ToString() })
    # Emit the GUID strings directly: a wrapped array arrives nested through
    # Invoke-Command and silently breaks the intersection below.
    return $usable
}
$session = Wait-LabGuest $dc1 $domainCredential
try {
    $before = @(Invoke-Command -Session $session -ArgumentList $dc1.name -ScriptBlock $kdsProbe)
    if (-not $before.Count) {
        # A root key is usable only ten hours after its effective time. A
        # disposable lab cannot wait, so the effective time is set in the past.
        # This is a lab acceleration and is not documented production guidance.
        $created = Invoke-Command -Session $session -ScriptBlock {
            $ErrorActionPreference = 'Stop'
            Import-Module ActiveDirectory
            $key = Add-KdsRootKey -EffectiveTime ([DateTime]::UtcNow.AddHours(-11))
            return "$key"
        }
        Write-LabLog "Created a backdated KDS root key: $created"
    }
} finally { Remove-PSSession $session -ErrorAction SilentlyContinue }

# The key must be present on both DCs before any dMSA work, so replicate the
# configuration partition rather than waiting for the schedule.
$session = Wait-LabGuest $dc1 $domainCredential
try {
    Invoke-Command -Session $session -ArgumentList $dc1.name, $dc2.name -ScriptBlock {
        param($Source, $Destination)
        $ErrorActionPreference = 'Stop'
        Import-Module ActiveDirectory
        $root = Get-ADRootDSE -Server $Source
        foreach ($pair in @(@($Destination, $Source), @($Source, $Destination))) {
            try { repadmin /replicate $pair[0] $pair[1] $root.configurationNamingContext /force | Out-Null } catch {}
        }
    }
} finally { Remove-PSSession $session -ErrorAction SilentlyContinue }

$observed = @{}
foreach ($dc in @($dc1, $dc2)) {
    $session = Wait-LabGuest $dc $domainCredential
    try {
        $deadline = [DateTime]::UtcNow.AddMinutes(3)
        do {
            $keys = @(Invoke-Command -Session $session -ArgumentList $dc.name -ScriptBlock $kdsProbe)
            if ($keys.Count) { break }
            Start-Sleep -Seconds 5
        } while ([DateTime]::UtcNow -lt $deadline)
        $observed[$dc.name] = $keys
        Write-LabLog "Usable KDS root keys on $($dc.name): $($keys.Count)."
    } finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
}
$shared = @($observed[$dc1.name] | Where-Object { [string]$_ -in @($observed[$dc2.name] | ForEach-Object { [string]$_ }) })
if ($shared.Count) {
    Write-LabLog "KDS root key effective on both controllers: $($shared.Count)."
} else {
    # Add-KdsRootKey -EffectiveTime backdates msKds-UseStartTime only;
    # msKds-CreateTime is the real creation time and cannot be faked. The dMSA
    # reference runner requires msKds-CreateTime + 10h to have passed, so a
    # freshly created key is genuinely not eligible yet. That is a wait, not a
    # provisioning failure, so configuration continues and reports when the
    # scenarios become available.
    $session = Wait-LabGuest $dc1 $domainCredential
    try {
        $eligible = Invoke-Command -Session $session -ArgumentList $dc1.name -ScriptBlock {
            param($Server)
            $ErrorActionPreference = 'Stop'
            $env:ADPS_LoadDefaultDrive = '0'
            Import-Module ActiveDirectory
            $root = Get-ADRootDSE -Server $Server
            $base = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($root.configurationNamingContext)"
            $times = @(Get-ADObject -LDAPFilter '(objectClass=msKds-ProvRootKey)' -SearchBase $base -Server $Server -Properties 'msKds-CreateTime' |
                ForEach-Object { [DateTime]::FromFileTimeUtc([long]$_.'msKds-CreateTime').AddHours(10) } | Sort-Object)
            if (-not $times.Count) { return $null }
            return $times[0].ToString('o')
        }
    } finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
    if ($eligible) {
        Write-LabLog "KDS root key exists but is not yet ten hours old; dMSA scenarios become eligible at $eligible."
    } else {
        Write-LabLog 'WARNING: no KDS root key is present; dMSA scenarios cannot run.'
    }
}

$session = Wait-LabGuest $member $domainCredential
try {
    $policy = Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
        if (-not (Test-Path $path)) { $null = New-Item -Path $path -Force }
        New-ItemProperty -Path $path -Name 'DelegatedMSAEnabled' -Value 1 -PropertyType DWord -Force | Out-Null
        return (Get-ItemProperty -Path $path -Name 'DelegatedMSAEnabled').DelegatedMSAEnabled
    }
    if ($policy -ne 1) { throw 'Client dMSA policy was not applied on the member.' }
    Write-LabLog 'Member client dMSA policy enabled.'
} finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
Write-LabLog 'Delegated managed service account prerequisites are in place.'
