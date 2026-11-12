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
