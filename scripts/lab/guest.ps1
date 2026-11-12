# Shared host-side helpers. Dot-source from an elevated lab action.
function Wait-LabGuest($Machine, [PSCredential[]]$Credential, [string]$PreviousBoot = '') {
    $deadline = [DateTime]::UtcNow.AddMinutes(15)
    $lastError = 'Guest has not responded.'
    while ([DateTime]::UtcNow -lt $deadline) {
        foreach ($candidate in $Credential) {
            $session = $null
            try {
                $session = New-PSSession -VMId ([guid]$Machine.id) -Credential $candidate -ErrorAction Stop
                $boot = Invoke-Command -Session $session -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') } -ErrorAction Stop
                if (-not $PreviousBoot -or $boot -ne $PreviousBoot) { return $session }
            } catch { $lastError = $_.Exception.Message }
            if ($session) { Remove-PSSession $session }
        }
        Start-Sleep -Seconds 5
    }
    throw "Timed out waiting for $($Machine.name): $lastError"
}

function Restart-LabGuest($Machine, $Session, [PSCredential]$Credential) {
    $boot = Invoke-Command -Session $Session -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
    Invoke-Command -Session $Session -ScriptBlock {
        & shutdown.exe /r /t 2 /f | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Guest shutdown command failed: $LASTEXITCODE" }
    }
    Remove-PSSession $Session
    return Wait-LabGuest $Machine $Credential $boot
}

function Wait-LabDirectory($Machine, [PSCredential]$Credential) {
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    $lastError = ''
    while ([DateTime]::UtcNow -lt $deadline) {
        $session = Wait-LabGuest $Machine $Credential
        try {
            Invoke-Command -Session $session -ScriptBlock {
                $ErrorActionPreference = 'Stop'
                Import-Module ActiveDirectory
                $null = Get-ADDomain -Server localhost
                foreach ($service in Get-Service NTDS,DNS,ADWS,Netlogon) {
                    if ($service.Status -ne 'Running') { throw "Directory service is not ready: $($service.Name)" }
                }
                $shares = @(Get-SmbShare -Name SYSVOL,NETLOGON)
                if ($shares.Count -ne 2) { throw 'SYSVOL and NETLOGON are not both published.' }
                if ((Get-ADRootDSE -Server localhost).isSynchronized -notcontains 'TRUE') { throw 'Directory synchronization is not complete.' }
            } -ErrorAction Stop
            return $session
        } catch { $lastError = $_.Exception.Message; Remove-PSSession $session }
        Start-Sleep -Seconds 5
    }
    throw "Directory did not become ready on $($Machine.name): $lastError"
}

function Wait-LabDomainDiscovery($Session, [string]$Domain) {
    $deadline = [DateTime]::UtcNow.AddMinutes(5)
    $lastError = ''
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            Invoke-Command -Session $Session -ArgumentList $Domain -ScriptBlock {
                param($DomainName)
                $ErrorActionPreference = 'Stop'
                Import-Module ActiveDirectory
                $null = Get-ADDomainController -Discover -DomainName $DomainName -Writable -ForceDiscover
            } -ErrorAction Stop
            return
        } catch { $lastError = $_.Exception.Message }
        Start-Sleep -Seconds 5
    }
    throw "Domain discovery did not become ready: $lastError"
}
