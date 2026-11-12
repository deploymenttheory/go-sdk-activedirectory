#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState, [Parameter(Mandatory)][PSCredential]$Credential, [Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
if (-not $LabState.configured) { throw 'Complete the Configure action before running the reference tests.' }
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$resultRoot = Join-Path $LabRoot "results\$runId"
$null = New-Item -ItemType Directory -Path $resultRoot -Force
$dc1 = $LabState.machines | Where-Object role -eq 'dc1'
$dc2 = $LabState.machines | Where-Object role -eq 'dc2'
$member = $LabState.machines | Where-Object role -eq 'member'
$hostOS = Get-CimInstance Win32_OperatingSystem
$hostBuild = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$hosts = @()
foreach ($machine in $LabState.machines) {
    $null = Get-OwnedVM $machine $LabState
    $session = Wait-LabGuest $machine $Credential
    try {
        $hosts += Invoke-Command -Session $session -ScriptBlock {
            $os = Get-CimInstance Win32_OperatingSystem
            $build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $module = Get-Module -ListAvailable ActiveDirectory | Sort-Object Version -Descending | Select-Object -First 1
            [ordered]@{computer=$env:COMPUTERNAME; caption=$os.Caption; version=$os.Version; build="$($build.CurrentBuild).$($build.UBR)"; architecture=$env:PROCESSOR_ARCHITECTURE; powershell=$PSVersionTable.PSVersion.ToString(); ad_module=$module.Version.ToString()} | ConvertTo-Json
        } | ConvertFrom-Json
    } finally { Remove-PSSession $session }
}
Write-LabLog "Collecting installed AD module inventory for reference run $runId."
$session = Wait-LabGuest $member $Credential
try {
    $inventory = Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        Import-Module ActiveDirectory
        $common = @('Verbose','Debug','ErrorAction','WarningAction','InformationAction','ProgressAction','ErrorVariable','WarningVariable','InformationVariable','OutVariable','OutBuffer','PipelineVariable')
        $commands = @(Get-Command -Module ActiveDirectory -CommandType Cmdlet | Sort-Object Name | ForEach-Object {
            $command = $_
            [ordered]@{
                name=$command.Name
                parameters=@($command.Parameters.Keys | Where-Object { $_ -notin $common } | Sort-Object)
                parameter_sets=@($command.ParameterSets | Sort-Object Name | ForEach-Object {
                    [ordered]@{name=$_.Name; parameters=@($_.Parameters.Name | Where-Object { $_ -notin $common } | Sort-Object)}
                })
            }
        })
        $build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        [ordered]@{schema_version=1; module_version=(Get-Module ActiveDirectory).Version.ToString(); server_build="$($build.CurrentBuild).$($build.UBR)"; architecture=$env:PROCESSOR_ARCHITECTURE; powershell_version=$PSVersionTable.PSVersion.ToString(); commands=$commands} | ConvertTo-Json -Depth 10
    }
    $inventory | Set-Content -LiteralPath (Join-Path $resultRoot 'module.json') -Encoding UTF8
    $environment = Invoke-Command -Session $session -ArgumentList $dc1.name -ScriptBlock {
        param($Server)
        $ErrorActionPreference = 'Stop'
        $domain = Get-ADDomain -Server $Server
        $forest = Get-ADForest -Server $Server
        $root = Get-ADRootDSE -Server $Server
        [ordered]@{
            domain=$domain.DNSRoot; domain_mode=$domain.DomainMode.ToString(); forest_mode=$forest.ForestMode.ToString()
            schema_version=(Get-ADObject -Identity $root.schemaNamingContext -Properties objectVersion -Server $Server).objectVersion
            controllers=@(Get-ADDomainController -Filter * -Server $Server | Sort-Object HostName | ForEach-Object { [ordered]@{name=$_.HostName; read_only=$_.IsReadOnly; global_catalog=$_.IsGlobalCatalog} })
            secure_channel=(Test-ComputerSecureChannel)
        } | ConvertTo-Json -Depth 6
    } | ConvertFrom-Json
    if ($environment.controllers.Count -ne 2 -or @($environment.controllers | Where-Object read_only).Count -ne 0 -or -not $environment.secure_channel) { throw 'The reference profile requires two writable DCs and a healthy member secure channel.' }
    Write-LabLog 'Running temporary user/group CRUD and replication checks.'
    $reference = Invoke-Command -Session $session -ArgumentList $dc1.name, $dc2.name -ScriptBlock {
        param($Source, $Destination)
        $ErrorActionPreference = 'Stop'
        $suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
        $ouName = "sdk-reference-$suffix"
        $domainDN = (Get-ADDomain -Server $Source).DistinguishedName
        $ouDN = "OU=$ouName,$domainDN"
        $userSam = "sdk${suffix}u"
        $groupSam = "sdk${suffix}g"
        $result = $null
        try {
            New-ADOrganizationalUnit -Name $ouName -Path $domainDN -ProtectedFromAccidentalDeletion:$false -Server $Source
            $user = New-ADUser -Name 'fixture-user' -SamAccountName $userSam -Path $ouDN -Enabled:$false -PassThru -Server $Source
            $group = New-ADGroup -Name 'fixture-group' -SamAccountName $groupSam -Path $ouDN -GroupScope Global -GroupCategory Security -PassThru -Server $Source
            Set-ADUser -Identity $user.ObjectGUID -Description 'AD SDK reference fixture' -Server $Source
            Add-ADGroupMember -Identity $group.ObjectGUID -Members $user.ObjectGUID -Server $Source
            $read = Get-ADUser -Identity $user.ObjectGUID -Properties Description -Server $Source
            $members = @(Get-ADGroupMember -Identity $group.ObjectGUID -Server $Source)
            if ($read.Enabled -or $read.Description -ne 'AD SDK reference fixture' -or $members.Count -ne 1 -or $members[0].ObjectGUID -ne $user.ObjectGUID) { throw 'Reference CRUD or membership assertion failed.' }
            $replicated = $false
            $deadline = [DateTime]::UtcNow.AddMinutes(3)
            while ([DateTime]::UtcNow -lt $deadline) {
                $remoteUser = @(Get-ADUser -LDAPFilter "(sAMAccountName=$userSam)" -SearchBase $domainDN -Properties Description -Server $Destination)
                $remoteGroup = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$groupSam)" -SearchBase $domainDN -Properties member -Server $Destination)
                if ($remoteUser.Count -eq 1 -and $remoteGroup.Count -eq 1 -and $remoteUser[0].Description -eq $read.Description -and $remoteGroup[0].member -contains $user.DistinguishedName) { $replicated = $true; break }
                Start-Sleep -Seconds 3
            }
            if (-not $replicated) { throw 'Fixture user and group membership did not replicate within three minutes.' }
            Remove-ADGroupMember -Identity $group.ObjectGUID -Members $user.ObjectGUID -Confirm:$false -Server $Source
            if (@(Get-ADGroupMember -Identity $group.ObjectGUID -Server $Source).Count -ne 0) { throw 'Group member removal failed.' }
            $result = [ordered]@{user_enabled=$read.Enabled; description=$read.Description; group_scope=$group.GroupScope.ToString(); group_category=$group.GroupCategory.ToString(); member_count=$members.Count; member_matches_user=$true; replicated_user_and_membership=$true; removed_membership=$true; cleanup=$false}
        } finally {
            $fixture = @(Get-ADOrganizationalUnit -LDAPFilter "(ou=$ouName)" -SearchBase $domainDN -Server $Source)
            if ($fixture.Count -gt 0) { Remove-ADOrganizationalUnit -Identity $ouDN -Recursive -Confirm:$false -Server $Source }
            $clean = $false
            $deadline = [DateTime]::UtcNow.AddMinutes(3)
            while ([DateTime]::UtcNow -lt $deadline) {
                $remaining = @()
                foreach ($server in @($Source, $Destination)) {
                    $remaining += @(Get-ADObject -LDAPFilter "(|(ou=$ouName)(sAMAccountName=$userSam)(sAMAccountName=$groupSam))" -SearchBase $domainDN -Server $server)
                }
                if ($remaining.Count -eq 0) { $clean = $true; break }
                Start-Sleep -Seconds 3
            }
            if (-not $clean) { throw "Reference fixture cleanup was not confirmed on both DCs: $ouDN" }
            if ($result) { $result.cleanup = $true }
        }
        return $result | ConvertTo-Json -Depth 5
    } | ConvertFrom-Json
    [ordered]@{
        schema_version=1; run=$runId; time=[DateTime]::UtcNow.ToString('o'); passed=$true
        host=[ordered]@{version=$hostOS.Version; build="$($hostBuild.CurrentBuild).$($hostBuild.UBR)"; architecture=$env:PROCESSOR_ARCHITECTURE}
        image=$LabState.image; machines=$hosts; directory=$environment; normalized_reference=$reference
        scope='PowerShell reference and lab bootstrap only; does not validate native SDK operation parity.'
    } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $resultRoot 'reference.json') -Encoding UTF8
    Write-LabLog "Reference test passed; fixtures removed. Results: $resultRoot"
} finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
