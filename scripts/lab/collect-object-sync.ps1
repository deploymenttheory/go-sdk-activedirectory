[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceHost,
    [Parameter(Mandatory)][ValidateRange(1,65535)][int]$SourcePort,
    [Parameter(Mandatory)][string]$DestinationHost,
    [Parameter(Mandatory)][ValidateRange(1,65535)][int]$DestinationPort,
    [Parameter(Mandatory)][string]$Partition,
    [Parameter(Mandatory)][string]$ObjectDN,
    [ValidateSet('description','displayName')][string[]]$Properties = @('description'),
    [switch]$PasswordOnly,
    [switch]$ApplyReferenceSync,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Revision,
    [Parameter(Mandatory)][string]$RunID,
    [Parameter(Mandatory)][string]$OutputPath
)
# Explicit opt-in reference mutation only. No fixtures, policy, VM or retry logic.
# Use existing lab process ownership and an outer deadline; a stopped Sync-ADObject
# can have an uncertain server outcome and must not be automatically replayed.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputPath) { throw 'OutputPath must be new.' }
foreach ($serverHost in @($SourceHost, $DestinationHost)) {
    if ($serverHost -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9.-]+$') { throw 'Explicit DC FQDN required.' }
}
if ([string]::IsNullOrWhiteSpace($RunID)) { throw 'RunID required.' }
Import-Module ActiveDirectory -ErrorAction Stop
$source = '{0}:{1}' -f $SourceHost,$SourcePort
$destination = '{0}:{1}' -f $DestinationHost,$DestinationPort
$selected = @($Properties)
if ($PasswordOnly) { $selected = @() }
function Read-Snapshot([string]$Server) {
    $readArguments = @{ Server=$Server; Partition=$Partition; Identity=$ObjectDN; ErrorAction='Stop' }
    if ($selected.Count -gt 0) { $readArguments.Properties = $selected }
    $entry = Get-ADObject @readArguments
    $attributes = [ordered]@{}
    foreach ($name in $selected) {
        $values = @($entry.$name)
        if ($values.Count -eq 0) { throw 'Selected comparison property unavailable.' }
        $encoded = @($values | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$_)) })
        $attributes[$name.ToLowerInvariant()] = $encoded
    }
    [ordered]@{ dn=$entry.DistinguishedName; guid=[Convert]::ToBase64String($entry.ObjectGUID.ToByteArray()); attributes=$attributes }
}
function Read-Server([string]$Server) {
    $root = Get-ADRootDSE -Server $Server -ErrorAction Stop
    $dsa = Get-ADObject -Server $Server -Identity $root.dsServiceName -Properties msDS-Behavior-Version -ErrorAction Stop
    $serverEntry = Get-ADObject -Server $Server -Identity $root.serverName -Properties serverReference -ErrorAction Stop
    $serverOS = $null
    if ($serverEntry.serverReference) {
        $computer = Get-ADObject -Server $Server -Identity $serverEntry.serverReference -Properties operatingSystem,operatingSystemVersion -ErrorAction Stop
        $serverOS = [ordered]@{ caption=$computer.operatingSystem; version=$computer.operatingSystemVersion }
    }
    [ordered]@{ dns_host_name=$root.dnsHostName; dsa=$root.dsServiceName; behavior_version=$dsa.'msDS-Behavior-Version'; naming_contexts=@($root.namingContexts); computer_dn=$serverEntry.serverReference; server_os=$serverOS }
}
$sourceInfo = Read-Server $source
$destinationInfo = Read-Server $destination
$beforeSource = Read-Snapshot $source
$beforeDestination = Read-Snapshot $destination
if ($beforeSource.guid -ne $beforeDestination.guid) { throw 'Different object identities.' }
if ($ApplyReferenceSync) {
    $arguments = @{ Source=$source; Destination=$destination; Object=$ObjectDN; ErrorAction='Stop' }
    if ($PasswordOnly) { $arguments.PasswordOnly = $true }
    Sync-ADObject @arguments
}
$after = Read-Snapshot $destination
$cacheObserved = $false
if ($PasswordOnly) {
    if (-not $destinationInfo.computer_dn) { throw 'RODC computer identity unavailable.' }
    $rodc = Get-ADObject -Server $destination -Identity $destinationInfo.computer_dn -Properties msDS-RevealedList -ErrorAction Stop
    $markerPrefix = 'S:10:unicodePwd:'
    foreach ($marker in @($rodc.'msDS-RevealedList')) {
        $text = [string]$marker
        if ($text.StartsWith($markerPrefix,[StringComparison]::OrdinalIgnoreCase)) {
            $cached = Get-ADObject -Server $destination -Identity $text.Substring($markerPrefix.Length) -ErrorAction Stop
            if ([Convert]::ToBase64String($cached.ObjectGUID.ToByteArray()) -eq $after.guid) { $cacheObserved = $true; break }
        }
    }
}
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$evidence = [ordered]@{
    schema=1; revision=$Revision; run_id=$RunID; observed_utc=[DateTime]::UtcNow.ToString('o')
    source_host=$SourceHost; source_port=$SourcePort; destination_host=$DestinationHost; destination_port=$DestinationPort
    partition=$Partition; object_dn=$ObjectDN; password_only=[bool]$PasswordOnly; applied=[bool]$ApplyReferenceSync
    secret_cache_observed=$cacheObserved
    ad_module=(Get-Module ActiveDirectory).Version.ToString(); powershell=$PSVersionTable.PSVersion.ToString()
    collector_os=[ordered]@{caption=$os.Caption; version=$os.Version; build=$os.BuildNumber}
    source_server=$sourceInfo; destination_server=$destinationInfo
    source_before=$beforeSource; destination_before=$beforeDestination; destination_after=$after
}
$json = $evidence | ConvertTo-Json -Depth 12
$stream = [IO.File]::Open($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream.Write($bytes,0,$bytes.Length)
} finally { $stream.Dispose() }
