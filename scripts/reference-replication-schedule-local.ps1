# Offline only: constructs Microsoft schedule objects; no directory connection.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.DirectoryServices
$type = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchedule]
$method = $type.GetMethod('GetUnmanagedSchedule', [Reflection.BindingFlags]'Instance,NonPublic')
if ($null -eq $method) { throw 'Microsoft schedule conversion method is unavailable' }
$offset = [int]([TimeZone]::CurrentTimeZone.GetUtcOffset([DateTime]::Now).Ticks / [TimeSpan]::TicksPerHour)
$checks = 0
foreach ($hour in 0..167) {
    foreach ($quarter in 0..3) {
        $schedule = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchedule]::new()
        $slots = [bool[,,]]::new(7,24,4)
        $slots[[int][Math]::Floor($hour / 24),($hour % 24),$quarter] = $true
        $schedule.RawSchedule = $slots
        $actual = [byte[]]$method.Invoke($schedule, @())
        $expected = [byte[]]::new(188)
        $expected[0] = 188; $expected[8] = 1; $expected[16] = 20
        $utcHour = ($hour - $offset + 168) % 168
        $expected[20 + $utcHour] = [byte](1 -shl $quarter)
        if ([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($expected)) { throw "Schedule mismatch at hour $hour quarter $quarter" }
        $checks++
    }
}
[ordered]@{
    complete = $true; checks = $checks; directory_calls = 0
    assembly = $type.Assembly.FullName; powershell = [string]$PSVersionTable.PSVersion
    local_offset_hours = $offset
    encoding = '188-byte UTC week; Sunday first; quarter bits 1,2,4,8'
} | ConvertTo-Json -Compress
