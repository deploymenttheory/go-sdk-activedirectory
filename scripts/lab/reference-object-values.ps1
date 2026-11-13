#Requires -Version 5.1
# Local .NET conversion reference only. No directory connection or mutation.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$path=[IO.Path]::GetFullPath($OutputPath)
for($cursor=$path;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
    if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Output traverses a reparse point.' }
}
if(Test-Path -LiteralPath $path) { throw 'Reference already exists; choose a fresh output.' }
$module=Get-Module -ListAvailable ActiveDirectory | Select-Object -First 1
$record=[ordered]@{schema_version=1;purpose='go-sdk-activedirectory-object-values-reference';collected_utc=[DateTime]::UtcNow.ToString('o');
    computer=$env:COMPUTERNAME;os_version=[Environment]::OSVersion.VersionString;powershell_version=$PSVersionTable.PSVersion.ToString();
    active_directory_module_version=$(if($module){$module.Version.ToString()}else{$null});directory_contacted=$false;full_ticket_complete=$false;
    guids=@();sids=@();file_times=@();intervals=@();flags=@();generalized_times=@()}
foreach($text in @('00112233-4455-6677-8899-aabbccddeeff','00000000-0000-0000-0000-000000000000','ffffffff-ffff-ffff-ffff-ffffffffffff')) {
    $value=[guid]$text
    $record.guids+=@([ordered]@{text=$value.ToString('D');binary_hex=[BitConverter]::ToString($value.ToByteArray()).Replace('-','').ToLowerInvariant()})
}
foreach($text in @('S-1-5-21-1-2-3-500','S-1-5-32-544','S-1-5-21-4294967295')) {
    $value=[Security.Principal.SecurityIdentifier]::new($text)
    $bytes=New-Object byte[] $value.BinaryLength;$value.GetBinaryForm($bytes,0)
    $record.sids+=@([ordered]@{text=$value.Value;binary_hex=[BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()})
}
foreach($text in @('0','9223372036854775807','-1','1','116444736000000000','133711234567890123')) {
    $sentinel=$text -in @('0','9223372036854775807','-1')
    $record.file_times+=@([ordered]@{ticks=([long]$text).ToString();sentinel=$sentinel;utc=$(if($sentinel){$null}else{[DateTime]::FromFileTimeUtc([long]$text).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')})})
}
foreach($text in @('0','1','-1','-864000000000','-9223372036854775808','9223372036854775807')) {
    $record.intervals+=@([ordered]@{ticks=[TimeSpan]::FromTicks([long]$text).Ticks.ToString()})
}
foreach($text in @('0','2','-2147483646','-1')) {
    $signed=[int32]$text
    $record.flags+=@([ordered]@{signed=$signed.ToString();unsigned=[BitConverter]::ToUInt32([BitConverter]::GetBytes($signed),0).ToString()})
}
foreach($text in @('20240229123456.1234567Z','20240101000000.0000001Z')) {
    $value=[DateTime]::ParseExact($text,'yyyyMMddHHmmss.fffffffZ',[Globalization.CultureInfo]::InvariantCulture,([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
    $record.generalized_times+=@([ordered]@{text=$text;file_time=$value.ToFileTimeUtc().ToString()})
}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 8))
$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
Write-Output 'Local conversion reference captured; no live directory coverage claimed.'
