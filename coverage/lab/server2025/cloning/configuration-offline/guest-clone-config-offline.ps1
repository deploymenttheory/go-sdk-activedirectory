#Requires -Version 5.1
# Invoked only by the reviewed host wrapper. No directory, group, ACL, or VM
# changes. The sole child runs the frozen harness in explicit Offline mode.
param(
    [Parameter(Mandatory)][ValidateSet('Stage','Run','Capture')][string]$Action,
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][string]$Run,
    [Parameter(Mandatory)][string]$PayloadJson,
    [ValidateRange(60,600)][int]$ProcessTimeoutSeconds=300
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-GuestPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Guest path traverses a reparse point.' }
    }
    return $full
}
function Assert-GuestIdentity($Identity) {
    if($env:COMPUTERNAME -cne 'ADSDK25DC1' -or
        $Run -cne 'clone-config-reviewed-20261112T211528Z-81823b4e-offline-server2025-v1' -or
        $Identity.run -cne $Run -or $Identity.source_commit -cne '4120ce5d13dd49de490cef67d41767ac3b409715' -or
        $Identity.native_sha256 -cne '9FC1C95989517E0AC5753747B56FB17931C8ECB387E22083F6B0B60C6D4642B2' -or
        $Identity.reference_sha256 -cne '3F68500FEC99CAF5948E4C391B62AD51CCB0A4C65A50C4D52E2E423DC4CCDC45' -or
        $Identity.schema_sha256 -cne 'A061F397D27B26563E6B4C7D611F707F5A3CA4A5B9CBD3353CB2CDC7BA9D7F35') { throw 'Guest or frozen payload identity differs.' }
    if((Assert-GuestPath $Directory) -cne (Join-Path 'C:\ad-sdk-validation' $Run)) { throw 'Guest staging path differs.' }
}
function Guest-Hash([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','') } finally { $hasher.Dispose() }
}
function Write-GuestBytes([string]$Path,[byte[]]$Bytes) {
    $full=Assert-GuestPath $Path
    if(-not $full.StartsWith($Directory+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Guest write escaped staging.' }
    $stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
}
function Write-ProcessRecord($Value) {
    $path=Assert-GuestPath (Join-Path $Directory 'guest-process.json')
    if(Test-Path -LiteralPath $path) {
        $old=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if($old.run -cne $Run -or $old.owner -cne $Value.owner) { throw 'Guest process journal ownership differs.' }
    }
    $pending=$path+'.pending-'+[guid]::NewGuid().ToString('N')
    Write-GuestBytes $pending ([Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12)))
    if(Test-Path -LiteralPath $path) { [IO.File]::Replace($pending,$path,[NullString]::Value) } else { [IO.File]::Move($pending,$path) }
}
function Assert-StagedPayload($Identity) {
    Assert-GuestIdentity $Identity
    $owner=Assert-GuestPath (Join-Path $Directory 'owner.txt')
    if([IO.File]::ReadAllText($owner) -cne $Run) { throw 'Guest staging owner differs.' }
    foreach($pair in @(@('dccloneconfig.exe','native_sha256'),@('reference-dc-clone-config.ps1','reference_sha256'),@('schema-evidence.json','schema_sha256'))) {
        $path=Assert-GuestPath (Join-Path $Directory $pair[0])
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $Identity.($pair[1])) { throw 'Staged frozen payload hash differs.' }
    }
}
function Assert-NoOwnedNativeProcess {
    $executable=Join-Path $Directory 'dccloneconfig.exe'
    foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='dccloneconfig.exe'" -OperationTimeoutSec 10 -ErrorAction Stop)) {
        if(-not $process.ExecutablePath -or [string]::Equals($process.ExecutablePath,$executable,[StringComparison]::OrdinalIgnoreCase)) { throw 'An owned or unidentifiable native process remains; preserve staging.' }
    }
}
function Wait-OwnedProcess($Process,[int]$Seconds) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.Elapsed.TotalSeconds -lt $Seconds) {
        if($Process.WaitForExit(250)) { return $true }
    }
    # Never kill or retry an uncertain process. The host stops all later work.
    return $false
}
function Start-OwnedReferenceProcess([string]$Executable,[string]$Arguments,[string]$Stdout,[string]$Stderr,$Record) {
    $process=Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr -ErrorAction Stop
    try {
        $Record.pid=$process.Id
        $null=$process.Handle # Hold the native handle, including for fast exits.
        $Record.started_utc=$process.StartTime.ToUniversalTime().ToString('o')
        return $process
    } catch {
        $process.Dispose() # Never terminate an uncertain process.
        throw
    }
}
function Assert-ReferenceSummary($Summary,$Identity) {
    if($Summary.computer -cne 'ADSDK25DC1' -or $Summary.mode -cne 'explicit offline only' -or
        $Summary.sdk_sha256 -cne $Identity.native_sha256 -or $Summary.schema_evidence_sha256 -cne $Identity.schema_sha256 -or
        -not $Summary.os_version -or -not $Summary.powershell -or -not $Summary.module_version -or -not $Summary.assembly_version -or
        $Summary.assembly_sha256 -notmatch '^[A-F0-9]{64}$' -or @($Summary.cases).Count -ne 10) { throw 'Reference summary provenance or case count differs.' }
    $expected=@('default','name-site','v4-dynamic','v4-static','v6-dynamic','v6-static','dual-dynamic','dual-static','four-resolvers','overwrite')
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($case in $Summary.cases) {
        if($case.name -cnotin $expected -or -not $seen.Add($case.name) -or $case.passed -isnot [bool] -or -not $case.passed -or
            $case.error -or $case.sdk_sha256 -notmatch '^[A-F0-9]{64}$' -or $case.reference_sha256 -notmatch '^[A-F0-9]{64}$') { throw 'A reference case is missing, duplicated, failed, or lacks XML hashes.' }
    }
}
function Invoke-ReferenceProcess($Identity) {
    Assert-StagedPayload $Identity
    Assert-NoOwnedNativeProcess
    $recordPath=Join-Path $Directory 'guest-process.json'
    if(Test-Path -LiteralPath $recordPath) { throw 'A process attempt was already recorded; no replay is allowed.' }
    $results=Assert-GuestPath (Join-Path $Directory 'results')
    if(Test-Path -LiteralPath $results) { throw 'Existing results are preserved.' }
    [void][IO.Directory]::CreateDirectory($results)
    $record=[ordered]@{schema_version=1;run=$Run;owner=[guid]::NewGuid().ToString('N');source_commit=$Identity.source_commit;native_sha256=$Identity.native_sha256;reference_sha256=$Identity.reference_sha256;schema_sha256=$Identity.schema_sha256;pid=$null;started_utc=$null;completed=$false;process_uncertain=$true;exit_code=$null;passed=$false;error=$null;timeout_seconds=$ProcessTimeoutSeconds;staging_preserved=$true}
    Write-ProcessRecord $record
    $process=$null
    try {
        $powerShell=Assert-GuestPath (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe')
        $reference=Assert-GuestPath (Join-Path $Directory 'reference-dc-clone-config.ps1')
        $native=Assert-GuestPath (Join-Path $Directory 'dccloneconfig.exe')
        $schema=Assert-GuestPath (Join-Path $Directory 'schema-evidence.json')
        # All paths come from fixed, validated roots/run IDs and contain no quote.
        $arguments='-NoLogo -NoProfile -NonInteractive -File "'+$reference+'" -SdkBinary "'+$native+'" -ArtifactDirectory "'+$results+'" -SchemaEvidence "'+$schema+'"'
        $process=Start-OwnedReferenceProcess $powerShell $arguments (Join-Path $Directory 'reference.stdout.txt') (Join-Path $Directory 'reference.stderr.txt') $record
        Write-ProcessRecord $record
        if(-not (Wait-OwnedProcess $process $ProcessTimeoutSeconds)) { throw 'Owned reference process exceeded its deadline; it is preserved without retry or cleanup.' }
        $record.exit_code=$process.ExitCode
        if($null -eq $record.exit_code) { throw 'Owned reference process exit status is unavailable.' }
        Assert-NoOwnedNativeProcess
        $record.completed=$true;$record.process_uncertain=$false
        if($record.exit_code -ne 0) { throw 'Frozen offline harness reported failure.' }
        $directories=@(Get-ChildItem -LiteralPath $results -Force)
        if($directories.Count -ne 1 -or -not $directories[0].PSIsContainer -or $directories[0].Name -cnotmatch '^clone-config-[a-f0-9]{32}$') { throw 'Reference result directory cardinality differs.' }
        $summaryPath=Assert-GuestPath (Join-Path $directories[0].FullName 'summary.json')
        if((Get-Item -LiteralPath $summaryPath).Length -gt 2097152) { throw 'Reference summary is oversized.' }
        $summary=Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        Assert-ReferenceSummary $summary $Identity
        $record.passed=$true
    } catch { $record.error=$_.Exception.Message }
    finally {
        Write-ProcessRecord $record
        if($null -ne $process) { $process.Dispose() } # Closes our handle, never the child.
    }
    return ($record | ConvertTo-Json -Depth 12 -Compress)
}
function Get-RawCapture($Identity) {
    Assert-StagedPayload $Identity
    $recordPath=Assert-GuestPath (Join-Path $Directory 'guest-process.json')
    $record=Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    if($record.run -cne $Run -or $record.completed -isnot [bool] -or -not $record.completed -or
        $record.process_uncertain -isnot [bool] -or $record.process_uncertain) { throw 'Guest process completion is uncertain; capture is prohibited.' }
    $current=Get-Process -Id $record.pid -ErrorAction SilentlyContinue
    if($null -ne $current -and $current.StartTime.ToUniversalTime().ToString('o') -ceq $record.started_utc) { throw 'Owned reference process is still present; capture is prohibited.' }
    Assert-NoOwnedNativeProcess
    $files=[Collections.Generic.List[object]]::new();$queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($Directory)
    $total=0L;$visited=0
    while($queue.Count) {
        $parent=Assert-GuestPath ($queue.Dequeue());$visited++
        if($visited -gt 64) { throw 'Evidence directory count exceeded its bound.' }
        foreach($item in @(Get-ChildItem -LiteralPath $parent -Force)) {
            $path=Assert-GuestPath $item.FullName
            if(-not $path.StartsWith($Directory+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Raw evidence path escaped staging.' }
            if($item.PSIsContainer) { $queue.Enqueue($path);continue }
            $relative=$path.Substring($Directory.Length+1).Replace('\','/')
            if($relative -cin @('dccloneconfig.exe','reference-dc-clone-config.ps1','schema-evidence.json')) { continue }
            if($item.Length -gt 2097152 -or $files.Count -ge 128) { throw 'Raw evidence file bound exceeded.' }
            $bytes=[IO.File]::ReadAllBytes($path);$total+=$bytes.Length
            if($bytes.Length -ne $item.Length -or $total -gt 16777216) { throw 'Raw evidence changed size or exceeds the aggregate bound.' }
            $files.Add([ordered]@{name=$relative;length=$bytes.Length;sha256=(Guest-Hash $bytes);bytes_base64=[Convert]::ToBase64String($bytes)})
        }
    }
    return ([ordered]@{run=$Run;files=@($files.ToArray())} | ConvertTo-Json -Depth 8 -Compress)
}

$identity=$PayloadJson | ConvertFrom-Json
Assert-GuestIdentity $identity
if($Action -ceq 'Stage') {
    if(Test-Path -LiteralPath $Directory) { throw 'Guest staging already exists; preserve it without replay.' }
    # Check every input before creating the owned directory.
    $payloads=[ordered]@{}
    foreach($item in @(@('native','dccloneconfig.exe','native_sha256',33554432),@('reference','reference-dc-clone-config.ps1','reference_sha256',1048576),@('schema','schema-evidence.json','schema_sha256',4194304))) {
        if($identity.($item[0]).Length -gt [Math]::Ceiling([double]$item[3]/3)*4) { throw 'Staging payload exceeds its bound.' }
        $bytes=[Convert]::FromBase64String($identity.($item[0]))
        if($bytes.Length -gt $item[3] -or (Guest-Hash $bytes) -cne $identity.($item[2])) { throw 'Staging payload size or hash differs.' }
        $payloads[$item[1]]=$bytes
    }
    [void][IO.Directory]::CreateDirectory($Directory)
    Write-GuestBytes (Join-Path $Directory 'owner.txt') ([Text.UTF8Encoding]::new($false).GetBytes($Run))
    foreach($name in $payloads.Keys) { Write-GuestBytes (Join-Path $Directory $name) $payloads[$name] }
    Assert-StagedPayload $identity
    Write-Output 'staged'
} elseif($Action -ceq 'Run') {
    Invoke-ReferenceProcess $identity
} else {
    Get-RawCapture $identity
}
