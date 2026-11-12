#Requires -Version 5.1
# PSDirect bootstrap only. Run invokes the hash-checked staged guest FILE so its
# ReferenceChild -File invocations retain PSCommandPath and identical bytes.
param(
    [Parameter(Mandatory)][ValidateSet('Stage','Run','Capture')][string]$Action,
    [Parameter(Mandatory)][string]$StageDirectory,
    [Parameter(Mandatory)][string]$Run,
    [Parameter(Mandatory)][string]$IdentityJson,
    [ValidateRange(1,300)][int]$ProcessTimeoutSeconds=60
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Assert-BootstrapPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    $stage=[IO.Path]::GetFullPath($StageDirectory)
    if($stage -cne (Join-Path 'C:\ad-sdk-validation' $Run) -or ($full -cne $stage -and -not $full.StartsWith($stage+'\',[StringComparison]::OrdinalIgnoreCase))) { throw 'Bootstrap path escaped owned staging.' }
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Bootstrap path traverses a reparse point.' }
    }
    return $full
}
function Assert-BootstrapIdentity($Identity) {
    if($env:COMPUTERNAME -cne 'ADSDK25DC1' -or $Run -cne 'clone-config-reviewed-20261112T211528Z-81823b4e-negative-server2025-v1' -or
        $Identity.run -cne $Run -or $Identity.source_commit -cne '4120ce5d13dd49de490cef67d41767ac3b409715' -or
        $Identity.guest_sha256 -notmatch '^[A-F0-9]{64}$' -or
        $Identity.helper_sha256 -cne '6E2DB3902038DF408192E3137CF541F86F2D43E99E3F455BA01C884140D4BEC9' -or
        $Identity.source_sha256 -cne 'F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1' -or
        $Identity.build_sha256 -cne '6AB9B1B9129A39BC9C68FB4B00CB38D6DB4A31C4E925BB1C3790431927AD9E29' -or
        $Identity.helper_build_sha256 -cne '0D9B53AF8EDDD7E942144158D6BE56E343B5A4C2F576A0D4D79CA7F594907C75') { throw 'Negative qualification payload identity differs.' }
    $null=Assert-BootstrapPath $StageDirectory
}
function Bootstrap-Hash([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','') } finally { $hasher.Dispose() }
}
function Write-BootstrapBytes([string]$Path,[byte[]]$Bytes) {
    $path=Assert-BootstrapPath $Path
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
}
function Get-BootstrapPayloads {
    return @(
        @('guest','guest-clone-config-negative.ps1','guest_sha256',1048576),
        @('helper','clone-config-helper.exe','helper_sha256',33554432),
        @('source','clone-config-helper.go','source_sha256',1048576),
        @('build','build.json','build_sha256',1048576),
        @('helper_build','helper-v2-build.json','helper_build_sha256',1048576)
    )
}
function Assert-BootstrapStaging($Identity) {
    Assert-BootstrapIdentity $Identity
    if([IO.File]::ReadAllText((Assert-BootstrapPath (Join-Path $StageDirectory 'owner.txt'))) -cne $Run) { throw 'Negative staging owner differs.' }
    foreach($item in Get-BootstrapPayloads) {
        $path=Assert-BootstrapPath (Join-Path $StageDirectory $item[1])
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $Identity.($item[2])) { throw 'Staged negative payload hash differs.' }
    }
}
function Assert-NegativeProcessesAbsent {
    $native=Join-Path $StageDirectory 'clone-config-helper.exe';$guest=Join-Path $StageDirectory 'guest-clone-config-negative.ps1'
    foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='clone-config-helper.exe' OR Name='powershell.exe'" -OperationTimeoutSec 10 -ErrorAction Stop)) {
        if($process.Name -ieq 'clone-config-helper.exe') {
            if(-not $process.ExecutablePath -or [string]::Equals($process.ExecutablePath,$native,[StringComparison]::OrdinalIgnoreCase)) { throw 'An owned or unidentifiable helper process remains.' }
        } elseif(-not $process.CommandLine -or $process.CommandLine.IndexOf($guest,[StringComparison]::OrdinalIgnoreCase) -ge 0) { throw 'An owned or unidentifiable reference process remains.' }
    }
}
function Get-NegativeCaseNames {
    return @('control-v4-static','control-four-v6-dns','dynamic-with-static-fields','static-missing-address','static-missing-mask','static-missing-dns','static-empty-dns','malformed-ipv4-address','broadcast-address','broadcast-gateway','noncontiguous-mask','dynamic-with-gateway','five-v4-dns','five-v6-dns','static-without-family','static-v4-dns-only','broadcast-dns','malformed-v4-dns','malformed-v6-dns')
}
function Assert-NegativeMatrixState($Summary) {
    $names=Get-NegativeCaseNames;$cases=@($Summary.cases)
    if($Summary.completed -isnot [bool] -or $Summary.passed -isnot [bool] -or $null -eq $Summary.cases -or $cases.Count -gt $names.Count -or
        $Summary.process_uncertain -isnot [bool] -or $Summary.process_uncertain -or $Summary.publication_uncertain -isnot [bool] -or $Summary.publication_uncertain -or
        $Summary.capture_failed -isnot [bool] -or $Summary.capture_failed -or
        ($Summary.completed -and $cases.Count -ne $names.Count) -or
        (-not $Summary.completed -and ($Summary.passed -or $null -eq $Summary.error)) -or
        ($Summary.passed -and $null -ne $Summary.error)) { throw 'Matrix is not a full result or a known stopped failure.' }
    for($index=0;$index -lt $cases.Count;$index++) {
        $case=$cases[$index]
        if($case.name -cne $names[$index] -or $case.passed -isnot [bool] -or ($Summary.passed -and -not $case.passed)) { throw 'Negative case sequence or success state differs.' }
        $partialLast=(-not $Summary.completed -and $index -eq $cases.Count-1 -and -not $case.passed)
        if($null -eq $case.sdk_process -and ($null -ne $case.reference_process -or $null -ne $case.sdk_file) -or
            $null -eq $case.reference_process -and $null -ne $case.reference) { throw 'Negative child/observation order is inconsistent.' }
        foreach($process in @($case.sdk_process,$case.reference_process)) {
            if($null -eq $process) { if(-not $partialLast) { throw 'A completed case is missing a child result.' };continue }
            if($process.completed -isnot [bool] -or -not $process.completed -or $process.process_uncertain -isnot [bool] -or $process.process_uncertain -or
                $process.pid -le 0 -or -not $process.started_utc -or $null -eq $process.exit_code) { throw 'An attempted negative child has uncertain completion.' }
        }
        if(($Summary.completed -or $case.passed) -and ($null -eq $case.sdk_file -or $null -eq $case.reference)) { throw 'Completed case lacks output observations.' }
    }
}
function Assert-NegativeCaptureSafe($Summary,$Identity) {
    if($Summary.run -cne $Run -or $Summary.harness_sha256 -cne $Identity.guest_sha256 -or
        $Summary.helper_binary_sha256 -cne $Identity.helper_sha256 -or $Summary.helper_source_sha256 -cne $Identity.source_sha256) { throw 'Negative capture identity differs.' }
    Assert-NegativeMatrixState $Summary
}
function Assert-NegativeAttemptFiles($Summary) {
    foreach($case in $Summary.cases) {
        $directory=Assert-BootstrapPath (Join-Path (Join-Path $StageDirectory 'negative-cases') $case.name)
        foreach($pair in @(@($case.sdk_process,'sdk'),@($case.reference_process,'reference-child'))) {
            if($null -ne $pair[0]) { continue }
            foreach($suffix in @('.requested.json','.started.json','.finished.json','.stdout.txt','.stderr.txt')) {
                if(Test-Path -LiteralPath (Assert-BootstrapPath (Join-Path $directory ($pair[1]+$suffix)))) { throw 'Unreported child attempt exists; capture is prohibited.' }
            }
        }
    }
}
function Capture-NegativeEvidence($Identity) {
    Assert-BootstrapStaging $Identity
    $summaryPath=Assert-BootstrapPath (Join-Path $StageDirectory 'negative-cases\summary.json')
    if((Get-Item -LiteralPath $summaryPath).Length -gt 2097152) { throw 'Negative summary exceeds its bound.' }
    $summary=Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    Assert-NegativeCaptureSafe $summary $Identity
    Assert-NegativeAttemptFiles $summary
    Assert-NegativeProcessesAbsent
    $files=[Collections.Generic.List[object]]::new();$queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($StageDirectory)
    $visited=0;$total=0L
    $payloadNames=@((Get-BootstrapPayloads) | ForEach-Object {$_[1]})
    while($queue.Count) {
        $directory=Assert-BootstrapPath ($queue.Dequeue());$visited++
        if($visited -gt 64) { throw 'Negative evidence directory count exceeds its bound.' }
        foreach($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            $path=Assert-BootstrapPath $item.FullName
            if($item.PSIsContainer) { $queue.Enqueue($path);continue }
            $relative=$path.Substring($StageDirectory.Length+1).Replace('\','/')
            if($relative -cin $payloadNames) { continue }
            if($item.Length -gt 2097152 -or $files.Count -ge 512) { throw 'Negative evidence file count/size exceeds its bound.' }
            $bytes=[IO.File]::ReadAllBytes($path);$total+=$bytes.Length
            if($bytes.Length -ne $item.Length -or $total -gt 33554432) { throw 'Negative evidence changed size or exceeds its aggregate bound.' }
            $files.Add([ordered]@{name=$relative;length=$bytes.Length;sha256=(Bootstrap-Hash $bytes);bytes_base64=[Convert]::ToBase64String($bytes)})
        }
    }
    return ([ordered]@{run=$Run;files=@($files.ToArray())} | ConvertTo-Json -Depth 8 -Compress)
}

$identity=$IdentityJson | ConvertFrom-Json
Assert-BootstrapIdentity $identity
if($Action -ceq 'Stage') {
    if(Test-Path -LiteralPath $StageDirectory) { throw 'Negative staging already exists; no replay is allowed.' }
    $payloads=[ordered]@{}
    foreach($item in Get-BootstrapPayloads) {
        if($identity.($item[0]).Length -gt [Math]::Ceiling([double]$item[3]/3)*4) { throw 'Negative staging payload exceeds its bound.' }
        $bytes=[Convert]::FromBase64String($identity.($item[0]))
        if($bytes.Length -gt $item[3] -or (Bootstrap-Hash $bytes) -cne $identity.($item[2])) { throw 'Negative staging payload size/hash differs.' }
        $payloads[$item[1]]=$bytes
    }
    [void][IO.Directory]::CreateDirectory($StageDirectory)
    Write-BootstrapBytes (Join-Path $StageDirectory 'owner.txt') ([Text.Encoding]::UTF8.GetBytes($Run))
    foreach($name in $payloads.Keys) { Write-BootstrapBytes (Join-Path $StageDirectory $name) $payloads[$name] }
    Assert-BootstrapStaging $identity
    Write-Output 'staged'
} elseif($Action -ceq 'Run') {
    Assert-BootstrapStaging $identity
    Assert-NegativeProcessesAbsent
    $guest=Assert-BootstrapPath (Join-Path $StageDirectory 'guest-clone-config-negative.ps1')
    & $guest -Mode Run -StageDirectory $StageDirectory -Run $Run -ExpectedScriptSHA256 $identity.guest_sha256 -NativeExecutable (Join-Path $StageDirectory 'clone-config-helper.exe') -HelperSource (Join-Path $StageDirectory 'clone-config-helper.go') -ProcessTimeoutSeconds $ProcessTimeoutSeconds
} else {
    Capture-NegativeEvidence $identity
}
