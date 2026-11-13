#Requires -Version 5.1
# PSDirect transport only. This bootstrap never alters AD or supported clone files.
# It invokes the reviewed staged guest file and retains all evidence.
param(
    [Parameter(Mandatory)][ValidateSet('Stage','Run','Capture')][string]$Action,
    [Parameter(Mandatory)][string]$StageDirectory,
    [Parameter(Mandatory)][string]$Run,
    [Parameter(Mandatory)][string]$IdentityJson,
    [ValidateRange(1,300)][int]$ProcessTimeoutSeconds=60,
    [ValidateRange(1,300)][int]$ReplicationTimeoutSeconds=90
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest

function Get-OnlinePins {
    return [ordered]@{
        build_root='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T232022Z-008266ad'
        run='clone-config-reviewed-20261112T232022Z-008266ad-online-qualification-server2025-v3'
        source_commit='59346e9641feada4915a3313273ee2fc845bdbeb'
        source_archive_sha256='D8D05B12B9678D0B11A7EA5081FEE24FAD4B9C44E185F1C91DECD2228B9E8B05'
        build_manifest_sha256='386ECB6700D11F28EBD4B4A9033392A9DAD03968AC0E5BE2E7AB60859E1F141F'
        helper_build_manifest_sha256='362DE5A85947FFDE1DB6571617F5AA908037553661F899B6A32E4E22DF38E377'
        helper_source_sha256='F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1'
        helper_binary_sha256='09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957'
        inventory_sha256='12280A1773B53B317BDEC242362B79DC8E9AF44BAC7ECA8555822B5868B63A23'
        process_support_sha256='2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D'
        inventory_support_sha256='69BA8CE559775192047F61105499AB23917721188C588F29A9BE1D6B4E2FCF68'
        schema_evidence_sha256='A061F397D27B26563E6B4C7D611F707F5A3CA4A5B9CBD3353CB2CDC7BA9D7F35'
    }
}
function Get-OnlinePayloads {
    return @(
        @('guest','guest-clone-config-online-qualification.ps1','harness_sha256',1048576),
        @('helper','clone-config-helper.exe','helper_binary_sha256',33554432),
        @('source','clone-config-helper.go','helper_source_sha256',1048576),
        @('build','build.json','build_manifest_sha256',1048576),
        @('helper_build','helper-v4-build.json','helper_build_manifest_sha256',1048576),
        @('inventory','inventory.json','inventory_sha256',2097152),
        @('process_support','negative-process-support.ps1','process_support_sha256',1048576),
        @('inventory_support','inventory-support.ps1','inventory_support_sha256',1048576),
        @('schema','schema-evidence.json','schema_evidence_sha256',4194304)
    )
}
function Assert-OnlineIdentity($Identity) {
    $pins=Get-OnlinePins
    foreach($name in $pins.Keys) {
        if($name -ceq 'build_root') { continue }
        if($Identity.$name -isnot [string] -or $Identity.$name -cne $pins[$name]) { throw 'Online qualification identity differs.' }
    }
    if($Identity.harness_sha256 -isnot [string] -or $Identity.harness_sha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'Online guest digest is missing.' }
}
function Get-OnlineCaseNames {
    return @('missing-group-sdk','missing-group-reference','add-direct-membership','excluded-apps-sdk','excluded-apps-reference','online-sdk-success','online-sdk-existing','online-reference-existing','online-reference-success','remove-direct-membership')
}
function Assert-OnlineMatrixState($Summary) {
    $names=Get-OnlineCaseNames;$cases=@($Summary.cases)
    foreach($name in @('completed','passed','cleanup_complete','staging_preserved','process_uncertain','publication_uncertain','mutation_uncertain','capture_failed')) {
        if($Summary.$name -isnot [bool]) { throw 'Online outcome contains an untyped safety state.' }
    }
    if(-not $Summary.staging_preserved -or $Summary.process_uncertain -or $Summary.publication_uncertain -or $Summary.mutation_uncertain -or $Summary.capture_failed -or
        $null -eq $Summary.cases -or $null -eq $Summary.recovery -or $cases.Count -gt $names.Count -or
        ($Summary.completed -and $cases.Count -ne $names.Count) -or
        (-not $Summary.completed -and ($Summary.passed -or $null -eq $Summary.error)) -or
        ($Summary.passed -and (-not $Summary.completed -or -not $Summary.cleanup_complete -or $null -ne $Summary.error))) { throw 'Online outcome is uncertain or is not a known terminal result.' }
    for($index=0;$index -lt $cases.Count;$index++) {
        $case=$cases[$index];$name=$names[$index]
        $kind=if($name -in @('add-direct-membership','remove-direct-membership')){'membership'}elseif($name -like '*-sdk*'){'sdk'}else{'reference'}
        if($case.name -cne $name -or $case.kind -cne $kind -or $case.passed -isnot [bool] -or ($Summary.passed -and -not $case.passed)) { throw 'Online case sequence or success differs.' }
        $partialLast=(-not $Summary.completed -and $index -eq $cases.Count-1 -and -not $case.passed)
        if((-not $case.passed -and -not $partialLast) -or ($case.passed -and $null -ne $case.error)) { throw 'Online work continued after a failed case or success retains an error.' }
        $process=$case.process
        if($null -eq $process) {
            if(-not $partialLast) { throw 'Completed online case lacks its child record.' }
            continue
        }
        if($process.completed -isnot [bool] -or -not $process.completed -or $process.process_uncertain -isnot [bool] -or $process.process_uncertain -or
            $process.pid -le 0 -or -not $process.started_utc -or $null -eq $process.exit_code -or
            $process.stdout_sha256 -cnotmatch '^[A-F0-9]{64}$' -or $process.stderr_sha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'An online child has uncertain completion or missing raw streams.' }
    }
}
function Assert-OnlineOutcome($Summary,$Identity) {
    Assert-OnlineIdentity $Identity
    if($Summary.schema_version -ne 1 -or $Summary.computer -cne 'ADSDK25DC1') { throw 'Online outcome schema or computer differs.' }
    foreach($name in @('run','source_commit','source_archive_sha256','build_manifest_sha256','helper_build_manifest_sha256','helper_source_sha256','helper_binary_sha256','harness_sha256','inventory_sha256','process_support_sha256','inventory_support_sha256','schema_evidence_sha256')) {
        if($Summary.$name -isnot [string] -or $Summary.$name -cne $Identity.$name) { throw 'Online outcome provenance differs.' }
    }
    Assert-OnlineMatrixState $Summary
}

function Assert-OnlineStagePath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path);$stage=[IO.Path]::GetFullPath($StageDirectory)
    if($stage -cne (Join-Path 'C:\ad-sdk-validation' $Run) -or ($full -cne $stage -and -not $full.StartsWith($stage+'\',[StringComparison]::OrdinalIgnoreCase))) { throw 'Online staging path escaped its owned root.' }
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Online staging traverses a reparse point.' }
    }
    return $full
}
function Assert-OnlineBootstrapIdentity($Identity) {
    Assert-OnlineIdentity $Identity
    if($env:COMPUTERNAME -cne 'ADSDK25DC1' -or $Run -cne $Identity.run) { throw 'Online bootstrap target differs.' }
    $null=Assert-OnlineStagePath $StageDirectory
}
function Online-Hash([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','') } finally { $hasher.Dispose() }
}
function Write-OnlineStageBytes([string]$Path,[byte[]]$Bytes) {
    $path=Assert-OnlineStagePath $Path
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
}
function Assert-OnlineStaging($Identity) {
    Assert-OnlineBootstrapIdentity $Identity
    if([IO.File]::ReadAllText((Assert-OnlineStagePath (Join-Path $StageDirectory 'owner.txt'))) -cne $Run) { throw 'Online staging owner differs.' }
    foreach($item in Get-OnlinePayloads) {
        $path=Assert-OnlineStagePath (Join-Path $StageDirectory $item[1])
        if((Get-Item -LiteralPath $path).Length -gt $item[3] -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $Identity.($item[2])) { throw 'Staged online source digest or size differs.' }
    }
}
function Assert-OnlineProcessesAbsent {
    $helper=Join-Path $StageDirectory 'clone-config-helper.exe';$guest=Join-Path $StageDirectory 'guest-clone-config-online-qualification.ps1'
    foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='clone-config-helper.exe' OR Name='powershell.exe'" -OperationTimeoutSec 10 -ErrorAction Stop)) {
        if($process.Name -ieq 'clone-config-helper.exe') {
            if(-not $process.ExecutablePath -or [string]::Equals($process.ExecutablePath,$helper,[StringComparison]::OrdinalIgnoreCase)) { throw 'An owned or unidentifiable online helper remains.' }
        } elseif(-not $process.CommandLine -or $process.CommandLine.IndexOf($guest,[StringComparison]::OrdinalIgnoreCase) -ge 0) { throw 'An owned or unidentifiable online reference/membership child remains.' }
    }
}
function Assert-OnlineAttemptFiles($Summary) {
    $cases=@{}
    foreach($case in $Summary.cases) { $cases[$case.name]=$case }
    foreach($name in Get-OnlineCaseNames) {
        $case=$null;if($cases.ContainsKey($name)) { $case=$cases[$name] }
        if($null -ne $case -and $null -ne $case.process) { continue }
        $directory=Join-Path (Join-Path $StageDirectory 'online-cases') $name
        foreach($suffix in @('.requested.json','.started.json','.finished.json','.stdout.txt','.stderr.txt')) {
            if(Test-Path -LiteralPath (Assert-OnlineStagePath (Join-Path $directory ('child'+$suffix)))) { throw 'Unreported online child attempt prohibits capture.' }
        }
    }
}
function Get-OnlineCapture($Identity) {
    Assert-OnlineStaging $Identity
    $path=Assert-OnlineStagePath (Join-Path $StageDirectory 'online-cases\summary.json')
    if((Get-Item -LiteralPath $path).Length -gt 2097152) { throw 'Online recovery summary exceeds its capture bound.' }
    $summary=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    Assert-OnlineOutcome $summary $Identity
    Assert-OnlineAttemptFiles $summary
    Assert-OnlineProcessesAbsent
    $payloadNames=@((Get-OnlinePayloads)|ForEach-Object {$_[1]})
    $files=[Collections.Generic.List[object]]::new();$queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($StageDirectory)
    $visited=0;$total=0L
    while($queue.Count) {
        $directory=Assert-OnlineStagePath ($queue.Dequeue());$visited++
        if($visited -gt 64) { throw 'Online evidence directory bound exceeded.' }
        foreach($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            $path=Assert-OnlineStagePath $item.FullName
            if($item.PSIsContainer) { $queue.Enqueue($path);continue }
            $relative=$path.Substring($StageDirectory.Length+1).Replace('\','/')
            if($relative -cin $payloadNames) { continue }
            if($item.Length -gt 2097152 -or $files.Count -ge 512) { throw 'Online evidence file count or size exceeds its bound.' }
            $bytes=[IO.File]::ReadAllBytes($path);$total+=$bytes.Length
            if($bytes.Length -ne $item.Length -or $total -gt 33554432) { throw 'Online evidence changed size or exceeds its total bound.' }
            $files.Add([ordered]@{name=$relative;length=$bytes.Length;sha256=(Online-Hash $bytes);bytes_base64=[Convert]::ToBase64String($bytes)})
        }
    }
    return ([ordered]@{run=$Run;files=@($files.ToArray())}|ConvertTo-Json -Depth 8 -Compress)
}
$identity=$IdentityJson|ConvertFrom-Json
Assert-OnlineBootstrapIdentity $identity
if($Action -ceq 'Stage') {
    if(Test-Path -LiteralPath $StageDirectory) { throw 'Online staging exists; interrupted work is never replayed.' }
    $payloads=[ordered]@{}
    foreach($item in Get-OnlinePayloads) {
        if($identity.($item[0]).Length -gt [Math]::Ceiling([double]$item[3]/3)*4) { throw 'Online staging payload exceeds its bound.' }
        $bytes=[Convert]::FromBase64String($identity.($item[0]))
        if($bytes.Length -gt $item[3] -or (Online-Hash $bytes) -cne $identity.($item[2])) { throw 'Online staging payload digest differs.' }
        $payloads[$item[1]]=$bytes
    }
    [void][IO.Directory]::CreateDirectory($StageDirectory)
    Write-OnlineStageBytes (Join-Path $StageDirectory 'owner.txt') ([Text.UTF8Encoding]::new($false).GetBytes($Run))
    foreach($name in $payloads.Keys) { Write-OnlineStageBytes (Join-Path $StageDirectory $name) $payloads[$name] }
    Assert-OnlineStaging $identity
    Write-Output 'staged'
} elseif($Action -ceq 'Run') {
    Assert-OnlineStaging $identity
    Assert-OnlineProcessesAbsent
    $guest=Assert-OnlineStagePath (Join-Path $StageDirectory 'guest-clone-config-online-qualification.ps1')
    & $guest -Mode Run -StageDirectory $StageDirectory -Run $Run -ExpectedScriptSHA256 $identity.harness_sha256 -NativeExecutable (Join-Path $StageDirectory 'clone-config-helper.exe') -HelperSource (Join-Path $StageDirectory 'clone-config-helper.go') -InventoryPath (Join-Path $StageDirectory 'inventory.json') -ProcessTimeoutSeconds $ProcessTimeoutSeconds -ReplicationTimeoutSeconds $ReplicationTimeoutSeconds
} else {
    Get-OnlineCapture $identity
}

