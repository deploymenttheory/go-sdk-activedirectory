#Requires -Version 5.1
# Offline function/AST tests only. No wrapper entry point, VM, AD, or child executes.
param([string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:checks=0
function Check([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message };$script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $failed=$false;try { & $Action } catch { $failed=$true };Check $failed $Message }
function Clone($Value) { return ($Value | ConvertTo-Json -Depth 40 | ConvertFrom-Json) }
function Get-ScriptAST([string]$Path) { $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors);if($errors.Count) { throw ($errors | Out-String) };return $ast }
function Find-Function($AST,[string]$Name) { $found=@($AST.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $Name);if($found.Count -ne 1) { throw "Function cardinality: $Name" };return $found[0].Extent.Text }
function Import-Functions($AST,[string[]]$Names) {
    foreach($name in $Names) {
        $text=Find-Function $AST $name
        # AST-created blocks have no script filename. Supply only the original
        # script-directory automatic variable for this read-only build check.
        if($name -ceq 'Assert-OnlineBuild') { $text=$text.Replace('$PSScriptRoot',("'"+$PSScriptRoot.Replace("'","''")+"'")) }
        $text=$text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name);. ([scriptblock]::Create($text))
    }
}
$hostPath=Join-Path $PSScriptRoot 'run-clone-config-online-qualification.ps1';$bootstrapPath=Join-Path $PSScriptRoot 'bootstrap-clone-config-online-qualification.ps1';$guestPath=Join-Path $PSScriptRoot 'guest-clone-config-online-qualification.ps1'
$sourceHashes=[ordered]@{}
foreach($path in @($hostPath,$bootstrapPath,$guestPath,$PSCommandPath)) { $sourceHashes[$path]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
$hostAST=Get-ScriptAST $hostPath;$bootstrapAST=Get-ScriptAST $bootstrapPath;$guestAST=Get-ScriptAST $guestPath
$previousPath=Join-Path $PSScriptRoot 'run-clone-config-offline.ps1';$previousAST=Get-ScriptAST $previousPath
Check ((Get-FileHash -LiteralPath $previousPath -Algorithm SHA256).Hash -ceq '116353985A315D63E60B16B3386B8E305B965F9D36FEA131D80A6B8F999C06BE') 'Approved guard source changed.'
foreach($name in @('Assert-UnlinkedPath','Assert-OwnedControllers','Assert-SwitchPorts','Write-NewHostJson','Write-NewHostBytes','Get-ProfileMutexName','Write-RunState','Wait-OwnedJob','Invoke-OwnedGuest','Assert-NewRunDirectory')) {
    Check ((Find-Function $hostAST $name) -ceq (Find-Function $previousAST $name)) "Reviewed guard/job changed: $name"
}
$common=@('Get-OnlinePins','Get-OnlinePayloads','Assert-OnlineIdentity','Get-OnlineCaseNames','Assert-OnlineMatrixState','Assert-OnlineOutcome')
foreach($name in $common) { Check ((Find-Function $hostAST $name) -ceq (Find-Function $bootstrapAST $name)) "Host/bootstrap contract differs: $name" }
Import-Functions $hostAST ($common+@('Assert-UnlinkedPath','Write-NewHostBytes','Write-NewHostJson','Assert-OnlineBuild','Read-OnlineOutcome','Test-OnlineEvidenceName','Save-OnlineCapture','Wait-OwnedJob','Invoke-OwnedGuest'))
Import-Functions $bootstrapAST @('Assert-OnlineStagePath','Assert-OnlineBootstrapIdentity','Online-Hash','Assert-OnlineProcessesAbsent','Assert-OnlineAttemptFiles','Get-OnlineCapture')
$guestNames=& ([scriptblock]::Create((Find-Function $guestAST 'Get-OnlineCaseNames')+[Environment]::NewLine+'Get-OnlineCaseNames'))
Check (((Get-OnlineCaseNames) -join ',') -ceq ($guestNames -join ',')) 'Host/guest case order differs.'
foreach($ast in @($hostAST,$bootstrapAST)) {
    $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    foreach($forbidden in @('Start-VM','Stop-VM','Restart-VM','Remove-VM','Set-Acl','Set-ADObject','Add-ADGroupMember','Remove-ADGroupMember','Remove-Item','Stop-Process','New-ADDCCloneConfigFile')) { Check ($forbidden -notin $commands) "Host/bootstrap contains forbidden action: $forbidden" }
    Check ($ast.Extent.Text -notmatch '\.Kill\(') 'Host/bootstrap kills an uncertain child.'
}
Check ($bootstrapAST.Extent.Text.Contains('& $guest -Mode Run -StageDirectory $StageDirectory')) 'Bootstrap must invoke the staged guest file.'
Check ($hostAST.Extent.Text.Contains('Invoke-OwnedGuest -FilePath $snapshot')) 'Host must invoke its pinned bootstrap snapshot.'
foreach($pair in @(@('guest-return.json','Read-OnlineOutcome $returned'),@('capture-return.json','Save-OnlineCapture $captured'))) {
    $rawOffset=$hostAST.Extent.Text.IndexOf("'"+$pair[0]+"'",[StringComparison]::Ordinal);$proofOffset=$hostAST.Extent.Text.IndexOf($pair[1],[StringComparison]::Ordinal)
    Check ($rawOffset -gt 0 -and $proofOffset -gt $rawOffset) 'Raw envelope must precede outcome interpretation.'
}
$pins=Get-OnlinePins;$identity=[ordered]@{}
foreach($name in $pins.Keys) { if($name -cne 'build_root') { $identity[$name]=$pins[$name] } }
$identity.harness_sha256=(Get-FileHash -LiteralPath $guestPath -Algorithm SHA256).Hash
Assert-OnlineIdentity $identity;$script:checks++
foreach($name in $identity.Keys) { $bad=Clone $identity;$bad.$name='invalid';Reject { Assert-OnlineIdentity $bad } "Altered identity accepted: $name" }
$payloads=@(Get-OnlinePayloads)
Check ($payloads.Count -eq 9) 'Online payload cardinality differs.'
Check ((@($payloads | ForEach-Object {$_[1]}) -join ',') -ceq 'guest-clone-config-online-qualification.ps1,clone-config-helper.exe,clone-config-helper.go,build.json,helper-v3-build.json,inventory.json,negative-process-support.ps1,inventory-support.ps1,schema-evidence.json') 'Online staged payload names differ.'
Check ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1') -Algorithm SHA256).Hash -ceq $pins.process_support_sha256) 'Frozen process support changed.'
Check ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'get-clone-config-online-prerequisites.ps1') -Algorithm SHA256).Hash -ceq $pins.inventory_support_sha256) 'Frozen readonly inventory support changed.'
# Read-only validation of the immutable local build. No guest/VM access occurs.
$paths=[ordered]@{
    guest=$guestPath
    helper=(Join-Path $pins.build_root 'helper-v3\clone-config-helper.exe')
    source=(Join-Path $pins.build_root 'helper-v3\clone-config-helper.go')
    build=(Join-Path $pins.build_root 'build.json')
    helper_build=(Join-Path $pins.build_root 'helper-v3\build.json')
    inventory=(Join-Path $pins.build_root 'server2025-online-inventory-v1\inventory.json')
    process_support=(Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1')
    inventory_support=(Join-Path $PSScriptRoot 'get-clone-config-online-prerequisites.ps1')
    schema=(Join-Path $pins.build_root 'source\docs\research\dc-cloning-evidence\server2025-readonly.json')
}
Assert-OnlineBuild $paths $identity;$script:checks++
$differentPaths=[ordered]@{};foreach($key in $paths.Keys) {$differentPaths[$key]=$paths[$key]};$differentPaths.helper=$paths.source
Reject { Assert-OnlineBuild $differentPaths $identity } 'Different build source path accepted.'
$Run=$identity.run;$StageDirectory=Join-Path 'C:\ad-sdk-validation' $Run
$savedComputer=$env:COMPUTERNAME
try {
    $env:COMPUTERNAME='ADSDK25DC1';Assert-OnlineBootstrapIdentity $identity;$script:checks++
    Reject { Assert-OnlineStagePath (Join-Path $StageDirectory '..\escape') } 'Staging path traversal accepted.'
    Reject { Assert-OnlineStagePath 'C:\Windows\NTDS' } 'Supported output accepted as staging.'
    $env:COMPUTERNAME='OTHER';Reject { Assert-OnlineBootstrapIdentity $identity } 'Wrong guest accepted.'
} finally { $env:COMPUTERNAME=$savedComputer }
$stream=[Text.Encoding]::UTF8.GetBytes('raw process bytes');$streamHash=Online-Hash $stream
$process=[pscustomobject]@{pid=42;started_utc='2026-11-12T23:00:00Z';completed=$true;process_uncertain=$false;exit_code=0;stdout_sha256=$streamHash;stderr_sha256=$streamHash}
$cases=@(Get-OnlineCaseNames | ForEach-Object {
    $kind=if($_ -in @('add-direct-membership','remove-direct-membership')){'membership'}elseif($_ -like '*-sdk*'){'sdk'}else{'reference'}
    $observation=if($kind -ceq 'reference'){[pscustomobject]@{completed=$true;streams_sha256=$streamHash}}else{[pscustomobject]@{completed=$true}}
    $exists=($_ -in @('online-sdk-success','online-sdk-existing','online-reference-existing','online-reference-success'))
    [pscustomobject]@{name=$_;kind=$kind;process=(Clone $process);observation=$observation;output_before=$null;output_after=[pscustomobject]@{exists=$exists;sha256=$(if($exists){$streamHash}else{$null})};passed=$true;error=$null}
})
$outcome=[ordered]@{schema_version=1;computer='ADSDK25DC1';completed=$true;passed=$true;cleanup_complete=$true;staging_preserved=$true;process_uncertain=$false;publication_uncertain=$false;mutation_uncertain=$false;capture_failed=$false;error=$null;recovery=[ordered]@{group_added=$false;intent=$null;custom_file=$null;config_file=$null};cases=$cases}
foreach($name in $identity.Keys) { $outcome[$name]=$identity[$name] };$outcome=Clone $outcome
$null=Read-OnlineOutcome ($outcome|ConvertTo-Json -Depth 40 -Compress) $identity;$script:checks++
foreach($mutation in @(
    {$bad.process_uncertain=$true},{$bad.publication_uncertain=$true},{$bad.mutation_uncertain=$true},{$bad.capture_failed=$true},
    {$bad.completed='true'},{$bad.passed='true'},{$bad.cleanup_complete='true'},{$bad.cleanup_complete=$false},{$bad.staging_preserved=$false},
    {$bad.cases=$bad.cases[0..8]},{$bad.cases[0].name=$bad.cases[1].name},{$bad.cases[0].kind='reference'},
    {$bad.cases[0].process=$null},{$bad.cases[0].process.completed=$false},{$bad.cases[0].process.process_uncertain=$true},
    {$bad.cases[0].process.pid=0},{$bad.cases[0].process.started_utc=$null},{$bad.cases[0].process.exit_code=$null},
    {$bad.cases[0].process.stdout_sha256='bad'},{$bad.cases[0].process.stderr_sha256='bad'},{$bad.cases[0].passed=$false},
    {$bad.cases[0].error='contradiction'},{$bad.recovery=$null},{$bad.source_commit='different'},{$bad.schema_version=2},{$bad.computer='OTHER'}
)) {
    $bad=Clone $outcome;& $mutation;$script:guestUncertain=$false
    Reject { Read-OnlineOutcome ($bad|ConvertTo-Json -Depth 40 -Compress) $identity } 'Invalid online outcome accepted.'
    Check $script:guestUncertain 'Invalid online outcome did not block further guest work.'
    Reject { Assert-OnlineOutcome $bad $identity } 'Bootstrap accepted invalid online outcome.'
}
$partial=Clone $outcome;$partial.completed=$false;$partial.passed=$false;$partial.cleanup_complete=$false;$partial.error='known failure';$partial.cases=@($partial.cases[0..3]);$partial.cases[-1].passed=$false;$partial.cases[-1].error='known failure'
Assert-OnlineOutcome $partial $identity;$script:checks++
$unstarted=Clone $partial;$unstarted.cases[-1].process=$null;$unstarted.cases[-1].observation=$null;$unstarted.cases[-1].output_after=$null
Assert-OnlineOutcome $unstarted $identity;$script:checks++
$empty=Clone $partial;$empty.cases=@();Assert-OnlineOutcome $empty $identity;$script:checks++
$bad=Clone $partial;$bad.cases[0].passed=$false;Reject { Assert-OnlineOutcome $bad $identity } 'Work after failed case accepted.'
$bad=Clone $partial;$bad.cases[0].process=$null;Reject { Assert-OnlineOutcome $bad $identity } 'Missing preceding child accepted.'
$bad=Clone $partial;$bad.error=$null;Reject { Assert-OnlineOutcome $bad $identity } 'Incomplete outcome without error accepted.'
$bad=Clone $partial;$bad.passed=$true;Reject { Assert-OnlineOutcome $bad $identity } 'Failed prefix promoted to success.'
function Assert-OwnedControllers { throw 'VM guard must never execute in offline tests.' }
$script:guestUncertain=$true;Reject { Invoke-OwnedGuest -Script {} -Arguments @() -TimeoutSeconds 1 -Action 'blocked' } 'Uncertainty allowed another guest operation.'
$runState=[ordered]@{jobs=@()};$script:removed=$false
function Write-RunState {}
function Wait-Job { param($Job,$Timeout) return $Job }
function Remove-Job { param($Job,$ErrorAction) $script:removed=$true }
$job=[pscustomobject]@{Id=42;State='Running';stops=0};$job|Add-Member ScriptMethod StopJobAsync {$this.stops++}
$script:guestUncertain=$false;Reject { Wait-OwnedJob $job 0 'timeout' } 'Running job deadline accepted.'
Check ($script:guestUncertain -and $job.stops -eq 1 -and -not $script:removed) 'Timeout retried or removed a live job.'
$script:mockProcesses=@()
function Get-CimInstance { param([string]$ClassName,[string]$Filter,[int]$OperationTimeoutSec,[string]$ErrorAction) Check ($ClassName -ceq 'Win32_Process' -and $Filter -ceq "Name='clone-config-helper.exe' OR Name='powershell.exe'" -and $OperationTimeoutSec -eq 10 -and $ErrorAction -ceq 'Stop') 'Process absence query is not bounded.';return $script:mockProcesses }
Assert-OnlineProcessesAbsent;$script:checks++
foreach($row in @(
    [pscustomobject]@{Name='clone-config-helper.exe';ExecutablePath=(Join-Path $StageDirectory 'clone-config-helper.exe');CommandLine='helper'},
    [pscustomobject]@{Name='clone-config-helper.exe';ExecutablePath=$null;CommandLine='helper'},
    [pscustomobject]@{Name='powershell.exe';ExecutablePath='powershell';CommandLine=('-File "'+(Join-Path $StageDirectory 'guest-clone-config-online-qualification.ps1')+'"')},
    [pscustomobject]@{Name='powershell.exe';ExecutablePath='powershell';CommandLine=$null}
)) { $script:mockProcesses=@($row);Reject { Assert-OnlineProcessesAbsent } 'Owned or unidentifiable child did not block capture.' }
$script:mockProcesses=@([pscustomobject]@{Name='clone-config-helper.exe';ExecutablePath='C:\unrelated\clone-config-helper.exe';CommandLine='other'},[pscustomobject]@{Name='powershell.exe';ExecutablePath='powershell';CommandLine='-NoProfile -Command unrelated'})
Assert-OnlineProcessesAbsent;$script:checks++
foreach($name in @('owner.txt','online-cases/summary.json','online-cases/events/0001-before-add-direct-membership.json','online-cases/snapshots/0001-world.json','online-cases/online-sdk-success/output.xml','online-cases/missing-group-sdk/output/DCCloneConfig.xml')) { Check (Test-OnlineEvidenceName $name) 'Known online evidence rejected.' }
foreach($name in @('../escape','online-cases/../escape','online-cases/foreign/result.json','online-cases/online-sdk-success/child.stdout.txt:stream','C:/escape','online-cases/online-sdk-success/unknown.json','online-cases/events/../escape.json','online-cases/events/0001-UPPER.json','owner.txt:stream')) { Check (-not (Test-OnlineEvidenceName $name)) 'Unsafe evidence name accepted.' }
$fixtureRoot=Join-Path $PSScriptRoot ('clone-config-online-host-tests-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixtureRoot)
function Raw-File([string]$Name,[byte[]]$Bytes) { return [pscustomobject]@{name=$Name;length=$Bytes.Length;sha256=(Online-Hash $Bytes);bytes_base64=[Convert]::ToBase64String($Bytes)} }
function Json-Bytes($Value) { return ,[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 40 -Compress)) }
function New-CaptureFixture($Summary) {
    $files=[Collections.Generic.List[object]]::new()
    foreach($name in @('owner.txt','online-cases/owner.txt')) { $files.Add((Raw-File $name ([Text.Encoding]::UTF8.GetBytes($Run)))) }
    foreach($name in @('online-cases/started.json','online-cases/summary.json')) { $files.Add((Raw-File $name (Json-Bytes $Summary))) }
    foreach($case in $Summary.cases) {
        $prefix='online-cases/'+$case.name+'/'
        $files.Add((Raw-File ($prefix+'case.json') (Json-Bytes $case)))
        if($null -ne $case.process) {
            foreach($suffix in @('requested.json','started.json','finished.json')) { $files.Add((Raw-File ($prefix+'child.'+$suffix) (Json-Bytes $case.process))) }
            foreach($suffix in @('stdout.txt','stderr.txt')) { $files.Add((Raw-File ($prefix+'child.'+$suffix) $stream)) }
            if($case.kind -ceq 'sdk') { $files.Add((Raw-File ($prefix+'options.json') (Json-Bytes @{Offline=$false}))) }
        }
        if($null -ne $case.observation -and $case.kind -cne 'sdk') {
            $name=if($case.kind -ceq 'reference'){'reference.json'}else{'membership.json'}
            $files.Add((Raw-File ($prefix+$name) (Json-Bytes $case.observation)))
            if($case.kind -ceq 'reference') { $files.Add((Raw-File ($prefix+'reference.streams.txt') $stream)) }
        }
        if($null -ne $case.output_after -and $case.output_after.exists) { $files.Add((Raw-File ($prefix+'output.xml') $stream)) }
        $files.Add((Raw-File ($prefix+'result.json') (Json-Bytes $case)))
    }
    return [pscustomobject]@{run=$Run;files=@($files.ToArray())}
}
function Save-Fixture($Capture,$Summary) {
    $script:resultRoot=Join-Path $fixtureRoot ([guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($script:resultRoot)
    $script:runState=[ordered]@{captures=[ordered]@{}}
    Save-OnlineCapture ($Capture|ConvertTo-Json -Depth 40 -Compress) $Summary $identity
}
$capture=New-CaptureFixture $outcome
Save-Fixture $capture $outcome;$script:checks++
Check ($runState.captures.Count -eq $capture.files.Count) 'Not all raw files retained.'
Save-Fixture (New-CaptureFixture $partial) $partial;$script:checks++
Save-Fixture (New-CaptureFixture $unstarted) $unstarted;$script:checks++
Save-Fixture (New-CaptureFixture $empty) $empty;$script:checks++
foreach($mutation in @(
    {$bad.run='other'},
    {$bad.files[0].name='../escape'},
    {$bad.files[1].name=$bad.files[0].name},
    {$bad.files[0].sha256='A'*64},
    {$bad.files[0].length++},
    {$bad.files[0].length=2097153},
    {$bad.files[0].bytes_base64='!'},
    {$bad.files=@($bad.files|Where-Object name -cne 'online-cases/summary.json')},
    {$bad.files=@($bad.files|Where-Object name -cne 'online-cases/missing-group-sdk/child.stdout.txt')},
    {$bad.files=@($bad.files|Where-Object name -cne 'online-cases/missing-group-sdk/options.json')},
    {$bad.files=@($bad.files|Where-Object name -cne 'online-cases/missing-group-sdk/result.json')},
    {$bad.files=@($bad.files|Where-Object name -cne 'online-cases/missing-group-reference/reference.json')},
    {$bad.files=@($bad.files|Where-Object name -cne 'online-cases/missing-group-reference/reference.streams.txt')},
    {$bad.files=@($bad.files|Where-Object name -cne 'online-cases/add-direct-membership/membership.json')},
    {$bad.files=@($bad.files|Where-Object name -cne 'online-cases/online-sdk-success/output.xml')},
    {$bad.files[0]=Raw-File 'owner.txt' ([Text.Encoding]::UTF8.GetBytes('foreign'))},
    {$index=[array]::IndexOf(@($bad.files.name),'online-cases/missing-group-sdk/child.finished.json');$different=Clone $process;$different.pid=43;$bad.files[$index]=Raw-File $bad.files[$index].name (Json-Bytes $different)},
    {$index=[array]::IndexOf(@($bad.files.name),'online-cases/missing-group-sdk/child.stdout.txt');$bad.files[$index]=Raw-File $bad.files[$index].name ([Text.Encoding]::UTF8.GetBytes('different'))},
    {$index=[array]::IndexOf(@($bad.files.name),'online-cases/missing-group-reference/reference.json');$bad.files[$index]=Raw-File $bad.files[$index].name (Json-Bytes @{changed=$true})},
    {$index=[array]::IndexOf(@($bad.files.name),'online-cases/online-sdk-success/output.xml');$bad.files[$index]=Raw-File $bad.files[$index].name ([Text.Encoding]::UTF8.GetBytes('different'))}
)) {
    $bad=Clone $capture;& $mutation;Reject { Save-Fixture $bad $outcome } 'Malformed or incomplete raw capture accepted.'
}
$bad=New-CaptureFixture $partial;$bad.files+=@(Raw-File 'online-cases/online-reference-success/child.requested.json' $stream)
Reject { Save-Fixture $bad $partial } 'Unreported attempt captured.'
$bad=New-CaptureFixture $unstarted;$bad.files+=@(Raw-File 'online-cases/excluded-apps-sdk/child.requested.json' $stream)
Reject { Save-Fixture $bad $unstarted } 'Unstarted case with child attempt accepted.'
$bad=New-CaptureFixture $partial;$bad.files=@($bad.files|Where-Object name -cne 'online-cases/excluded-apps-sdk/result.json')
Save-Fixture $bad $partial;$script:checks++
$bad=Clone $capture;$bad.files=@($bad.files[0..2]);Reject { Save-Fixture $bad $outcome } 'Undersized capture accepted.'
$bad=Clone $capture;$bad.files=@(1..513|ForEach-Object {$capture.files[0]});Reject { Save-Fixture $bad $outcome } 'Oversized capture accepted.'
# Mock only the staging-path boundary for local fixture capture. Real path checks
# above remain covered; all subsequent filesystem reads stay beneath fixtureRoot.
$StageDirectory=Join-Path $fixtureRoot 'guest-staging';[void][IO.Directory]::CreateDirectory($StageDirectory)
function Assert-OnlineStagePath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if($full -cne $StageDirectory -and -not $full.StartsWith($StageDirectory+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Test fixture escape.' }
    if((Test-Path -LiteralPath $full) -and ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Test fixture reparse.' }
    return $full
}
function Assert-OnlineStaging($Identity) { Assert-OnlineIdentity $Identity }
$script:mockProcesses=@()
foreach($file in (New-CaptureFixture $unstarted).files) {
    $path=Join-Path $StageDirectory $file.name;[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path));[IO.File]::WriteAllBytes($path,[Convert]::FromBase64String($file.bytes_base64))
}
Assert-OnlineAttemptFiles $unstarted;$script:checks++
$returned=Get-OnlineCapture $identity|ConvertFrom-Json
Check ($returned.files.Count -eq (New-CaptureFixture $unstarted).files.Count) 'Bootstrap failed to capture known failed prefix.'
$unreported=Join-Path $StageDirectory 'online-cases\online-reference-success';[void][IO.Directory]::CreateDirectory($unreported)
[IO.File]::WriteAllText((Join-Path $unreported 'child.requested.json'),'{}')
Reject { Assert-OnlineAttemptFiles $unstarted } 'Bootstrap accepted hidden child attempt.'
Reject { Get-OnlineCapture $identity } 'Bootstrap captured after hidden child attempt.'
foreach($path in $sourceHashes.Keys) { Check ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $sourceHashes[$path]) 'Source changed during offline tests; this report must not be emitted.' }
$report=[ordered]@{schema_version=1;mode='offline AST and fixture tests only';powershell=$PSVersionTable.PSVersion.ToString();checks=$script:checks;passed=$true;host_sha256=(Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash;bootstrap_sha256=(Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256).Hash;guest_sha256=(Get-FileHash -LiteralPath $guestPath -Algorithm SHA256).Hash;test_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;fixture_root=$fixtureRoot;vm_or_ad_actions=$false;completed_utc=[DateTime]::UtcNow.ToString('o')}
if($OutputPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($report|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false)) }
$report|ConvertTo-Json -Depth 8
