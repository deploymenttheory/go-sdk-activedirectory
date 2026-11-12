#Requires -Version 5.1
# Offline AST/function tests only; neither wrapper nor guest entry point runs.
param([string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:checks=0
function Check([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message };$script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $failed=$false;try { & $Action } catch { $failed=$true };Check $failed $Message }
function Clone($Value) { return ($Value | ConvertTo-Json -Depth 40 | ConvertFrom-Json) }
function Get-ScriptAST([string]$Path) { $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors);if($errors.Count) { throw ($errors | Out-String) };return $ast }
function Find-Function($AST,[string]$Name) { $found=@($AST.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $Name);if($found.Count -ne 1) { throw "Function cardinality: $Name" };return $found[0].Extent.Text }
function Import-Functions($AST,[string[]]$Names) { foreach($name in $Names) { $text=Find-Function $AST $name;$text=$text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name);. ([scriptblock]::Create($text)) } }
$hostPath=Join-Path $PSScriptRoot 'run-clone-config-negative.ps1';$bootstrapPath=Join-Path $PSScriptRoot 'bootstrap-clone-config-negative.ps1';$guestPath=Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1'
$hostAST=Get-ScriptAST $hostPath;$bootstrapAST=Get-ScriptAST $bootstrapPath;$guestAST=Get-ScriptAST $guestPath
$previousAST=Get-ScriptAST (Join-Path $PSScriptRoot 'run-clone-config-offline.ps1')
foreach($name in @('Assert-UnlinkedPath','Assert-OwnedControllers','Assert-SwitchPorts','Write-NewHostJson','Write-NewHostBytes','Get-ProfileMutexName','Write-RunState','Wait-OwnedJob','Invoke-OwnedGuest','Assert-NewRunDirectory','Assert-Build')) {
    Check ((Find-Function $hostAST $name) -ceq (Find-Function $previousAST $name)) "Reviewed guard/job changed: $name"
}
Import-Functions $hostAST @('Assert-NegativeBuild','Get-NegativeCaseNames','Assert-NegativeMatrixState','Read-NegativeOutcome','Test-NegativeEvidenceName','Save-NegativeCapture','Wait-OwnedJob','Invoke-OwnedGuest','Write-NewHostBytes','Write-NewHostJson')
Import-Functions $bootstrapAST @('Assert-BootstrapPath','Assert-BootstrapIdentity','Bootstrap-Hash','Get-BootstrapPayloads','Assert-NegativeCaptureSafe','Assert-NegativeAttemptFiles','Assert-NegativeProcessesAbsent')
Check ((Find-Function $hostAST 'Assert-NegativeMatrixState') -ceq (Find-Function $bootstrapAST 'Assert-NegativeMatrixState')) 'Host/bootstrap partial-run safety differs.'
Import-Functions $guestAST @('Get-NegativeCases')
Check (((Get-NegativeCaseNames) -join ',') -ceq ((Get-NegativeCases | ForEach-Object {$_.name}) -join ',')) 'Host/guest frozen case matrix differs.'
Check (@(Get-BootstrapPayloads).Count -eq 5) 'Staging payload cardinality differs.'
Check (((Get-BootstrapPayloads | ForEach-Object {$_[1]}) -join ',') -ceq 'guest-clone-config-negative.ps1,clone-config-helper.exe,clone-config-helper.go,build.json,helper-v2-build.json') 'Staging payload names differ.'
foreach($ast in @($hostAST,$bootstrapAST)) {
    $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    foreach($forbidden in @('Start-VM','Stop-VM','Restart-VM','Remove-VM','Set-Acl','Add-ADGroupMember','Remove-ADGroupMember','Remove-Item','Stop-Process','New-ADDCCloneConfigFile')) { Check ($forbidden -notin $commands) "Host/bootstrap contains forbidden action: $forbidden" }
    Check ($ast.Extent.Text -notmatch '\.Kill\(') 'Host/bootstrap kills an uncertain child.'
}
Check ($bootstrapAST.Extent.Text.Contains('& $guest -Mode Run -StageDirectory $StageDirectory')) 'Bootstrap does not invoke the staged guest file.'
Check ($hostAST.Extent.Text.Contains('Invoke-OwnedGuest -FilePath $snapshot')) 'Host does not use its frozen bootstrap file.'
$saveOffset=$hostAST.Extent.Text.IndexOf('Save-NegativeCapture $captured $outcome',[StringComparison]::Ordinal)
$envelopeOffset=$hostAST.Extent.Text.IndexOf("Write-NewHostJson (Join-Path `$resultRoot 'capture-return.json')",[StringComparison]::Ordinal)
Check ($envelopeOffset -gt 0 -and $saveOffset -gt $envelopeOffset) 'Raw capture is not persisted before interpretation.'

$ExpectedManifestSHA256='6AB9B1B9129A39BC9C68FB4B00CB38D6DB4A31C4E925BB1C3790431927AD9E29'
$ExpectedHelperManifestSHA256='0D9B53AF8EDDD7E942144158D6BE56E343B5A4C2F576A0D4D79CA7F594907C75'
$ExpectedGuestScriptSHA256='2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D'
Check ((Get-FileHash -LiteralPath $guestPath -Algorithm SHA256).Hash -ceq $ExpectedGuestScriptSHA256) 'Frozen guest source changed.'
$build=[pscustomobject]@{source_commit='4120ce5d13dd49de490cef67d41767ac3b409715';source_archive_sha256='1FA1A904FDEE8ED7F49428117C8215989F895E3EBCF7AC3554827248654C2E19';directory='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T211528Z-81823b4e'}
$helperBuild=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'clone-config-helper-v2-build.json') -Raw | ConvertFrom-Json
$script:hashes=@{}
foreach($pair in @(@('clone-config-helper.go','helper_source_sha256'),@('clone-config-helper.exe','helper_executable_sha256'),@('clone-config-helper_test.go','helper_tests_sha256'))) { $script:hashes[(Join-Path $helperBuild.directory $pair[0])]=$helperBuild.($pair[1]) }
function Assert-Build($Build) { Check ($Build.source_commit -ceq '4120ce5d13dd49de490cef67d41767ac3b409715') 'Original build check was bypassed.' }
function Assert-UnlinkedPath([string]$Path) { return [IO.Path]::GetFullPath($Path) }
function Get-FileHash { param([string]$LiteralPath,[string]$Algorithm) if($script:hashes.ContainsKey($LiteralPath)) { return [pscustomobject]@{Hash=$script:hashes[$LiteralPath]} };Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256 }
Assert-NegativeBuild $build $helperBuild;$script:checks++
foreach($field in @('source_commit','source_archive_sha256','directory','helper_source_sha256','helper_executable_sha256','helper_tests_sha256','built_utc','previous_build_preserved','guest_execution')) {
    $bad=Clone $helperBuild;$bad.$field=if($field -ceq 'built_utc'){''}else{'invalid'}
    Reject { Assert-NegativeBuild $build $bad } "Helper provenance accepted changed $field."
}
$nativePath=Join-Path $helperBuild.directory 'clone-config-helper.exe';$script:hashes[$nativePath]='A'*64
Reject { Assert-NegativeBuild $build $helperBuild } 'Altered helper executable passed.';$script:hashes[$nativePath]=$helperBuild.helper_executable_sha256

$executionID='clone-config-reviewed-20261112T211528Z-81823b4e-negative-server2025-v1';$Run=$executionID;$StageDirectory=Join-Path 'C:\ad-sdk-validation' $Run
$identity=[pscustomobject]@{run=$Run;source_commit=$build.source_commit;guest_sha256=$ExpectedGuestScriptSHA256;helper_sha256=$helperBuild.helper_executable_sha256;source_sha256=$helperBuild.helper_source_sha256;build_sha256=$ExpectedManifestSHA256;helper_build_sha256=$ExpectedHelperManifestSHA256}
$savedComputer=$env:COMPUTERNAME
try {
    $env:COMPUTERNAME='ADSDK25DC1';Assert-BootstrapIdentity $identity;$script:checks++
    foreach($field in @('run','source_commit','guest_sha256','helper_sha256','source_sha256','build_sha256','helper_build_sha256')) { $bad=Clone $identity;$bad.$field='bad';Reject { Assert-BootstrapIdentity $bad } "Bootstrap accepted altered $field." }
    Reject { Assert-BootstrapPath (Join-Path $StageDirectory '..\escape') } 'Bootstrap accepted escaped stage path.'
    $env:COMPUTERNAME='OTHER';Reject { Assert-BootstrapIdentity $identity } 'Bootstrap accepted wrong guest computer.'
} finally { $env:COMPUTERNAME=$savedComputer }

$stream=[Text.Encoding]::UTF8.GetBytes('raw child stream');$streamHash=Bootstrap-Hash $stream
$file=[pscustomobject]@{exists=$true;sha256=$streamHash}
$process=[pscustomobject]@{pid=42;started_utc='2026-11-12T22:00:00Z';completed=$true;process_uncertain=$false;exit_code=1;stdout_sha256=$streamHash;stderr_sha256=$streamHash}
$cases=@(Get-NegativeCaseNames | ForEach-Object {[pscustomobject]@{name=$_;passed=$true;sdk_process=(Clone $process);reference_process=(Clone $process);sdk_file=(Clone $file);reference=[pscustomobject]@{streams_sha256=$streamHash;file=(Clone $file)}}})
$outcome=[pscustomobject]@{schema_version=1;run=$Run;computer='ADSDK25DC1';mode='explicit Offline only';source_commit=$build.source_commit;source_archive_sha256=$build.source_archive_sha256;build_manifest_sha256=$ExpectedManifestSHA256;helper_build_manifest_sha256=$ExpectedHelperManifestSHA256;helper_source_sha256=$helperBuild.helper_source_sha256;helper_binary_sha256=$helperBuild.helper_executable_sha256;harness_sha256=$ExpectedGuestScriptSHA256;completed=$true;process_uncertain=$false;publication_uncertain=$false;capture_failed=$false;passed=$true;staging_preserved=$true;error=$null;cases=$cases}
$null=Read-NegativeOutcome ($outcome | ConvertTo-Json -Depth 32 -Compress);Assert-NegativeCaptureSafe $outcome $identity;$script:checks+=2
foreach($mutation in @({$bad.completed=$false},{$bad.process_uncertain=$true},{$bad.publication_uncertain=$true},{$bad.capture_failed=$true},{$bad.staging_preserved=$false},{$bad.helper_binary_sha256='A'*64},{$bad.harness_sha256='A'*64},{$bad.passed='true'},{$bad.cases=$bad.cases[0..17]},{$bad.cases[0].name=$bad.cases[1].name},{$bad.cases[0].sdk_process.process_uncertain=$true},{$bad.cases[0].reference_process.completed=$false},{$bad.cases[0].sdk_process.exit_code=$null},{$bad.cases[0].passed=$false})) {
    $bad=Clone $outcome;$script:guestUncertain=$false;& $mutation
    Reject { Read-NegativeOutcome ($bad | ConvertTo-Json -Depth 32 -Compress) } 'Host accepted invalid negative outcome.'
    Check $script:guestUncertain 'Invalid negative outcome did not stop further guest operations.'
}
foreach($field in @('process_uncertain','publication_uncertain','capture_failed')) { $bad=Clone $outcome;$bad.$field=$true;Reject { Assert-NegativeCaptureSafe $bad $identity } "Bootstrap allowed capture after $field." }
function Assert-OwnedControllers { throw 'VM guard must not run after uncertainty.' }
$script:guestUncertain=$true;Reject { Invoke-OwnedGuest -Script {} -Arguments @() -TimeoutSeconds 1 -Action 'blocked' } 'Uncertainty permitted another guest operation.'
$runState=[ordered]@{jobs=@()};$script:removed=$false
function Write-RunState {}
function Wait-Job { param($Job,$Timeout) return $Job }
function Remove-Job { param($Job,$ErrorAction) $script:removed=$true }
$job=[pscustomobject]@{Id=42;State='Running';stops=0};$job | Add-Member ScriptMethod StopJobAsync {$this.stops++}
$script:guestUncertain=$false;Reject { Wait-OwnedJob $job 0 'negative-timeout' } 'Negative job timeout was accepted.'
Check ($script:guestUncertain -and $job.stops -eq 1 -and -not $script:removed) 'Negative timeout retried or removed an unconfirmed live job.'

$script:mockProcesses=@()
function Get-CimInstance { param([string]$ClassName,[string]$Filter,[int]$OperationTimeoutSec,[string]$ErrorAction) if($ClassName -cne 'Win32_Process' -or $OperationTimeoutSec -ne 10 -or $ErrorAction -cne 'Stop') { throw 'Unexpected process query.' };return $script:mockProcesses }
Assert-NegativeProcessesAbsent;$script:checks++
foreach($row in @([pscustomobject]@{Name='clone-config-helper.exe';ExecutablePath=(Join-Path $StageDirectory 'clone-config-helper.exe');CommandLine='helper'},[pscustomobject]@{Name='clone-config-helper.exe';ExecutablePath=$null;CommandLine='helper'},[pscustomobject]@{Name='powershell.exe';ExecutablePath='powershell';CommandLine=('-File "'+(Join-Path $StageDirectory 'guest-clone-config-negative.ps1')+'"')},[pscustomobject]@{Name='powershell.exe';ExecutablePath='powershell';CommandLine=$null})) { $script:mockProcesses=@($row);Reject { Assert-NegativeProcessesAbsent } 'Bootstrap failed to detect a live or unidentifiable child.' }
$script:mockProcesses=@([pscustomobject]@{Name='clone-config-helper.exe';ExecutablePath='C:\unrelated\clone-config-helper.exe';CommandLine='other'},[pscustomobject]@{Name='powershell.exe';ExecutablePath='powershell';CommandLine='-NoProfile -Command unrelated'})
Assert-NegativeProcessesAbsent;$script:checks++

foreach($name in @('owner.txt','negative-cases/summary.json','negative-cases/control-v4-static/sdk.started.json','negative-cases/malformed-v6-dns/reference-child.stderr.txt','negative-cases/broadcast-address/reference/DCCloneConfig.xml')) { Check (Test-NegativeEvidenceName $name) 'Known negative evidence name rejected.' }
foreach($name in @('../escape','negative-cases/../escape','negative-cases/foreign/result.json','negative-cases/control-v4-static/sdk.stdout.txt:stream','C:/escape','negative-cases/control-v4-static/unknown.json')) { Check (-not (Test-NegativeEvidenceName $name)) 'Unsafe or unknown negative evidence name accepted.' }

$fixtureRoot=Join-Path $PSScriptRoot ('clone-config-negative-host-tests-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixtureRoot)
function Raw-File([string]$Name,[byte[]]$Bytes) { return [pscustomobject]@{name=$Name;length=$Bytes.Length;sha256=(Bootstrap-Hash $Bytes);bytes_base64=[Convert]::ToBase64String($Bytes)} }
function New-CaptureFixture($Summary) {
    $files=[Collections.Generic.List[object]]::new()
    foreach($name in @('owner.txt','negative-cases/owner.txt')) { $files.Add((Raw-File $name ([Text.Encoding]::UTF8.GetBytes($Run)))) }
    foreach($name in @('negative-cases/started.json','negative-cases/summary.json')) { $files.Add((Raw-File $name ([Text.Encoding]::UTF8.GetBytes(($Summary | ConvertTo-Json -Depth 32 -Compress))))) }
    foreach($case in $Summary.cases) {
        $prefix='negative-cases/'+$case.name+'/'
        foreach($suffix in @('case.json','options.json','before.json')) { $files.Add((Raw-File ($prefix+$suffix) $stream)) }
        if($null -ne $case.sdk_file) { $files.Add((Raw-File ($prefix+'sdk-observed.json') $stream));if($case.sdk_file.exists) { $files.Add((Raw-File ($prefix+'sdk/DCCloneConfig.xml') $stream)) } }
        if($null -ne $case.reference) {
            foreach($suffix in @('observations.json','reference.json','reference.streams.txt')) { $files.Add((Raw-File ($prefix+$suffix) $stream)) }
            if($null -ne $case.reference.file -and $case.reference.file.exists) { $files.Add((Raw-File ($prefix+'reference/DCCloneConfig.xml') $stream)) }
        }
        foreach($pair in @(@($case.sdk_process,'sdk'),@($case.reference_process,'reference-child'))) {
            if($null -eq $pair[0]) { continue }
            foreach($suffix in @('.requested.json','.started.json','.stdout.txt','.stderr.txt')) { $files.Add((Raw-File ($prefix+$pair[1]+$suffix) $stream)) }
            $files.Add((Raw-File ($prefix+$pair[1]+'.finished.json') ([Text.Encoding]::UTF8.GetBytes(($pair[0] | ConvertTo-Json -Depth 32 -Compress)))))
        }
        $files.Add((Raw-File ($prefix+'result.json') ([Text.Encoding]::UTF8.GetBytes(($case | ConvertTo-Json -Depth 32 -Compress)))))
    }
    return [pscustomobject]@{run=$Run;files=@($files.ToArray())}
}
function Reset-CaptureDestination { $script:resultRoot=Join-Path $fixtureRoot ([guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($script:resultRoot);$script:runState=[ordered]@{captures=[ordered]@{}};$script:guestUncertain=$false }
$capture=New-CaptureFixture $outcome;Reset-CaptureDestination
Save-NegativeCapture ($capture | ConvertTo-Json -Depth 40 -Compress) $outcome
Check ($runState.captures.Count -eq 384) 'Complete negative capture failed to bind 384 synthetic artifacts.'
foreach($mutation in @({$bad.files[0].name='../escape'},{$bad.files[0].length=2097153},{$bad.files[0].sha256='A'*64},{$bad.files[1].name=$bad.files[0].name},{$bad.files=@($bad.files | Where-Object name -cne 'negative-cases/broadcast-dns/sdk.stdout.txt')})) {
    $bad=Clone $capture;& $mutation;Reset-CaptureDestination
    Reject { Save-NegativeCapture ($bad | ConvertTo-Json -Depth 40 -Compress) $outcome } 'Negative capture accepted unsafe, altered, duplicate, or missing raw data.'
}
$badOutcome=Clone $outcome;$badOutcome.cases[0].sdk_process.stdout_sha256='A'*64;$badCapture=New-CaptureFixture $badOutcome;Reset-CaptureDestination
Reject { Save-NegativeCapture ($badCapture | ConvertTo-Json -Depth 40 -Compress) $badOutcome } 'Raw child stream differed from its recorded hash.'
$badCapture=Clone $capture
$finished=@($badCapture.files | Where-Object name -ceq 'negative-cases/control-v4-static/sdk.finished.json')[0]
$changedProcess=Clone $process;$changedProcess.process_uncertain=$true
$changedBytes=[Text.Encoding]::UTF8.GetBytes(($changedProcess | ConvertTo-Json -Depth 32 -Compress))
$finished.length=$changedBytes.Length;$finished.sha256=Bootstrap-Hash $changedBytes;$finished.bytes_base64=[Convert]::ToBase64String($changedBytes)
Reset-CaptureDestination
Reject { Save-NegativeCapture ($badCapture | ConvertTo-Json -Depth 40 -Compress) $outcome } 'Raw uncertain completion differed from the successful summary.'

# A failed first control is a terminal failure with known-ended children. Its
# raw diagnostics must be captured while its qualification remains failed.
$partial=Clone $outcome;$partial.completed=$false;$partial.passed=$false;$partial.error=[pscustomobject]@{text='Independent positive control failed.'};$partial.cases=@($partial.cases[0]);$partial.cases[0].passed=$false
$script:guestUncertain=$false
$stopped=Read-NegativeOutcome ($partial | ConvertTo-Json -Depth 32 -Compress)
Check (-not $stopped.passed -and -not $stopped.completed -and -not $script:guestUncertain -and @($stopped.cases).Count -eq 1) 'Known failed first control was treated as unknown execution.'
Assert-NegativeCaptureSafe $partial $identity;$script:checks++
$partialCapture=New-CaptureFixture $partial;Reset-CaptureDestination
Save-NegativeCapture ($partialCapture | ConvertTo-Json -Depth 40 -Compress) $partial
Check ($runState.captures.Count -eq 24 -and (Test-Path -LiteralPath (Join-Path $resultRoot 'raw\negative-cases\control-v4-static\sdk.stderr.txt'))) 'Failed first control lost its raw diagnostics.'
foreach($mutation in @({$bad.error=$null},{$bad.passed=$true},{$bad.completed=$true},{$bad.cases[0].name='control-four-v6-dns'},{$bad.cases[0].sdk_process.completed=$false},{$bad.cases[0].reference_process.process_uncertain=$true},{$bad.publication_uncertain=$true},{$bad.capture_failed=$true},{$bad.cases[0].sdk_process=$null})) {
    $bad=Clone $partial;& $mutation;$script:guestUncertain=$false
    Reject { Read-NegativeOutcome ($bad | ConvertTo-Json -Depth 32 -Compress) } 'Partial run accepted malformed ordering, success, or uncertain child evidence.'
    Check $script:guestUncertain 'Malformed partial result did not block guest work.'
}
$notStarted=Clone $partial;$notStarted.cases[0].reference_process=$null;$notStarted.cases[0].reference=$null
$script:guestUncertain=$false;$null=Read-NegativeOutcome ($notStarted | ConvertTo-Json -Depth 32 -Compress)
Assert-NegativeCaptureSafe $notStarted $identity;$script:checks++
$notStartedCapture=New-CaptureFixture $notStarted;Reset-CaptureDestination
Save-NegativeCapture ($notStartedCapture | ConvertTo-Json -Depth 40 -Compress) $notStarted
Check ($runState.captures.Count -eq 15) 'Known unstarted reference child required invented artifacts.'
$unexpected=(Raw-File 'negative-cases/control-v4-static/reference-child.requested.json' $stream)
$notStartedCapture.files+=@($unexpected);Reset-CaptureDestination
Reject { Save-NegativeCapture ($notStartedCapture | ConvertTo-Json -Depth 40 -Compress) $notStarted } 'Unreported reference child attempt was accepted.'
# Exercise attempt detection against real workspace files. The production path
# guard was tested above; substitute only its stage root for this local fixture.
$savedStageDirectory=$StageDirectory
$StageDirectory=Join-Path $fixtureRoot 'attempt-status'
$attemptDirectory=Join-Path $StageDirectory 'negative-cases\control-v4-static'
[void][IO.Directory]::CreateDirectory($attemptDirectory)
function Assert-BootstrapPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($StageDirectory+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Synthetic attempt path escaped fixture.' }
    return $full
}
Assert-NegativeAttemptFiles $notStarted;$script:checks++
[IO.File]::WriteAllText((Join-Path $attemptDirectory 'reference-child.requested.json'),'{}')
$attemptFailure=$null
try { Assert-NegativeAttemptFiles $notStarted } catch { $attemptFailure=$_.Exception.Message }
Check ($attemptFailure -ceq 'Unreported child attempt exists; capture is prohibited.') 'Bootstrap ignored an unreported child attempt before capture.'
$StageDirectory=$savedStageDirectory

$record=[ordered]@{passed=$true;checks=$script:checks;collected_utc=[DateTime]::UtcNow.ToString('o');powershell=$PSVersionTable.PSVersion.ToString();scope='offline AST helpers and synthetic local files only; no wrapper, guest, Hyper-V, CIM, AD, or child-process execution';host_script_sha256=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash;bootstrap_sha256=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $bootstrapPath -Algorithm SHA256).Hash;guest_script_sha256=$ExpectedGuestScriptSHA256;fixture_directory=$fixtureRoot}
if($OutputPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($record | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false)) }
$record | ConvertTo-Json -Depth 8
