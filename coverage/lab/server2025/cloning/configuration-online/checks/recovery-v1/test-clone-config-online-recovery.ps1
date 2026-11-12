#Requires -Version 5.1
# Offline AST-only guard regression checks. Never imports a script entrypoint.
param([string]$ReportPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$checks=[Collections.Generic.List[string]]::new()
function Check([string]$Name,[scriptblock]$Body,[bool]$Throws=$false) {
    $thrown=$false;try {& $Body} catch {$thrown=$true;if(-not $Throws) {throw}}
    if($Throws -and -not $thrown) {throw "Expected rejection: $Name"}
    $checks.Add($Name)
}
function Import-Only([string]$Path,[string[]]$Names) {
    $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
    if($e.Count) {throw 'Parse failure.'}
    foreach($name in $Names) {
        $match=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object Name -ceq $name)
        if($match.Count -ne 1) {throw 'Function ambiguity.'}
        . ([scriptblock]::Create(($match[0].Extent.Text-replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name))))
    }
}
$base='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T215735Z-b4707e3f'
$summaryBytes=[IO.File]::ReadAllText((Join-Path $base 'server2025-online-qualification-v1\raw\online-cases\summary.json'))
$journalBytes=[IO.File]::ReadAllText((Join-Path $base 'server2025-online-qualification-v1\run-journal.json'))
$baseline=Get-Content (Join-Path $base 'server2025-online-inventory-v1\inventory.json') -Raw|ConvertFrom-Json
$identity=($journalBytes|ConvertFrom-Json).identity
Import-Only (Join-Path $PSScriptRoot 'recover-clone-config-online-guest.ps1') @('Assert-RecoveryPriorSummary','Observe-RecoveryExclusionShape')
Import-Only (Join-Path $PSScriptRoot 'recover-clone-config-online.ps1') @('Assert-RecoveryPriorJournal','Read-RecoveryOutcome')
Import-Only (Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1') @('Error-Observation')
Check 'actual failed guest summary accepted' {Assert-RecoveryPriorSummary ($summaryBytes|ConvertFrom-Json)}
Check 'actual terminal host journal accepted' {Assert-RecoveryPriorJournal ($journalBytes|ConvertFrom-Json)}
foreach($field in @('completed','passed','cleanup_complete','process_uncertain','publication_uncertain','mutation_uncertain','capture_failed')) {
    $value=$summaryBytes|ConvertFrom-Json;$value.$field=$true
    Check ('reject prior '+$field) {Assert-RecoveryPriorSummary $value} $true
}
foreach($caseIndex in 0..4) {
    $value=$summaryBytes|ConvertFrom-Json;$value.cases[$caseIndex].process.completed=$false
    Check ('reject unfinished case '+$caseIndex) {Assert-RecoveryPriorSummary $value} $true
}
foreach($jobIndex in 0..2) {
    $value=$journalBytes|ConvertFrom-Json;$value.jobs[$jobIndex].removed=$false
    Check ('reject retained job '+$jobIndex) {Assert-RecoveryPriorJournal $value} $true
    $value=$journalBytes|ConvertFrom-Json;$value.jobs[$jobIndex].timeout=$true
    Check ('reject timed out job '+$jobIndex) {Assert-RecoveryPriorJournal $value} $true
}
$value=$summaryBytes|ConvertFrom-Json;$value.recovery.baseline_group_guid=[guid]::NewGuid().ToString()
Check 'reject changed group identity' {Assert-RecoveryPriorSummary $value} $true
$value=$summaryBytes|ConvertFrom-Json;$value.recovery.config_file=@{path='C:\Windows\NTDS\DCCloneConfig.xml'}
Check 'reject unexpected owned config' {Assert-RecoveryPriorSummary $value} $true
$script:capturedShape=$null
function Snapshot-Online([string]$Name,$Value) {$script:capturedShape=$Value}
function Get-ADDCCloningExcludedApplicationList {[CmdletBinding()]param() $null;$false;'No excluded applications';[pscustomobject]@{Name='example';Type='Service'}}
Check 'observe null boolean string object without Name assumptions' {
    Observe-RecoveryExclusionShape
    if(-not $script:capturedShape.completed -or $script:capturedShape.count -ne 4 -or
       -not $script:capturedShape.items[0].is_null -or $script:capturedShape.items[1].type -cne 'System.Boolean' -or
       $script:capturedShape.items[2].scalar -cne 'No excluded applications') {throw 'Output shape observation differs.'}
}
$validOutcome=[ordered]@{recovery_id='recovery-00000000000000000000000000000000';prior_run='original-run';completed=$true;passed=$true;cleanup_complete=$true;process_uncertain=$false;publication_uncertain=$false;mutation_uncertain=$false;capture_failed=$false;file_removed=$true;member_removed=$true;error=$null;recovery=[ordered]@{group_added=$false;custom_file=$null;config_file=$null;intent=$null}}
$validJson=$validOutcome|ConvertTo-Json -Depth 8 -Compress
$script:mockReturn=$validJson
function Invoke-OwnedGuest {param($FilePath,$Arguments,$TimeoutSeconds,$Action) $script:mockReturn}
$snapshot='offline-no-execution';$executionID=$validOutcome.recovery_id;$prior=[pscustomobject]@{identity=@{};execution_id='original-run'};$bootstrapPath=Join-Path $PSScriptRoot 'bootstrap-clone-config-online-qualification.ps1'
$t=$null;$e=$null;$hostAST=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'recover-clone-config-online.ps1'),[ref]$t,[ref]$e)
$returnAssignments=@($hostAST.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$returned'},$true))
if($returnAssignments.Count -ne 1) {throw 'Expected exactly one host return assignment.'}
$actualReturnAssignment=[scriptblock]::Create($returnAssignments[0].Extent.Text)
Check 'reproduce old scalar-return failure' {
    $oldReturned=Invoke-OwnedGuest
    if($oldReturned -isnot [string] -or $oldReturned[0] -isnot [char]) {throw 'Old scalar pattern did not reproduce.'}
}
Check 'actual host assignment preserves one JSON string as array' {
    . $actualReturnAssignment
    if($returned -isnot [array] -or $returned.Count -ne 1 -or $returned[0] -isnot [string]) {throw 'Actual return assignment flattened its payload.'}
    $script:guestUncertain=$true
    $outcome=Read-RecoveryOutcome $returned $executionID 'original-run'
    if(-not $outcome.passed -or $script:guestUncertain) {throw 'Known success was not established.'}
}
foreach($case in @(
    @{name='empty';payload=@()},
    @{name='multiple';payload=@($validJson,$validJson)},
    @{name='non-string';payload=@(42)},
    @{name='malformed-json';payload=@('{broken')},
    @{name='JSON-null';payload=@('null')},
    @{name='wrong-identity';payload=@($validJson.Replace('original-run','another-run'))},
    @{name='untyped-state';payload=@($validJson.Replace('"completed":true','"completed":"true"'))},
    @{name='uncertain';payload=@($validJson.Replace('"mutation_uncertain":false','"mutation_uncertain":true'))},
    @{name='contradictory-success';payload=@($validJson.Replace('"group_added":false','"group_added":true'))},
    @{name='missing-ownership-field';payload=@($validJson.Replace('"config_file":null,',''))}
)) {
    Check ('reject outcome '+$case.name+' and retain uncertainty') {
        $script:guestUncertain=$false;$rejected=$false
        try {$null=Read-RecoveryOutcome $case.payload $executionID 'original-run'} catch {$rejected=$true}
        if(-not $rejected -or -not $script:guestUncertain) {throw 'Malformed outcome was accepted or marked certain.'}
    }
}
$knownFailure=$validJson|ConvertFrom-Json;$knownFailure.passed=$false;$knownFailure.cleanup_complete=$false;$knownFailure.error=[pscustomobject]@{text='known failure'}
Check 'typed terminal failure is known without claiming cleanup' {
    $outcome=Read-RecoveryOutcome @(($knownFailure|ConvertTo-Json -Depth 8 -Compress)) $executionID 'original-run'
    if($outcome.passed -or $outcome.cleanup_complete -or $script:guestUncertain) {throw 'Known failure state differs.'}
}
foreach($file in @('recover-clone-config-online.ps1','recover-clone-config-online-guest.ps1')) {
    $t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$t,[ref]$e)
    Check ($file+' parses') {if($e.Count) {throw 'Parse error.'}}
    Check ($file+' has no native process or VM lifecycle command') {
        $forbidden=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)|Where-Object {$_.GetCommandName() -in @('Start-Process','Start-VM','Stop-VM','Restart-VM','New-VM','Remove-VM')})
        if($forbidden.Count) {throw 'Forbidden command.'}
    }
}
$report=[ordered]@{passed=$true;powershell=$PSVersionTable.PSVersion.ToString();completed_utc=[DateTime]::UtcNow.ToString('o');count=$checks.Count;checks=@($checks);guest_sha256=(Get-FileHash (Join-Path $PSScriptRoot 'recover-clone-config-online-guest.ps1')).Hash;host_sha256=(Get-FileHash (Join-Path $PSScriptRoot 'recover-clone-config-online.ps1')).Hash}
if($ReportPath) {[IO.File]::WriteAllText($ReportPath,($report|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}
[pscustomobject]$report|Select-Object passed,powershell,count,guest_sha256,host_sha256|ConvertTo-Json
