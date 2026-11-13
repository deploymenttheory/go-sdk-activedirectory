#Requires -Version 5.1
# One reviewed recovery only. No test replay, VM lifecycle operation, or child process.
param(
    [Parameter(Mandatory)][string]$IdentityJson,
    [Parameter(Mandatory)][ValidatePattern('^recovery-[a-f0-9]{32}$')][string]$RecoveryID,
    [Parameter(Mandatory)][string]$BootstrapBase64
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$Run='clone-config-reviewed-20261112T215735Z-b4707e3f-online-qualification-server2025-v2'
$StageDirectory=Join-Path 'C:\ad-sdk-validation' $Run
$ReplicationTimeoutSeconds=90
$script:processUncertain=$false;$script:publicationUncertain=$false;$script:mutationUncertain=$false;$script:captureFailed=$false
function Import-RecoveryFunctions([string]$Source,[string[]]$Names) {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($Source,[ref]$tokens,[ref]$errors)
    if($errors.Count) { throw 'Recovery dependency parse failed.' }
    foreach($name in $Names) {
        $matches=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object Name -ceq $name)
        if($matches.Count -ne 1) { throw 'Recovery dependency function cardinality differs.' }
        $definition=$matches[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name)
        . ([scriptblock]::Create($definition))
    }
}
function Recovery-Hash([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','') } finally {$hasher.Dispose()}
}
function Snapshot-Online([string]$Name,$Value) {
    $script:snapshotNumber++
    $record=[ordered]@{name=$Name;value=$Value}
    Write-NewJson (Join-Path $root ('snapshots\{0:D4}-{1}.json' -f $script:snapshotNumber,$Name)) $record
    $script:state.snapshots+=@($record)
}
function Assert-RecoveryPriorSummary($Prior) {
    foreach($name in @('completed','passed','cleanup_complete','process_uncertain','publication_uncertain','mutation_uncertain','capture_failed')) {
        if($Prior.$name -isnot [bool] -or $Prior.$name) {throw 'Prior state is uncertain or outside this exact recovery.'}
    }
    if($Prior.phase -cne 'before-online-sdk-existing' -or $Prior.recovery.group_added -ne $true -or
       $null -eq $Prior.recovery.custom_file -or $null -eq $Prior.recovery.config_file -or $null -ne $Prior.recovery.intent -or
       $Prior.recovery.baseline_group_guid -cne $baseline.directory.group_guid -or
       $Prior.recovery.baseline_source_guid -cne $baseline.directory.source_guid -or
       $Prior.recovery.baseline_inventory_sha256 -cne $identity.inventory_sha256) {throw 'Prior recovery ownership differs.'}
    $expected=@('missing-group-sdk','missing-group-reference','add-direct-membership','excluded-apps-sdk','excluded-apps-reference','online-sdk-success','online-sdk-existing')
    if(@($Prior.cases).Count -ne $expected.Count) {throw 'Prior case count differs.'}
    for($index=0;$index -lt $expected.Count;$index++) {
        $case=$Prior.cases[$index]
        $expectedPassed=($index -lt 6)
        if($case.name -cne $expected[$index] -or $case.passed -isnot [bool] -or $case.passed -ne $expectedPassed -or
           $case.process.completed -ne $true -or $case.process.process_uncertain -ne $false) {throw 'Prior child completion is not established.'}
    }
    if($Prior.cases[6].error.text -cne 'Observed online case failed its expectation; retain evidence and recovery state.' -or
       -not (Same-OnlineValue $Prior.cases[6].output_before $Prior.cases[6].output_after) -or
       -not (Same-OnlineValue $Prior.cases[6].output_after $Prior.recovery.config_file)) {throw 'Known failed collision case or unchanged owned output differs.'}
}
function Assert-RecoveryPreWorld {
    # The v2 inventory is fixed. Require full world/replica validation plus
    # exact metadata for both owned files before removing either one.
    Assert-OnlineWorld $true $prior.recovery.custom_file $prior.recovery.config_file
    if(-not (Same-OnlineValue (Read-OnlineFile 'C:\Windows\NTDS\DCCloneConfig.xml') $prior.recovery.config_file) -or
       -not (Same-OnlineValue (Read-OnlineFile 'C:\Windows\NTDS\CustomDCCloneAllowList.xml') $prior.recovery.custom_file)) {throw 'Recovery exact file ownership differs.'}
}

if($env:COMPUTERNAME -cne 'ADSDK25DC1') {throw 'Recovery guest differs.'}
$bootstrapBytes=[Convert]::FromBase64String($BootstrapBase64)
if((Recovery-Hash $bootstrapBytes) -cne '9028C554B2AFAF9602E1B780846F32EB597374CA1CE8A124EE3DCC1A57AD076B') {throw 'Recovery bootstrap source differs.'}
Import-RecoveryFunctions ([Text.Encoding]::UTF8.GetString($bootstrapBytes)) @('Get-OnlinePins','Get-OnlinePayloads','Assert-OnlineIdentity','Get-OnlineCaseNames','Assert-OnlineMatrixState','Assert-OnlineOutcome','Assert-OnlineStagePath','Assert-OnlineBootstrapIdentity','Assert-OnlineStaging','Assert-OnlineProcessesAbsent','Assert-OnlineAttemptFiles')
$identity=$IdentityJson|ConvertFrom-Json
Assert-OnlineStaging $identity
Assert-OnlineProcessesAbsent
$guestPath=Assert-OnlineStagePath (Join-Path $StageDirectory 'guest-clone-config-online-qualification.ps1')
if((Get-FileHash -LiteralPath $guestPath).Hash -cne '87E2DB53A47A6EEAB20DE0C7704DA0338407F45108B977CB98447977267AD2EB') {throw 'Original guest dependency differs.'}
Import-RecoveryFunctions ([IO.File]::ReadAllText($guestPath)) @('Import-OnlineFunctions','Assert-OnlineLocalPath','Assert-CanRun','Same-OnlineValue','Online-Entries','Read-OnlineFile','Checkpoint-Online','Read-OnlineReplica','Assert-OnlineReplica','Wait-OnlineReplicas','Assert-OnlineWorld','Remove-OnlineOwnedFile')
Import-OnlineFunctions (Join-Path $StageDirectory 'negative-process-support.ps1') @('Assert-StagePath','Write-NewBytes','Write-NewJson','Error-Observation')
Import-OnlineFunctions (Join-Path $StageDirectory 'inventory-support.ps1') @('Read-InventoryItem','Assert-InventoryPath','Read-InventoryFile','Inventory-SID','Get-InventoryRemovable','Read-CloneConfigOnlineInventory')
Import-Module ActiveDirectory -ErrorAction Stop
$baseline=Get-Content -LiteralPath (Join-Path $StageDirectory 'inventory.json') -Raw|ConvertFrom-Json
$priorPath=Assert-OnlineStagePath (Join-Path $StageDirectory 'online-cases\summary.json')
if((Get-FileHash -LiteralPath $priorPath).Hash -cne '6BBB302CDC5BAD56C85EB34624A42EA148E1BD271C7D3941E8B6F64EFDCD661A') {throw 'Original failed summary differs.'}
$prior=Get-Content -LiteralPath $priorPath -Raw|ConvertFrom-Json
Assert-OnlineOutcome $prior $identity
Assert-RecoveryPriorSummary $prior
Assert-OnlineAttemptFiles $prior
$root=Assert-OnlineStagePath (Join-Path $StageDirectory $RecoveryID)
if(Test-Path -LiteralPath $root) {throw 'Recovery evidence exists; no replay.'}
[void][IO.Directory]::CreateDirectory($root);[void][IO.Directory]::CreateDirectory((Join-Path $root 'events'));[void][IO.Directory]::CreateDirectory((Join-Path $root 'snapshots'))
$script:eventNumber=0;$script:snapshotNumber=0
$script:state=[ordered]@{schema_version=1;recovery_id=$RecoveryID;prior_run=$Run;prior_summary_sha256='6BBB302CDC5BAD56C85EB34624A42EA148E1BD271C7D3941E8B6F64EFDCD661A';phase='prepared';completed=$false;passed=$false;cleanup_complete=$false;process_uncertain=$false;publication_uncertain=$false;mutation_uncertain=$false;capture_failed=$false;file_removed=$false;member_removed=$false;error=$null;snapshots=@();recovery=$prior.recovery}
Write-NewJson (Join-Path $root 'started.json') $script:state
try {
    Assert-RecoveryPreWorld
    Assert-CanRun;Assert-OnlineProcessesAbsent
    Remove-OnlineOwnedFile $prior.recovery.config_file
    $script:state.recovery.config_file=$null;Checkpoint-Online 'config-file-removed'
    Assert-OnlineWorld $true $prior.recovery.custom_file $null
    Remove-OnlineOwnedFile $prior.recovery.custom_file
    $script:state.file_removed=$true;$script:state.recovery.custom_file=$null;Checkpoint-Online 'custom-file-removed'
    Assert-OnlineWorld $true $null $null
    Assert-OnlineProcessesAbsent
    Assert-OnlineReplica (Read-OnlineReplica 'ADSDK25DC1.ad.sdk.test') $true
    $script:state.recovery.intent=[ordered]@{operation='remove-member';group_guid=$baseline.directory.group_guid;member_dn=$baseline.directory.source_dn}
    Checkpoint-Online 'before-owned-membership-removal'
    try {
        Set-ADObject -Identity ([guid]$baseline.directory.group_guid) -Server 'ADSDK25DC1.ad.sdk.test' -Remove @{member=$baseline.directory.source_dn} -ErrorAction Stop
        Assert-OnlineReplica (Read-OnlineReplica 'ADSDK25DC1.ad.sdk.test') $false
    } catch {$script:mutationUncertain=$true;throw}
    $script:state.member_removed=$true;$script:state.recovery.group_added=$false;$script:state.recovery.intent=$null;Checkpoint-Online 'owned-membership-removed'
    Wait-OnlineReplicas $false
    Assert-OnlineWorld $false $null $null
    Assert-OnlineProcessesAbsent
    $script:state.cleanup_complete=$true;$script:state.passed=$true;Checkpoint-Online 'baseline-restored'
} catch {$script:state.error=Error-Observation $_}
finally {
    $script:state.completed=$true;$script:state.process_uncertain=$script:processUncertain;$script:state.publication_uncertain=$script:publicationUncertain;$script:state.mutation_uncertain=$script:mutationUncertain;$script:state.capture_failed=$script:captureFailed
    if($script:processUncertain -or $script:publicationUncertain -or $script:mutationUncertain -or $script:captureFailed) {$script:state.passed=$false;$script:state.cleanup_complete=$false}
    Write-NewJson (Join-Path $root 'summary.json') $script:state
}
$payload=$script:state|ConvertTo-Json -Depth 24 -Compress
if([Text.Encoding]::UTF8.GetByteCount($payload) -gt 2097152) {throw 'Recovery result exceeds transport bound.'}
$payload
