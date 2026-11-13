#Requires -Version 5.1
# One reviewed recovery only. No test replay, VM lifecycle operation, or child process.
param(
    [Parameter(Mandatory)][string]$IdentityJson,
    [Parameter(Mandatory)][ValidatePattern('^recovery-[a-f0-9]{32}$')][string]$RecoveryID,
    [Parameter(Mandatory)][string]$BootstrapBase64
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$Run='clone-config-reviewed-20261112T215735Z-b4707e3f-online-qualification-server2025-v1'
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
    if($Prior.phase -cne 'inclusion-created' -or $Prior.recovery.group_added -ne $true -or
       $null -eq $Prior.recovery.custom_file -or $null -ne $Prior.recovery.config_file -or $null -ne $Prior.recovery.intent -or
       $Prior.recovery.baseline_group_guid -cne $baseline.directory.group_guid -or
       $Prior.recovery.baseline_source_guid -cne $baseline.directory.source_guid -or
       $Prior.recovery.baseline_inventory_sha256 -cne $identity.inventory_sha256) {throw 'Prior recovery ownership differs.'}
    $expected=@('missing-group-sdk','missing-group-reference','add-direct-membership','excluded-apps-sdk','excluded-apps-reference')
    if(@($Prior.cases).Count -ne $expected.Count) {throw 'Prior case count differs.'}
    for($index=0;$index -lt $expected.Count;$index++) {
        $case=$Prior.cases[$index]
        if($case.name -cne $expected[$index] -or $case.passed -ne $true -or
           $case.process.completed -ne $true -or $case.process.process_uncertain -ne $false) {throw 'Prior child completion is not established.'}
    }
}
function Observe-RecoveryExclusionShape {
    $record=[ordered]@{completed=$false;count=$null;items=@();warnings=@();information=@();error=$null}
    try {
        $warnings=@();$information=@()
        $values=@(Get-ADDCCloningExcludedApplicationList -ErrorAction Stop -WarningVariable warnings -InformationVariable information)
        if($values.Count -gt 1024) {throw 'Exclusion shape count exceeds bound.'}
        $record.count=$values.Count
        foreach($value in $values) {
            if($null -eq $value) {$record.items+=@([ordered]@{is_null=$true;type=$null;type_names=@();properties=@();scalar=$null});continue}
            $scalar=$null;if($value -is [bool]) {$scalar=$value} elseif($value -is [string]) {$scalar=$value.Substring(0,[Math]::Min(2048,$value.Length))}
            $record.items+=@([ordered]@{is_null=$false;type=$value.GetType().FullName;type_names=@($value.PSObject.TypeNames);properties=@($value.PSObject.Properties|ForEach-Object {$_.Name});scalar=$scalar})
        }
        $record.warnings=@($warnings|ForEach-Object {$_.ToString()});$record.information=@($information|ForEach-Object {$_.ToString()});$record.completed=$true
    } catch {$record.error=Error-Observation $_}
    Snapshot-Online 'exclusion-output-shape' $record
}
function Assert-RecoveryPreWorld {
    # The known inventory defect occurs after files, versions and directory
    # observations. Validate those fields individually; do not claim inventory
    # completion or accept its application projection as evidence.
    $current=Read-CloneConfigOnlineInventory 'clone-config-reviewed-20261112T215735Z-b4707e3f-online-inventory-v1'
    Snapshot-Online 'pre-removal-partial-inventory' $current
    foreach($field in @('server','domain_dn','domain_sid','pdc','source_dn','source_guid','source_sid','group_dn','group_guid','group_sid','source_read_only','dc_functionality')) {
        if(-not (Same-OnlineValue $current.directory.$field $baseline.directory.$field)) {throw "Recovery directory identity differs: $field"}
    }
    if($null -eq $current.versions -or -not (Same-OnlineValue $current.versions $baseline.versions) -or
       -not (Same-OnlineValue $current.files.directories $baseline.files.directories) -or
       -not (Same-OnlineValue $current.files.default_list $baseline.files.default_list) -or
       $current.files.dsa_directory -cne 'C:\Windows\NTDS' -or $current.files.windows_ntds -cne 'C:\Windows\NTDS' -or
       $null -ne $current.files.allow_list_folder -or @($current.files.removable).Count -ne 0 -or
       @($current.files.custom_lists).Count -ne 1 -or @($current.files.clone_configs).Count -ne 1) {throw 'Recovery file locations, directory ACL, default list or reference version differs.'}
    if((Read-OnlineFile 'C:\Windows\NTDS\DCCloneConfig.xml').exists -or
       -not (Same-OnlineValue (Read-OnlineFile 'C:\Windows\NTDS\CustomDCCloneAllowList.xml') $prior.recovery.custom_file)) {throw 'Recovery exact file ownership differs.'}
    foreach($server in @('ADSDK25DC1.ad.sdk.test','ADSDK25DC2.ad.sdk.test')) {Assert-OnlineReplica (Read-OnlineReplica $server) $true}
}

if($env:COMPUTERNAME -cne 'ADSDK25DC1') {throw 'Recovery guest differs.'}
$bootstrapBytes=[Convert]::FromBase64String($BootstrapBase64)
if((Recovery-Hash $bootstrapBytes) -cne 'E823C10B7497834C637F93782EA71FD91FA76035779411C668E96C05CE836CCD') {throw 'Recovery bootstrap source differs.'}
Import-RecoveryFunctions ([Text.Encoding]::UTF8.GetString($bootstrapBytes)) @('Get-OnlinePins','Get-OnlinePayloads','Assert-OnlineIdentity','Get-OnlineCaseNames','Assert-OnlineMatrixState','Assert-OnlineOutcome','Assert-OnlineStagePath','Assert-OnlineBootstrapIdentity','Assert-OnlineStaging','Assert-OnlineProcessesAbsent','Assert-OnlineAttemptFiles')
$identity=$IdentityJson|ConvertFrom-Json
Assert-OnlineStaging $identity
Assert-OnlineProcessesAbsent
$guestPath=Assert-OnlineStagePath (Join-Path $StageDirectory 'guest-clone-config-online-qualification.ps1')
if((Get-FileHash -LiteralPath $guestPath).Hash -cne '3025A2F740BE1764DF1A13F2C266554B68BAC4DAA9A4889CFA20C3BD8A8AFED1') {throw 'Original guest dependency differs.'}
Import-RecoveryFunctions ([IO.File]::ReadAllText($guestPath)) @('Import-OnlineFunctions','Assert-OnlineLocalPath','Assert-CanRun','Same-OnlineValue','Online-Entries','Read-OnlineFile','Checkpoint-Online','Read-OnlineReplica','Assert-OnlineReplica','Wait-OnlineReplicas','Assert-OnlineWorld','Remove-OnlineOwnedFile')
Import-OnlineFunctions (Join-Path $StageDirectory 'negative-process-support.ps1') @('Assert-StagePath','Write-NewBytes','Write-NewJson','Error-Observation')
Import-OnlineFunctions (Join-Path $StageDirectory 'inventory-support.ps1') @('Read-InventoryItem','Assert-InventoryPath','Read-InventoryFile','Inventory-SID','Get-InventoryRemovable','Read-CloneConfigOnlineInventory')
Import-Module ActiveDirectory -ErrorAction Stop
$baseline=Get-Content -LiteralPath (Join-Path $StageDirectory 'inventory.json') -Raw|ConvertFrom-Json
$priorPath=Assert-OnlineStagePath (Join-Path $StageDirectory 'online-cases\summary.json')
if((Get-FileHash -LiteralPath $priorPath).Hash -cne '6EF6FC734F7B201F1DC1DABD2A8892843531F7DCB1B1433AFF30744FEC28E506') {throw 'Original failed summary differs.'}
$prior=Get-Content -LiteralPath $priorPath -Raw|ConvertFrom-Json
Assert-OnlineOutcome $prior $identity
Assert-RecoveryPriorSummary $prior
Assert-OnlineAttemptFiles $prior
$root=Assert-OnlineStagePath (Join-Path $StageDirectory $RecoveryID)
if(Test-Path -LiteralPath $root) {throw 'Recovery evidence exists; no replay.'}
[void][IO.Directory]::CreateDirectory($root);[void][IO.Directory]::CreateDirectory((Join-Path $root 'events'));[void][IO.Directory]::CreateDirectory((Join-Path $root 'snapshots'))
$script:eventNumber=0;$script:snapshotNumber=0
$script:state=[ordered]@{schema_version=1;recovery_id=$RecoveryID;prior_run=$Run;prior_summary_sha256='6EF6FC734F7B201F1DC1DABD2A8892843531F7DCB1B1433AFF30744FEC28E506';phase='prepared';completed=$false;passed=$false;cleanup_complete=$false;process_uncertain=$false;publication_uncertain=$false;mutation_uncertain=$false;capture_failed=$false;file_removed=$false;member_removed=$false;error=$null;snapshots=@();recovery=$prior.recovery}
Write-NewJson (Join-Path $root 'started.json') $script:state
try {
    Assert-RecoveryPreWorld
    Observe-RecoveryExclusionShape
    Assert-CanRun;Assert-OnlineProcessesAbsent
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
