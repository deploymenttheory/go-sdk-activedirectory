#Requires -Version 5.1
# Reviewed exact recovery for terminal online qualification v1. No test replay.
param([Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedGuestSHA256)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Import-RecoveryHostFunctions([string]$Path,[string[]]$Names) {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count) {throw 'Recovery host dependency parse failed.'}
    foreach($name in $Names) {
        $matches=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object Name -ceq $name)
        if($matches.Count -ne 1) {throw 'Recovery host function cardinality differs.'}
        $definition=$matches[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name)
        . ([scriptblock]::Create($definition))
    }
}
function Assert-RecoveryPriorJournal($Prior) {
    if($Prior.terminal -ne $true -or $Prior.guest_uncertain -ne $false -or $Prior.passed -ne $false -or
       $Prior.cleanup_complete -ne $false -or $Prior.phase -cne 'failed-preserve-for-review' -or
       $Prior.lab_id -cne '60197892-ec9f-4c19-abe8-34dc60d473e5' -or $Prior.vm_id -cne 'a364b1d0-7868-47f1-ab29-a5e80c97aa4b' -or
       @($Prior.jobs).Count -ne 3) {throw 'Original journal is uncertain or outside this recovery.'}
    $expected=@('stage','online-qualification','capture')
    for($index=0;$index -lt $expected.Count;$index++) {
        $job=$Prior.jobs[$index]
        if($job.action -cne $expected[$index] -or $job.state -cne 'Completed' -or $job.timeout -ne $false -or
           $job.removed -ne $true -or $null -ne $job.error) {throw 'Original guest job completion is unverified.'}
    }
}
function Read-RecoveryOutcome([object[]]$Returned,[string]$ExpectedRecoveryID,[string]$ExpectedPriorRun) {
    # A completed remoting job alone cannot establish what the recovery did.
    # Keep uncertainty until transport, identity and terminal state are proven.
    $script:guestUncertain=$true
    if($null -eq $Returned -or $Returned.Count -ne 1 -or $Returned[0] -isnot [string] -or
       [Text.Encoding]::UTF8.GetByteCount($Returned[0]) -gt 2097152) {throw 'Recovery outcome transport is malformed.'}
    $outcome=$Returned[0]|ConvertFrom-Json
    foreach($field in @('completed','passed','cleanup_complete','process_uncertain','publication_uncertain','mutation_uncertain','capture_failed','file_removed','member_removed')) {
        if($outcome.$field -isnot [bool]) {throw 'Recovery outcome safety state is untyped.'}
    }
    if($outcome.recovery_id -cne $ExpectedRecoveryID -or $outcome.prior_run -cne $ExpectedPriorRun -or
       -not $outcome.completed -or $outcome.process_uncertain -or $outcome.publication_uncertain -or $outcome.mutation_uncertain -or $outcome.capture_failed -or
       $null -eq $outcome.recovery -or $outcome.recovery.group_added -isnot [bool]) {throw 'Recovery outcome is uncertain; preserve all staging and do not dispatch further work.'}
    # Access required recovery fields before clearing uncertainty, including
    # fields whose legitimate value is null in a fully restored result.
    foreach($field in @('custom_file','config_file','intent')) {
        if($null -eq $outcome.recovery.PSObject.Properties[$field]) {throw 'Recovery ownership state is incomplete.'}
    }
    if($null -eq $outcome.PSObject.Properties['error']) {throw 'Recovery error state is absent.'}
    if($outcome.passed) {
        if(-not $outcome.cleanup_complete -or -not $outcome.file_removed -or -not $outcome.member_removed -or
           $null -ne $outcome.error -or $outcome.recovery.group_added -or $null -ne $outcome.recovery.custom_file -or
           $null -ne $outcome.recovery.config_file -or $null -ne $outcome.recovery.intent) {throw 'Passing recovery outcome contradicts its ownership state.'}
    } elseif($outcome.cleanup_complete -or $null -eq $outcome.error) {throw 'Failed recovery outcome lacks a known terminal error.'}
    $script:guestUncertain=$false
    return $outcome
}
$frozenHost=Join-Path $PSScriptRoot 'run-clone-config-online-qualification.ps1'
if((Get-FileHash -LiteralPath $frozenHost).Hash -cne '7B6CB02A7094A40D8347BA471BBF2572F94EDDBBD4F1231B255F00BA49CA0EDB') {throw 'Original host guard source differs.'}
Import-RecoveryHostFunctions $frozenHost @('Assert-UnlinkedPath','Assert-OwnedControllers','Assert-SwitchPorts','Write-NewHostJson','Write-NewHostBytes','Get-ProfileMutexName','Write-RunState','Wait-OwnedJob','Invoke-OwnedGuest','Assert-NewRunDirectory')
$profile='H:\ad-sdk-lab\server2025';$operationMutex=$null;$mutexHeld=$false;$runState=$null
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T215735Z-b4707e3f'
$priorRoot=Join-Path $buildRoot 'server2025-online-qualification-v2'
try {
    $operationMutex=[Threading.Mutex]::new($false,(Get-ProfileMutexName $profile))
    try {$mutexHeld=$operationMutex.WaitOne(0)} catch [Threading.AbandonedMutexException] {$mutexHeld=$true}
    if(-not $mutexHeld) {throw 'Another lab action owns this profile.'}
    $priorPath=Assert-UnlinkedPath (Join-Path $priorRoot 'run-journal.json')
    if((Get-FileHash -LiteralPath $priorPath).Hash -cne '1ECB5B7DAD255D719D1E6B4831CA16AEE0A13F3FFA672232635C569F0544B20A') {throw 'Original terminal journal differs.'}
    $prior=Get-Content -LiteralPath $priorPath -Raw|ConvertFrom-Json
    Assert-RecoveryPriorJournal $prior
    $summaryPath=Assert-UnlinkedPath (Join-Path $priorRoot 'raw\online-cases\summary.json')
    if((Get-FileHash -LiteralPath $summaryPath).Hash -cne '6BBB302CDC5BAD56C85EB34624A42EA148E1BD271C7D3941E8B6F64EFDCD661A') {throw 'Captured prior summary differs.'}
    $bootstrapPath=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'bootstrap-clone-config-online-qualification.ps1')
    if((Get-FileHash -LiteralPath $bootstrapPath).Hash -cne '9028C554B2AFAF9602E1B780846F32EB597374CA1CE8A124EE3DCC1A57AD076B') {throw 'Original bootstrap guard source differs.'}
    $guestPath=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'recover-clone-config-online-guest.ps1')
    if((Get-FileHash -LiteralPath $guestPath).Hash -cne $ExpectedGuestSHA256) {throw 'Reviewed recovery guest differs.'}
    $statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml'
    foreach($path in @($statePath,$credentialPath)) {$null=Assert-UnlinkedPath $path}
    $stateHash=(Get-FileHash -LiteralPath $statePath).Hash;$state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
    Import-Module Hyper-V -ErrorAction Stop
    Assert-OwnedControllers
    $machine=@($state.machines|Where-Object role -ceq 'dc1')[0]
    $executionID='recovery-'+[guid]::NewGuid().ToString('N')
    $resultRoot=Assert-NewRunDirectory (Join-Path $buildRoot $executionID)
    [void][IO.Directory]::CreateDirectory($resultRoot)
    $runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'run-journal.json';$script:guestUncertain=$false
    $runState=[ordered]@{schema_version=1;owner=$runOwner;execution_id=$executionID;phase='prepared';terminal=$false;guest_uncertain=$false;jobs=@();passed=$false;cleanup_complete=$false;error=$null;updated=$null;prior_run=$prior.execution_id;prior_journal_sha256='1ECB5B7DAD255D719D1E6B4831CA16AEE0A13F3FFA672232635C569F0544B20A';host_script_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash;guest_script_sha256=$ExpectedGuestSHA256;lab_id=$state.id;vm_id=$machine.id;staging_preserved=$true}
    Write-RunState
    $snapshot=Join-Path $resultRoot 'recover-clone-config-online-guest.ps1'
    Write-NewHostBytes $snapshot ([IO.File]::ReadAllBytes($guestPath))
    Write-NewHostBytes (Join-Path $resultRoot 'recover-clone-config-online.ps1') ([IO.File]::ReadAllBytes($PSCommandPath))
    Write-NewHostBytes (Join-Path $resultRoot 'prior-summary.json') ([IO.File]::ReadAllBytes($summaryPath))
    $saved=Import-Clixml -LiteralPath $credentialPath;$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
    if((Get-FileHash -LiteralPath $snapshot).Hash -cne $ExpectedGuestSHA256) {throw 'Recovery guest snapshot differs.'}
    $returned=@(Invoke-OwnedGuest -FilePath $snapshot -Arguments @(($prior.identity|ConvertTo-Json -Compress),$executionID,([Convert]::ToBase64String([IO.File]::ReadAllBytes($bootstrapPath)))) -TimeoutSeconds 300 -Action 'exact-online-recovery')
    $script:guestUncertain=$true
    Write-NewHostJson (Join-Path $resultRoot 'guest-return.json') ([ordered]@{payload=@($returned)})
    $outcome=Read-RecoveryOutcome $returned $executionID $prior.execution_id
    Write-NewHostJson (Join-Path $resultRoot 'recovery.json') $outcome
    if(-not $outcome.passed) {throw 'Recovery did not verify baseline restoration; preserve evidence.'}
    Assert-OwnedControllers
    $runState.passed=$true;$runState.cleanup_complete=$true
} catch {if($null -ne $runState) {$runState.error=$_.Exception.Message};throw}
finally {
    try {
        if($null -ne $runState) {$runState.terminal=$true;$runState.phase=if($runState.passed){'restored'}else{'failed-preserve'};Write-RunState;Write-NewHostJson (Join-Path $resultRoot 'qualification.json') $runState}
    } finally {if($mutexHeld) {$operationMutex.ReleaseMutex()};if($operationMutex) {$operationMutex.Dispose()}}
}
[pscustomobject]@{directory=$resultRoot;passed=$runState.passed;cleanup_complete=$runState.cleanup_complete;staging_preserved=$true}|ConvertTo-Json
