#Requires -Version 5.1
# Offline ownership-boundary tests. No Hyper-V, keys, or lab credentials are used.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'portable-linux.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'The Linux orchestration script does not parse.'}
foreach ($name in @('Assert-LinuxPath','Assert-LinuxState','Get-LinuxControlDirectory','Assert-LinuxControlCacheOwner','Write-LinuxControlChunk','Assert-LinuxControlEntries','Assert-LinuxControlReconciled','Save-LinuxControlReconciliation','Invoke-LinuxControlCommand')) {
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if (-not $definition) {throw "Missing ownership guard: $name"}
    Invoke-Expression $definition.Extent.Text
}
function Assert-Rejected([scriptblock]$Operation,[string]$Description) {
    $rejected=$false
    try {& $Operation | Out-Null} catch {$rejected=$true}
    if (-not $rejected) {throw "Ownership guard accepted $Description."}
}
$temporary=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tmp'))
$fixture=[IO.Path]::GetFullPath((Join-Path $temporary ('portable-linux-guards-'+[guid]::NewGuid().ToString('N'))))
if (-not $fixture.StartsWith($temporary+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Test fixture escaped the repository tmp root.'}
$script:root=Join-Path $fixture 'owned'
$null=New-Item -ItemType Directory -Path $script:root
try {
    if ((Assert-LinuxPath (Join-Path $script:root 'disks\client.vhdx')) -cne (Join-Path $script:root 'disks\client.vhdx')) {throw 'An owned path was changed.'}
    Assert-Rejected {Assert-LinuxPath $script:root} 'the root directory itself'
    Assert-Rejected {Assert-LinuxPath (Join-Path $script:root '..\outside.vhdx')} 'parent traversal'
    Assert-Rejected {Assert-LinuxPath ($script:root+'-other\disk.vhdx')} 'a sibling sharing the root prefix'
    $target=Join-Path $fixture 'target';$null=New-Item -ItemType Directory -Path $target
    $junction=Join-Path $script:root 'redirect'
    $null=New-Item -ItemType Junction -Path $junction -Target $target
    try {Assert-Rejected {Assert-LinuxPath (Join-Path $junction 'disk.vhdx')} 'a reparse-point ancestor'}
    finally {Remove-Item -LiteralPath $junction -Force}
    $script:state=[pscustomobject]@{schema_version=1;root=$script:root;id=[guid]::NewGuid().ToString()
        base_disk=(Join-Path $script:root 'disks\base.vhdx');child_disk=(Join-Path $script:root 'disks\client.vhdx')
        seed_iso=(Join-Path $script:root 'secrets\seed.iso');client_key=(Join-Path $script:root 'secrets\client_ed25519')
        host_key=(Join-Path $script:root 'secrets\host_ed25519')}
    Assert-LinuxState
    $script:state.client_key=Join-Path $fixture 'unowned-key'
    Assert-Rejected {Assert-LinuxState} 'an unowned private-key location in the journal'
    $script:state.client_key=Join-Path $script:root 'secrets\client_ed25519'
    $script:state.id='------------------------------------'
    Assert-Rejected {Assert-LinuxState} 'a malformed ownership GUID'
    Write-Output 'PASS: Linux ownership guards reject traversal, sibling prefixes, reparse points, changed key paths, and invalid IDs.'

    $ownerId='11111111-1111-4111-8111-111111111111'
    if ((Get-LinuxControlDirectory $ownerId) -cne ('C:\adsdk-linux-control-cache\'+$ownerId)) {throw 'Public cache root differs.'}
    Assert-Rejected {Get-LinuxControlDirectory '../outside'} 'public cache traversal'
    Assert-Rejected {Get-LinuxControlDirectory ('x'+$ownerId)} 'an ambiguous cache owner'
    $expectedCache=[pscustomobject]@{owner_id=$ownerId;member_id='22222222-2222-4222-8222-222222222222';profile_id='33333333-3333-4333-8333-333333333333';sha256=('a'*64);bytes=4}
    $cacheOwner=[pscustomobject]@{schema_version=1;purpose='adsdk-public-ssh-control';owner_id=$expectedCache.owner_id;member_id=$expectedCache.member_id;profile_id=$expectedCache.profile_id;sha256=$expectedCache.sha256;bytes=4}
    Assert-LinuxControlCacheOwner $cacheOwner $expectedCache
    foreach($property in @('owner_id','member_id','profile_id','sha256','bytes','purpose','schema_version')){
        $changed=$cacheOwner|ConvertTo-Json|ConvertFrom-Json
        if($property -cin @('bytes','schema_version')){$changed.$property=9}else{$changed.$property='changed'}
        Assert-Rejected {Assert-LinuxControlCacheOwner $changed $expectedCache} ('changed cache '+$property)
    }
    $regular=[IO.FileAttributes]::Archive
    $entries=@([pscustomobject]@{Name='owner.json';PSIsContainer=$false;Attributes=$regular},[pscustomobject]@{Name='sshbridge.exe';PSIsContainer=$false;Attributes=$regular})
    Assert-LinuxControlEntries $entries $ownerId
    Assert-Rejected {Assert-LinuxControlEntries @([pscustomobject]@{Name='client.key';PSIsContainer=$false;Attributes=$regular}) $ownerId} 'a private or unexpected cleanup file'
    Assert-Rejected {Assert-LinuxControlEntries @([pscustomobject]@{Name='sshbridge.exe';PSIsContainer=$false;Attributes=[IO.FileAttributes]::ReparsePoint}) $ownerId} 'a cache reparse point'
    Assert-Rejected {Assert-LinuxControlEntries @([pscustomobject]@{Name='owner.json';PSIsContainer=$true;Attributes=$regular}) $ownerId} 'a nested cache directory'
    $stream=[IO.MemoryStream]::new();$algorithm=[Security.Cryptography.SHA256]::Create()
    try{
        $publicBytes=[byte[]]@(0,255,127,42)
        $hash=([BitConverter]::ToString($algorithm.ComputeHash($publicBytes))).Replace('-','').ToLowerInvariant()
        $encoded=[Convert]::ToBase64String($publicBytes)
        $receipt=Write-LinuxControlChunk $stream 0 $encoded $hash 4
        if($receipt.offset-ne0-or$receipt.bytes-ne4-or$receipt.sha256-cne$hash-or[Convert]::ToBase64String($stream.ToArray())-cne$encoded){throw 'Chunk receipt or exact bytes differ.'}
        Assert-Rejected {Write-LinuxControlChunk $stream 0 $encoded $hash 4} 'a repeated append after acknowledgement'
        Assert-Rejected {Write-LinuxControlChunk $stream 4 $encoded ('b'*64) 8} 'a corrupt chunk'
        Assert-Rejected {Write-LinuxControlChunk $stream 4 $encoded $hash 4} 'a chunk exceeding the exact source length'
        Assert-Rejected {Write-LinuxControlChunk $stream 4 '!!' $hash 8} 'malformed base64'
        $oversize=[byte[]]::new(262145)
        Assert-Rejected {Write-LinuxControlChunk $stream 4 ([Convert]::ToBase64String($oversize)) $hash 33554432} 'an oversized public chunk'
        if($stream.Length-ne4){throw 'A rejected chunk modified the stream.'}
        $boundary=[byte[]]::new(262144);$boundary[262143]=42
        $boundaryHash=([BitConverter]::ToString($algorithm.ComputeHash($boundary))).Replace('-','').ToLowerInvariant()
        $boundaryReceipt=Write-LinuxControlChunk $stream 4 ([Convert]::ToBase64String($boundary)) $boundaryHash 262148
        if($boundaryReceipt.bytes-ne262144-or$stream.Length-ne262148){throw 'The public chunk boundary failed.'}
    }finally{$algorithm.Dispose();$stream.Dispose()}
    $cacheFunction=$ast.Find({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq'Get-LinuxControlSession'},$true)
    if($cacheFunction.Extent.Text-match'Copy-Item'){throw 'Public bridge staging still uses an unbounded bulk copy.'}
    $script:controlCalls=0;$script:controlStops=0;$script:controlRemovals=0;$script:simulateControlTimeout=$false
    $script:controlCloses=0;$script:controlSessionAbandoned=$false
    $script:state.id=$ownerId;$script:controlMember=$expectedCache.member_id;$script:controlProfile=$expectedCache.profile_id
    function Invoke-Command($Session,$ScriptBlock,$ArgumentList,[switch]$AsJob){$script:controlCalls++;if(-not$AsJob){throw 'Control request is not bounded by a job.'};[pscustomobject]@{State='Running';InstanceId=[guid]::NewGuid()}}
    function Wait-Job($Job,$Timeout){if($Timeout-ne30){throw 'Unexpected control deadline.'};if(-not$script:simulateControlTimeout){$Job.State='Completed';return $Job}}
    function Receive-Job($Job){[pscustomobject]@{fixture='control-result'}}
    function Stop-Job($Job){$script:controlStops++;throw 'Synchronous Stop-Job would block on the unresponsive transport.'}
    function Remove-Job($Job,[switch]$Force){$script:controlRemovals++}
    $transport=[pscustomobject]@{}
    $transport|Add-Member ScriptMethod CloseAsync {$script:controlCloses++}
    $controlSession=[pscustomobject]@{Runspace=$transport;InstanceId=[guid]::NewGuid()}
    $reply=Invoke-LinuxControlCommand $controlSession {} @('Inspect',$expectedCache)
    if($reply.fixture-cne'control-result'-or$script:controlCalls-ne1-or$script:controlStops-ne0-or$script:controlRemovals-ne1){throw 'Successful control request did not dispose its job.'}
    $script:simulateControlTimeout=$true
    $deadlineFailure=$null
    try {Invoke-LinuxControlCommand $controlSession {} @('Inspect',$expectedCache)} catch {$deadlineFailure=$_}
    if(-not$deadlineFailure-or$deadlineFailure.Exception.Message-notmatch'exceeded its deadline'-or$script:controlCalls-ne2-or$script:controlStops-ne0-or$script:controlRemovals-ne1-or$script:controlCloses-ne1){throw 'Deadline cleanup synchronously stopped/disposed an unresponsive job, retried, or lost the original timeout.'}
    $pendingPath=Join-Path $script:root 'control-reconciliation-required.json'
    $pending=Get-Content -LiteralPath $pendingPath -Raw|ConvertFrom-Json
    if($pending.owner_id-cne$ownerId-or$pending.member_id-cne$script:controlMember-or$pending.profile_id-cne$script:controlProfile-or$pending.session_id-cne$controlSession.InstanceId.ToString()-or$pending.guest_retirement_verified-or$pending.operation_retried){throw 'Timeout reconciliation journal lost its public identity or claimed retirement.'}
    $permitted=@('schema_version','purpose','owner_id','member_id','profile_id','host_process_id','session_id','job_id','utc','guest_retirement_verified','operation_retried')
    if(@($pending.PSObject.Properties.Name|Where-Object{$_-cnotin$permitted}).Count){throw 'Timeout journal contains non-public request data.'}
    # A fresh helper invocation has no in-memory abandoned-session flag. The
    # retained journal must still reject it before any remoting dispatch.
    $script:controlSessionAbandoned=$false
    Assert-Rejected {Invoke-LinuxControlCommand $controlSession {} @('Exec','synthetic-secret-never-dispatched')} 'a request before independent timeout reconciliation'
    if($script:controlCalls-ne2){throw 'An unreconciled timeout allowed another request.'}
    Assert-Rejected {Save-LinuxControlReconciliation $controlSession ([pscustomobject]@{InstanceId=[guid]::NewGuid()})} 'replacement of a retained timeout journal'
    Write-Output 'PASS: public bridge cache binds exact identities and chunks; timeout cleanup never synchronously stops/disposes an unconfirmed job, falsely confirms retirement, retries, or persists request data.'
    $outer=$ast.Find({param($node)$node-is[Management.Automation.Language.TryStatementAst]-and$node.Body.Extent.Text.Contains('$mutex.WaitOne(0)')},$true)
    if(-not$outer-or-not$outer.Finally){throw 'Cannot locate the main transport finalizer.'}
    $finalize=[ScriptBlock]::Create('& '+$outer.Finally.Extent.Text)
    $script:releaseCount=0;$script:disposeCount=0
    $mutex=[pscustomobject]@{}
    $mutex|Add-Member ScriptMethod ReleaseMutex {$script:releaseCount++}
    $mutex|Add-Member ScriptMethod Dispose {$script:disposeCount++}
    function Remove-PSSession($Session){throw 'Simulated session close failure.'}
    $script:controlSessionAbandoned=$false
    $held=$true;$script:session='fixture-session';$InputBytes=[byte[]]@(1,2,3);$finalInput=$InputBytes
    Assert-Rejected {& $finalize} 'a simulated session close failure'
    if($script:releaseCount-ne1-or$script:disposeCount-ne1-or@($finalInput|Where-Object{$_-ne0}).Count){throw 'Session cleanup failure leaked stdin or the transport mutex.'}
    $script:controlSessionAbandoned=$true
    $InputBytes=[byte[]]@(4,5,6);$abandonedInput=$InputBytes
    & $finalize
    if($script:releaseCount-ne2-or$script:disposeCount-ne2-or@($abandonedInput|Where-Object{$_-ne0}).Count){throw 'Abandoned transport cleanup leaked stdin/mutex or tried synchronous session closure.'}
    $script:controlSessionAbandoned=$false
    $script:session=$null
    Write-Output 'PASS: transport mutex and stdin are released even when session closure fails.'

    # Exercise the actual Exec clause without loading Hyper-V or using SSH.
    $actionSwitch=$ast.Find({param($node) $node -is [Management.Automation.Language.SwitchStatementAst] -and $node.Condition.Extent.Text -ceq '$Action'},$true)
    $execClause=@($actionSwitch.Clauses | Where-Object {$_.Item1.Value -ceq 'Exec'})
    if ($execClause.Count -ne 1) {throw 'Cannot locate the production Exec branch.'}
    $execute=[ScriptBlock]::Create('& '+$execClause[0].Item2.Extent.Text)
    function Invoke-LinuxSSH([string]$RemoteCommand,[byte[]]$Payload) {
        if ($RemoteCommand -cne 'fixture-command') {throw 'The control command changed.'}
        $script:observedInput=$Payload.Clone()
        $script:bridgeCalls++
        if ($script:simulateSshFailure) {throw 'Simulated SSH failure.'}
        [pscustomobject]@{exit_code=0;stdout='fixture-output';stderr=''}
    }
    $script:bridgeCalls=0;$script:simulateSshFailure=$false
    $Command='fixture-command'
    $InputBytes=[Text.Encoding]::UTF8.GetBytes("synthetic-stdin-437`0exact bytes`r`n")
    $callerBytes=$InputBytes;$expected=$InputBytes.Clone()
    $allStreams=@(& $execute *>&1)
    if ([Convert]::ToBase64String($script:observedInput) -cne [Convert]::ToBase64String($expected)) {throw 'Exec altered stdin bytes.'}
    if (@($callerBytes | Where-Object {$_ -ne 0}).Count) {throw 'Exec did not clear caller input after success.'}
    if ($allStreams.Count -ne 1 -or $allStreams[0].stdout -cne 'fixture-output' -or ($allStreams | Out-String).Contains('synthetic-stdin-437')) {throw 'Exec emitted stdin or unexpected output.'}
    $InputBytes=[byte[]]::new(65536);$InputBytes[65535]=42;$boundaryBytes=$InputBytes
    $null=& $execute
    if ($script:observedInput.Length -ne 65536 -or $script:observedInput[65535] -ne 42 -or $boundaryBytes[65535] -ne 0) {throw 'Exec failed the 64 KiB boundary.'}
    $InputBytes=[byte[]]::new(65537);$InputBytes[0]=42;$oversizeBytes=$InputBytes
    Assert-Rejected {& $execute} 'oversized stdin'
    if ($script:bridgeCalls -ne 2 -or $oversizeBytes[0] -ne 0) {throw 'Oversized stdin reached SSH or was not cleared.'}
    $script:simulateSshFailure=$true;$InputBytes=[byte[]]@(1,2,3);$failedBytes=$InputBytes
    Assert-Rejected {& $execute} 'a simulated SSH failure'
    if (@($failedBytes | Where-Object {$_ -ne 0}).Count) {throw 'Exec did not clear stdin after SSH failure.'}
    Write-Output 'PASS: Exec forwards exact binary stdin, emits no input, clears success/failure inputs, and rejects payloads over 64 KiB before SSH.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    if (-not $resolved.StartsWith($temporary+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe test cleanup path.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
