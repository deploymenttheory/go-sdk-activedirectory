#Requires -Version 7.0
# Offline ownership-boundary tests. No Hyper-V, keys, or lab credentials are used.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'portable-linux.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'The Linux orchestration script does not parse.'}
foreach ($name in @('Assert-LinuxPath','Assert-LinuxState')) {
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
