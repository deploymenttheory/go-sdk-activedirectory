#Requires -Version 5.1
# Root-reviewed execution only. Starts only the existing owned member, makes one
# SDK call, then uses normal shutdown after known completion. No guest configure.
param([Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedGuestSHA256)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Import-HostPrimitives([string]$Path) {
    if((Get-FileHash -LiteralPath $Path).Hash -cne '116353985A315D63E60B16B3386B8E305B965F9D36FEA131D80A6B8F999C06BE') { throw 'Frozen host support changed.' }
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count) { throw 'Frozen host support parse failed.' }
    foreach($name in @('Assert-UnlinkedPath','Assert-OwnedControllers','Assert-SwitchPorts','Write-NewHostBytes','Write-NewHostJson','Get-ProfileMutexName','Write-RunState','Wait-OwnedJob','Assert-NewRunDirectory')) {
        $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
        if($definitions.Count -ne 1) { throw 'Host primitive is missing or duplicated.' }
        $definition=$definitions[0].Extent.Text
        if($name -ceq 'Assert-OwnedControllers') {
            $old="name='ADSDK25MEM';power='Off'"
            if(([regex]::Matches($definition,[regex]::Escape($old))).Count -ne 1) { throw 'Expected member power guard is missing.' }
            $definition=$definition.Replace($old,'name=''ADSDK25MEM'';power=$memberPower')
        }
        # Only function scope changes; no frozen entrypoint executes.
        $definition=$definition.Replace('function '+$name+' ','function script:'+$name+' ')
        $definition=$definition.Replace('function '+$name+'(','function script:'+$name+'(')
        . ([scriptblock]::Create($definition))
    }
}
function Assert-MemberOwnership {
    Assert-OwnedControllers
    $member=Get-VM -Id ([guid]$machine.id)
    $disks=@(Get-VMHardDiskDrive -VM $member)
    $diskPath=Join-Path $profile 'ADSDK25MEM\os.vhdx'
    if($disks.Count -ne 1 -or (Assert-UnlinkedPath $disks[0].Path) -cne $diskPath -or $member.Generation -ne 2) { throw 'Exact member disk/generation differs.' }
    $vhd=Get-VHD -Path $diskPath
    if($vhd.VhdType -ne 'Differencing' -or (Assert-UnlinkedPath $vhd.ParentPath) -cne (Join-Path $profile 'base.vhdx')) { throw 'Owned member disk parent differs.' }
}
function Wait-MemberJob($Job,[int]$TimeoutSeconds,[string]$Action) {
    if($script:guestUncertain) { throw 'Prior guest/job uncertainty forbids another wait boundary.' }
    $values=@(Wait-OwnedJob $Job $TimeoutSeconds $Action)
    # Frozen Wait-OwnedJob may return normally while its finally block records
    # Remove-Job failure. No subsequent dispatch may erase that uncertainty.
    if($script:guestUncertain) { throw 'Owned job returned with completion/evidence cleanup uncertainty.' }
    return $values
}
function Read-MemberOutcome($Returned) {
    if($script:guestUncertain) { throw 'Prior guest/job uncertainty cannot be cleared by a returned payload.' }
    # A completed remoting job alone does not prove native child completion.
    $script:guestUncertain=$true
    $values=@($Returned)
    if($values.Count -ne 1 -or $values[0] -isnot [string]) { throw 'Guest return cardinality/type differs.' }
    $envelope=$values[0]|ConvertFrom-Json -ErrorAction Stop;$summary=$envelope.summary
    foreach($field in @('terminal','passed','child_invoked','process_uncertain','capture_failed','staging_preserved','part_of_domain')) {
        if($summary.$field -isnot [bool]) { throw 'Guest safety state is untyped.' }
    }
    if($envelope.schema_version -ne 1 -or $envelope.run -cne $executionID -or $summary.schema_version -ne 1 -or $summary.run -cne $executionID -or
        $summary.computer -cne 'ADSDK25MEM' -or $summary.cim_domain_role -ne 2 -or $summary.product_type -ne 3 -or $summary.os_build -cne '26100' -or $summary.part_of_domain -or
        $summary.source_commit -cne '59346e9641feada4915a3313273ee2fc845bdbeb' -or $summary.helper_sha256 -cne '09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957' -or
        -not $summary.terminal -or -not $summary.child_invoked -or $summary.process_uncertain -or $summary.capture_failed -or -not $summary.staging_preserved -or
        $summary.process.completed -isnot [bool] -or -not $summary.process.completed -or $summary.process.process_uncertain -isnot [bool] -or $summary.process.process_uncertain -or
        $null -eq $summary.process.exit_code -or $summary.process.pid -le 0 -or -not $summary.process.started_utc -or $null -ne $summary.process.error -or
        ($summary.passed -and ($null -ne $summary.error -or @($summary.output_files).Count -ne 0))) { throw 'Guest result lacks known child completion or expected identity.' }
    $names=@('owner.txt','options.json','sdk.requested.json','sdk.started.json','sdk.finished.json','sdk.stdout.txt','sdk.stderr.txt','summary.json')
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $decoded=@{}
    foreach($artifact in @($envelope.artifacts)) {
        if($artifact.name -cnotin $names -or -not $seen.Add($artifact.name) -or $artifact.sha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'Unexpected/duplicate capture artifact.' }
        $bytes=[Convert]::FromBase64String($artifact.base64)
        $hasher=[Security.Cryptography.SHA256]::Create()
        try { $hash=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','') } finally { $hasher.Dispose() }
        if($bytes.Length -gt 2097152 -or $bytes.Length -ne $artifact.bytes -or $hash -cne $artifact.sha256) { throw 'Captured bytes differ.' }
        $decoded[$artifact.name]=$bytes
    }
    if($seen.Count -ne $names.Count) { throw 'Capture is incomplete.' }
    $rawSummary=[Text.Encoding]::UTF8.GetString($decoded['summary.json'])|ConvertFrom-Json
    if(($rawSummary|ConvertTo-Json -Depth 24 -Compress) -cne ($summary|ConvertTo-Json -Depth 24 -Compress)) { throw 'Raw summary differs from returned summary.' }
    foreach($stream in @('stdout','stderr')) {
        $item=@($envelope.artifacts|Where-Object name -ceq ('sdk.'+$stream+'.txt'))[0]
        if($item.sha256 -cne $summary.process.($stream+'_sha256')) { throw 'Raw stream differs from held child record.' }
    }
    foreach($name in $names) { Write-NewHostBytes (Join-Path $resultRoot $name) $decoded[$name] }
    $script:guestUncertain=$false
    return $summary
}
function Restore-OwnedMemberOff {
    if($script:guestUncertain) { throw 'Unknown guest/job completion forbids shutdown.' }
    Assert-MemberOwnership
    $runState.phase='normal-shutdown-requested';Write-RunState
    try {
        $job=Stop-VM -VM (Get-VM -Id ([guid]$machine.id)) -AsJob -Confirm:$false -ErrorAction Stop
        $null=Wait-MemberJob $job 150 'normal-member-shutdown'
    } catch { $script:guestUncertain=$true;throw }
    $memberPower='Off';Assert-MemberOwnership
    $runState.final_power='Off';$runState.power_restored=$true;Write-RunState
}
$profile='H:\ad-sdk-lab\server2025'
$statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml'
$stateHash='F11DBEEAB66BB28B2EDF9A6CCA57B510AD76C5505BD2F5FDCBF2010E569619FE'
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T232022Z-008266ad'
$executionID='clone-config-unsupported-server2025-59346e9-v1'
$memberPower='Off';$machine=[pscustomobject]@{id='80aa4382-c228-489c-b5f7-007c7feee3ff';name='ADSDK25MEM'}
$script:guestUncertain=$false;$runState=$null;$operationMutex=$null;$mutexHeld=$false;$startedKnown=$false
Import-HostPrimitives (Join-Path $PSScriptRoot 'run-clone-config-offline.ps1')
try {
    $operationMutex=[Threading.Mutex]::new($false,(Get-ProfileMutexName $profile))
    try { $mutexHeld=$operationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld=$true }
    if(-not $mutexHeld) { throw 'Owned profile is busy.' }
    Import-Module Hyper-V -ErrorAction Stop
    Assert-MemberOwnership
    $state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
    if($state.configured -isnot [bool] -or $state.configured) { throw 'Expected unconfigured member profile differs.' }
    $guestPath=Assert-UnlinkedPath (Join-Path $PSScriptRoot 'guest-clone-config-unsupported-member.ps1')
    if((Get-FileHash -LiteralPath $guestPath).Hash -cne $ExpectedGuestSHA256) { throw 'Reviewed guest differs.' }
    $paths=[ordered]@{
        'clone-config-helper.exe'=@((Join-Path $buildRoot 'helper-v4\clone-config-helper.exe'),'09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957')
        'helper-v4-build.json'=@((Join-Path $buildRoot 'helper-v4\build.json'),'362DE5A85947FFDE1DB6571617F5AA908037553661F899B6A32E4E22DF38E377')
        'build.json'=@((Join-Path $buildRoot 'build.json'),'386ECB6700D11F28EBD4B4A9033392A9DAD03968AC0E5BE2E7AB60859E1F141F')
        'negative-process-support.ps1'=@((Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1'),'2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D')
    }
    $payload=[ordered]@{}
    foreach($name in $paths.Keys) {
        $path=Assert-UnlinkedPath $paths[$name][0]
        if((Get-FileHash -LiteralPath $path).Hash -cne $paths[$name][1]) { throw 'Pinned artifact differs.' }
        $payload[$name]=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
    }
    $archive=Assert-UnlinkedPath (Join-Path $buildRoot 'source.zip')
    if((Get-FileHash -LiteralPath $archive).Hash -cne 'D8D05B12B9678D0B11A7EA5081FEE24FAD4B9C44E185F1C91DECD2228B9E8B05') { throw 'SDK source archive differs.' }
    $resultRoot=Assert-NewRunDirectory (Join-Path $buildRoot 'server2025-unsupported-member-v1');[void][IO.Directory]::CreateDirectory($resultRoot)
    $runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'run-journal.json'
    $runState=[ordered]@{schema_version=1;owner=$runOwner;execution_id=$executionID;phase='prepared';terminal=$false;guest_uncertain=$false;jobs=@();passed=$false;error=$null;updated=$null;initial_power='Off';final_power=$null;power_restored=$false;lab_state_sha256=$stateHash;vm_id=$machine.id;source_archive_sha256='D8D05B12B9678D0B11A7EA5081FEE24FAD4B9C44E185F1C91DECD2228B9E8B05';host_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash;guest_sha256=$ExpectedGuestSHA256;staging_preserved=$true}
    Write-RunState
    Write-NewHostBytes (Join-Path $resultRoot 'host.ps1') ([IO.File]::ReadAllBytes($PSCommandPath))
    Write-NewHostBytes (Join-Path $resultRoot 'guest.ps1') ([IO.File]::ReadAllBytes($guestPath))
    foreach($name in @('build.json','helper-v4-build.json','negative-process-support.ps1')) { Write-NewHostBytes (Join-Path $resultRoot $name) ([Convert]::FromBase64String($payload[$name])) }
    $saved=Import-Clixml -LiteralPath $credentialPath
    if($saved -isnot [PSCredential]) { throw 'Owned encrypted credential is not a credential.' }
    $credential=[PSCredential]::new('ADSDK25MEM\Administrator',$saved.Password)
    Assert-MemberOwnership
    $runState.phase='member-start-requested';Write-RunState
    try { $job=Start-VM -VM (Get-VM -Id ([guid]$machine.id)) -AsJob -ErrorAction Stop;$null=Wait-MemberJob $job 120 'start-member' } catch { $script:guestUncertain=$true;throw }
    $startedKnown=$true;$memberPower='Running';Assert-MemberOwnership
    $job=Wait-VM -VM (Get-VM -Id ([guid]$machine.id)) -For Heartbeat -Delay 20 -Timeout 120 -AsJob -ErrorAction Stop
    $null=Wait-MemberJob $job 150 'member-heartbeat'
    Assert-MemberOwnership
    if((Get-FileHash -LiteralPath $guestPath).Hash -cne $ExpectedGuestSHA256) { throw 'Guest script changed before dispatch.' }
    $runState.phase='one-sdk-probe-requested';Write-RunState
    try {
        $job=Invoke-Command -VMId ([guid]$machine.id) -Credential $credential -FilePath $guestPath -ArgumentList ($payload|ConvertTo-Json -Compress) -AsJob -ErrorAction Stop
        $returned=@(Wait-MemberJob $job 120 'unsupported-member-probe')
    } catch { $script:guestUncertain=$true;throw }
    Write-NewHostJson (Join-Path $resultRoot 'guest-return.json') ([ordered]@{payload=$returned})
    $summary=Read-MemberOutcome $returned
    $runState.passed=$summary.passed;Write-RunState
    if(-not $summary.passed) { throw 'Known-complete unsupported-host observation failed; retain original evidence.' }
} catch { if($null -ne $runState) { $runState.error=$_.Exception.Message };throw }
finally {
    try {
        if($null -ne $runState) {
            if($startedKnown -and -not $script:guestUncertain) {
                try { Restore-OwnedMemberOff } catch { $runState.passed=$false;$runState.error=$_.Exception.Message }
            }
            $runState.passed=[bool]($runState.passed -and $runState.power_restored -and -not $script:guestUncertain)
            $runState.terminal=$true;$runState.phase=if($runState.passed){'passed-member-restored-off'}else{'failed-preserve-for-review'}
            Write-RunState;Write-NewHostJson (Join-Path $resultRoot 'qualification.json') $runState
        }
    } finally { if($mutexHeld){$operationMutex.ReleaseMutex()};if($operationMutex){$operationMutex.Dispose()} }
}
if(-not $runState.passed) { throw 'Probe or graceful power restoration failed; inspect retained evidence.' }
[ordered]@{directory=$resultRoot;passed=$runState.passed;final_power=$runState.final_power;power_restored=$runState.power_restored}|ConvertTo-Json
