#Requires -Version 5.1
# Exercise the production helpers with injected filesystem/process boundaries.
# No guests, processes, certificate stores, or firewall rules are accessed.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$source=Join-Path $PSScriptRoot 'guest-lds-tls-peer.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'TLS peer script syntax error.'}
foreach($name in @('Get-PeerError','Assert-PeerPath','Assert-OwnedPeerProcess','Stop-PeerProcess','Stop-OwnedPeer','Start-OwnedPeer','Invoke-PeerCleanup')) {
    $node=$ast.Find({param($candidate) $candidate -is [Management.Automation.Language.FunctionDefinitionAst] -and $candidate.Name -eq $name},$false)
    if(-not $node){throw "Missing production helper: $name"}
    . ([scriptblock]::Create($node.Extent.Text))
}
$runRoot='C:\ad-sdk-lds\owned\tls-peers\run'
$marker='owned-marker';$PeerHash='owned-hash'
function New-TestPeerEntry {
    return [pscustomobject]@{name='valid-ldaps';marker=$marker;pid=0;started='';phase='reserved';process_stopped=$false}
}

function Test-IndependentCleanup([string]$Case) {
    $state=[pscustomobject]@{cases=@([pscustomobject]@{name='first'},[pscustomobject]@{name='second'});phase='ready'}
    $events=[Collections.Generic.List[string]]::new()
    $fixture=@{saves=0}
    function Remove-PeerFirewall($Entry) {
        $events.Add('firewall:'+$Entry.name)
        if($Case -eq 'combined' -and $Entry.name -eq 'first'){throw [IO.IOException]::new('private-firewall-failure')}
    }
    function Stop-OwnedPeer($Entry) {
        $events.Add('process:'+$Entry.name)
        if($Case -eq 'combined' -and $Entry.name -eq 'first'){throw [InvalidOperationException]::new('private-process-failure')}
    }
    function Save-PeerOwner {
        $fixture.saves++;$events.Add('save:'+$fixture.saves)
        if($Case -in @('all-saves','combined') -or ($Case -eq 'first-save' -and $fixture.saves -eq 1) -or ($Case -eq 'final-save' -and $fixture.saves -eq 3)){throw [IO.IOException]::new('private-save-failure')}
    }
    function Remove-PeerTrust {
        $events.Add('trust')
        if($Case -eq 'combined'){throw [InvalidOperationException]::new('private-trust-failure')}
    }
    $observed=@(Invoke-PeerCleanup)
    $expected='firewall:first,process:first,save:1,firewall:second,process:second,save:2,trust,save:3'
    if(($events -join ',') -cne $expected){throw "Independent cleanup stopped early: $Case"}
    $count=switch($Case){'success'{0};'first-save'{1};'final-save'{1};'all-saves'{3};'combined'{6}}
    if($observed.Count -ne $count -or ($observed | ConvertTo-Json -Depth 8 -Compress) -match 'private-'){throw "Cleanup errors were lost or disclosed: $Case"}
    if(($state.phase -eq 'cleaned') -ne ($Case -eq 'success')){throw "Cleanup status differs: $Case"}
}
foreach($case in @('success','first-save','final-save','all-saves','combined')){Test-IndependentCleanup $case}
'5 independent-cleanup cases passed'

function Test-UnrecordedPeer([string]$Case) {
    $entry=New-TestPeerEntry
    $fixture=@{queries=0}
    if($Case -eq 'missing-start-time'){$entry.pid=4242}
    if($Case -eq 'foreign-marker'){$entry.marker='foreign'}
    function Test-Path {param($LiteralPath) return $false}
    function Get-CimInstance {
        [CmdletBinding()]param($ClassName,$Filter)
        $fixture.queries++
        if($ClassName -ne 'Win32_Process' -or $Filter -cne "Name='tls-peer.exe'" -or $PSBoundParameters.ErrorAction -ne 'Stop'){throw 'Unexpected reconciliation query.'}
        switch($Case) {
            'query-failure' {throw [IO.IOException]::new('private-query-failure')}
            'unrelated' {return [pscustomobject]@{ExecutablePath='C:\unrelated\tls-peer.exe'}}
            'unknown-path' {return [pscustomobject]@{ExecutablePath=$null}}
            'present' {return [pscustomobject]@{ExecutablePath=(Join-Path $runRoot 'tls-peer.exe')}}
            'missing-start-time' {return [pscustomobject]@{ExecutablePath=(Join-Path $runRoot 'tls-peer.exe')}}
        }
    }
    $caught=$null
    try {Stop-OwnedPeer $entry}catch{$caught=$_}
    $absent=$Case -in @('absent','unrelated')
    if($entry.process_stopped -ne $absent -or ($null -eq $caught) -ne $absent){throw "Unrecorded process did not fail closed: $Case"}
    if($fixture.queries -ne $(if($Case -eq 'foreign-marker'){0}else{1})){throw "Reconciliation skipped its authoritative query: $Case"}
}
foreach($case in @('absent','unrelated','present','unknown-path','query-failure','foreign-marker','missing-start-time')){Test-UnrecordedPeer $case}
'7 unrecorded-process reconciliation cases passed'

function Test-LaunchRollback([string]$Case) {
    $entry=New-TestPeerEntry
    $state=[pscustomobject]@{owner_sid='owned-sid'}
    $binary=Join-Path $runRoot 'tls-peer.exe';$caseRoot=Join-Path $runRoot $entry.name
    $fixture=@{saves=0;starts=0;queries=0;persisted=$null}
    $fakeProcess=[pscustomobject]@{
        Id=4242;StartTime=[DateTime]::Parse('2026-11-12T12:00:00Z').ToUniversalTime();Handle=[IntPtr]1
        HasExited=$false;Killed=0;Waited=0;Disposed=$false;KillFails=($Case -eq 'kill-failure');WaitFails=($Case -eq 'wait-failure')
    }
    $fakeProcess | Add-Member ScriptMethod Kill { $this.Killed++;if($this.KillFails){throw [InvalidOperationException]::new('private-kill-failure')} }
    $fakeProcess | Add-Member ScriptMethod WaitForExit {param($Milliseconds) $this.Waited++;if($Milliseconds -ne 5000){throw 'Unbounded process wait.'};if($this.WaitFails){return $false};$this.HasExited=$true;return $true}
    $fakeProcess | Add-Member ScriptMethod Dispose { $this.Disposed=$true }
    function Test-Path {param($LiteralPath) return $false}
    function Get-FileHash {param($LiteralPath) if($LiteralPath -ine $binary){throw 'Unexpected executable hash path.'};return [pscustomobject]@{Hash=$PeerHash}}
    function Save-PeerOwner {
        $fixture.saves++
        if(($Case -eq 'prelaunch-save' -and $fixture.saves -eq 1) -or ($Case -notin @('success','prelaunch-save','start-error-present','start-error-absent') -and $fixture.saves -eq 2) -or ($Case -eq 'rollback-save' -and $fixture.saves -eq 3)){throw [IO.IOException]::new('private-persistence-failure')}
        $fixture.persisted=$entry | ConvertTo-Json | ConvertFrom-Json
    }
    function Start-Process {
        param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError)
        $fixture.starts++
        if($FilePath -ine $binary -or $WindowStyle -ne 'Hidden' -or -not $PassThru -or $RedirectStandardOutput -ine "$caseRoot\stdout.log" -or $RedirectStandardError -ine "$caseRoot\stderr.log"){throw 'Unexpected launch boundary.'}
        if($Case -in @('start-error-present','start-error-absent')){throw [InvalidOperationException]::new('private-uncertain-start')}
        return $fakeProcess
    }
    function Get-CimInstance {
        [CmdletBinding()]param($ClassName,$Filter)
        $fixture.queries++
        if($PSBoundParameters.ErrorAction -ne 'Stop'){throw 'Process query must terminate on failure.'}
        if($Case -eq 'query-failure'){throw [IO.IOException]::new('private-query-failure')}
        if($Case -eq 'start-error-absent'){return}
        if($Case -eq 'missing-process'){return}
        return [pscustomobject]@{ExecutablePath=$binary;CommandLine=($binary+' -ready '+$caseRoot+'\ready.json')}
    }
    function Invoke-CimMethod {
        [CmdletBinding()]param($InputObject,$MethodName)
        return [pscustomobject]@{ReturnValue=0;Sid=$(if($Case -eq 'foreign-owner'){'foreign'}else{'owned-sid'})}
    }
    $caught=$null
    try {Start-OwnedPeer $entry $binary 'owned-arguments' $caseRoot}catch{$caught=$_}
    if(($null -eq $caught) -ne ($Case -eq 'success')){throw "Launch outcome differs: $Case"}
    if($caught -and (@(Get-PeerError $caught) | ConvertTo-Json -Depth 10 -Compress) -match 'private-'){throw 'Launch evidence disclosed private error text.'}
    $launched=$Case -notin @('prelaunch-save','start-error-present','start-error-absent')
    if($fakeProcess.Disposed -ne $launched){throw "Owned live handle was not disposed: $Case"}
    $stopped=$Case -in @('persistence','rollback-save','prelaunch-save','start-error-absent')
    if($entry.process_stopped -ne $stopped){throw "Launch rollback claimed an unconfirmed stop: $Case"}
    $killExpected=$Case -in @('persistence','rollback-save','kill-failure','wait-failure')
    if($fakeProcess.Killed -ne [int]$killExpected){throw "Launch rollback bypassed ownership or skipped its live handle: $Case"}
    if($Case -eq 'rollback-save') {
        if($fixture.persisted.pid -ne 0 -or $fixture.persisted.phase -ne 'launching' -or $fixture.persisted.process_stopped){throw 'Failed rollback save did not retain uncertain durable state.'}
        $details=@(Get-PeerError $caught)
        if(@($details | Where-Object type -eq 'System.IO.IOException').Count -ne 2){throw 'Original and rollback persistence failures were not both retained.'}
    } elseif($Case -ne 'success') {
        $phase=if($stopped){'launch-failed-stopped'}else{'launch-uncertain'}
        if($fixture.persisted.phase -ne $phase -or $fixture.persisted.process_stopped -ne $stopped){throw "Durable rollback state differs: $Case"}
    }
    if($Case -eq 'prelaunch-save' -and $fixture.starts){throw 'Launch occurred without durable intent.'}
    if($Case -in @('start-error-present','start-error-absent') -and $fixture.queries -ne 1){throw 'Unknown launch skipped reconciliation.'}
}
foreach($case in @('success','persistence','rollback-save','kill-failure','wait-failure','query-failure','foreign-owner','missing-process','prelaunch-save','start-error-present','start-error-absent')){Test-LaunchRollback $case}
'11 launch/persistence rollback cases passed'
('Windows PowerShell '+$PSVersionTable.PSVersion.ToString()+': 23 cleanup regressions passed without guest operations')
