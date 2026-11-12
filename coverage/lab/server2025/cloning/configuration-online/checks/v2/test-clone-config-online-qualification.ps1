#Requires -Version 5.1
# Offline functions, synthetic files and fake directory/native results only.
param([string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;$script:checks=0
function Check([bool]$Value,[string]$Message) { if(-not $Value) { throw $Message };$script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $failed=$false;try { & $Action } catch { $failed=$true };Check $failed $Message }
function Clone($Value) { return ($Value | ConvertTo-Json -Depth 32 | ConvertFrom-Json) }
$guestPath=Join-Path $PSScriptRoot 'guest-clone-config-online-qualification.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($guestPath,[ref]$tokens,[ref]$errors);Check ($errors.Count -eq 0) 'Guest parse failed.'
function Import-Definition([string]$Name) {
    $found=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $Name)
    if($found.Count -ne 1) { throw 'Expected one guest function.' }
    $text=$found[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($Name)+'(?=[\s(])'),('function script:'+$Name)
    . ([scriptblock]::Create($text))
}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) { Import-Definition $definition.Name }
Import-OnlineFunctions (Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1') @('Bytes-Hash','Write-NewBytes','Write-NewJson','Error-Observation')
Import-OnlineFunctions (Join-Path $PSScriptRoot 'get-clone-config-online-prerequisites.ps1') @('Read-InventoryItem','Inventory-SID')
$commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
foreach($name in @('Start-VM','Stop-VM','Restart-VM','Remove-VM','Set-Acl','Set-ItemProperty','Add-ADGroupMember','Remove-ADGroupMember','Stop-Process')) { Check ($name -notin $commands) "Unrequested operation: $name" }
Check ($ast.Extent.Text -notmatch '(RunAs|\.Kill\(|-Offline\b|-Recurse\b)') 'Guest contains elevation, forced termination, Offline, or recursive removal.'
$baselinePath=Join-Path $PSScriptRoot 'clone-config-online-baseline-inventory.json'
Check ((Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash -ceq (Get-OnlinePins)['inventory.json']) 'Baseline bytes differ.'
$baseline=Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
Check (@($baseline.applications.reference_entries).Count -eq 28) 'Baseline exclusion cardinality differs.'
$fixtureRoot=Join-Path $PSScriptRoot ('clone-config-online-tests-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixtureRoot)
$StageDirectory=$fixtureRoot;$Run='offline-fixture';$ExpectedScriptSHA256='A'*64;$NativeExecutable=Join-Path $fixtureRoot 'fake-helper.exe';$ReplicationTimeoutSeconds=2;$ProcessTimeoutSeconds=60
function Assert-StagePath([string]$Path) { $full=[IO.Path]::GetFullPath($Path);if(-not $full.StartsWith($StageDirectory+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Synthetic path escaped.' };return $full }
function Assert-OnlineStage {}
function Reset-Fixture {
    $script:processUncertain=$false;$script:publicationUncertain=$false;$script:mutationUncertain=$false;$script:captureFailed=$false;$script:eventNumber=0;$script:snapshotNumber=0
    $script:root=Join-Path $fixtureRoot ([guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($root);[void][IO.Directory]::CreateDirectory((Join-Path $root 'events'));[void][IO.Directory]::CreateDirectory((Join-Path $root 'snapshots'))
    $script:state=[ordered]@{phase='prepared';cases=@();completed=$false;passed=$false;cleanup_complete=$false;process_uncertain=$false;publication_uncertain=$false;mutation_uncertain=$false;capture_failed=$false;error=$null;recovery=[ordered]@{intent=$null;group_added=$false;custom_file=$null;config_file=$null}}
}
Reset-Fixture
foreach($flag in @('processUncertain','publicationUncertain','mutationUncertain','captureFailed')) { Set-Variable -Name $flag -Value $true -Scope Script;Reject { Assert-CanRun } "Unknown $flag did not stop work.";Set-Variable -Name $flag -Value $false -Scope Script }
$xmlBytes=Encode-OnlineInclusion $baseline.applications.reference_entries
$document=[Xml.XmlDocument]::new();$document.LoadXml([Text.Encoding]::UTF8.GetString($xmlBytes))
Check ($document.DocumentElement.NamespaceURI -ceq 'uri:microsoft.com:schemas:CustomDCCloneAllowList' -and $document.DocumentElement.SelectNodes('Allow').Count -eq 28) 'Inclusion namespace or count differs.'
Check ((($document.DocumentElement.SelectNodes('Allow/Name') | ForEach-Object {$_.InnerText}) -join ',') -ceq (($baseline.applications.reference_entries | ForEach-Object {$_.name}) -join ',')) 'Inclusion entries changed.'
foreach($entry in @([pscustomobject]@{type='Program';name='unreviewed'},[pscustomobject]@{type='Service';name=''})) { Reject { Encode-OnlineInclusion @($entry) } 'Unreviewed inclusion accepted.' }
$template='The local domain controller is not a member of the {0} security group.'
Check (Test-OnlineReferenceDiagnostic 'Start. The local domain controller is not a member of the Cloneable Domain Controllers security group. Stop.' $template) 'Version-owned refusal template was not recognized.'
Check (-not (Test-OnlineReferenceDiagnostic 'Checking Cloneable Domain Controllers. LDAP bind failed.' $template)) 'Unrelated failure counted as group refusal.'
Check (-not (Test-OnlineReferenceDiagnostic 'Pass: The local domain controller is a member of the Cloneable Domain Controllers security group.' $template)) 'Positive membership diagnostic counted as refusal.'
Check (Test-OnlineReferenceDiagnostic "Validation of the cloning allow list`r`nfailed. Please review." 'Validation of the cloning allow list failed. Please review.') 'Wrapped reference diagnostic was not recognized.'
foreach($template in @('','{0}','short',('x'*4097))) { Check (-not (Test-OnlineReferenceDiagnostic $template $template)) 'Insufficient reference template accepted.' }

# Real membership logic against fake DC objects, with actual member deltas logged.
$script:members=@();$script:mutations=@();$script:directoryFailure=$false
function Get-ADGroup { param($Identity,$Properties,$Server,$ErrorAction) if($script:directoryFailure){throw 'Directory read failed.'};return [pscustomobject]@{ObjectGUID=[guid]$baseline.directory.group_guid;DistinguishedName=$baseline.directory.group_dn;SID=$baseline.directory.group_sid;member=$script:members} }
function Get-ADComputer { param($Identity,$Properties,$Server,$ErrorAction) $added=($script:members -contains $baseline.directory.source_dn);$direct=@($baseline.directory.source_direct_groups);$tokens=@($baseline.directory.source_token_groups);if($added){$direct+=@($baseline.directory.group_dn);$tokens+=@($baseline.directory.group_sid)};return [pscustomobject]@{ObjectGUID=[guid]$baseline.directory.source_guid;DistinguishedName=$baseline.directory.source_dn;SID=$baseline.directory.source_sid;memberOf=$direct;tokenGroups=$tokens} }
function Get-ADPrincipalGroupMembership { param($Identity,$Server,$ErrorAction) foreach($row in $baseline.directory.source_reference_groups){[pscustomobject]@{SID=$row.sid}};if($script:members -contains $baseline.directory.source_dn){[pscustomobject]@{SID=$baseline.directory.group_sid}} }
function Set-ADObject { param($Identity,$Server,$Add,$Remove,$ErrorAction) $script:mutations+=@([pscustomobject]@{identity=$Identity.ToString();server=$Server;add=$Add;remove=$Remove});if($script:mutationThrow){throw 'Simulated uncertain directory write.'};if($Add){$script:members+=@($Add.member)}else{$script:members=@($script:members | Where-Object {$_ -cne $Remove.member})} }
$script:mutationThrow=$false
foreach($server in @('ADSDK25DC1.ad.sdk.test','ADSDK25DC2.ad.sdk.test')) { Assert-OnlineReplica (Read-OnlineReplica $server) $false;$script:checks++ }
Reject { Read-OnlineReplica 'OTHER' } 'Unexpected replica accepted.'
$script:members=@('foreign');Reject { Assert-OnlineReplica (Read-OnlineReplica 'ADSDK25DC1.ad.sdk.test') $false } 'Foreign group member accepted.';$script:members=@()
function New-MembershipCase([string]$Name) { $directory=Join-Path $root $Name;[void][IO.Directory]::CreateDirectory($directory);return [pscustomobject]@{name=$Name;kind='membership';expectation=$(if($Name -ceq 'add-direct-membership'){'member'}else{'absent'});output='C:\Windows\NTDS';computer_name='ADSDK25CLONE'} }
$addCase=New-MembershipCase 'add-direct-membership';Invoke-OnlineMembershipChild $addCase
$addRecord=Get-Content -LiteralPath (Join-Path $root 'add-direct-membership\membership.json') -Raw | ConvertFrom-Json
Check ($addRecord.completed -and -not $addRecord.mutation_uncertain -and $script:mutations.Count -eq 1 -and $script:mutations[0].identity -ceq $baseline.directory.group_guid -and $script:mutations[0].server -ceq 'ADSDK25DC1.ad.sdk.test' -and $script:mutations[0].add.Count -eq 1 -and $script:mutations[0].add.member -ceq $baseline.directory.source_dn -and $null -eq $script:mutations[0].remove) 'Add was not the exact single-member delta.'
Wait-OnlineReplicas $true;$script:checks++
$removeCase=New-MembershipCase 'remove-direct-membership';Invoke-OnlineMembershipChild $removeCase
$removeRecord=Get-Content -LiteralPath (Join-Path $root 'remove-direct-membership\membership.json') -Raw | ConvertFrom-Json
Check ($removeRecord.completed -and -not $removeRecord.mutation_uncertain -and $script:members.Count -eq 0 -and $script:mutations.Count -eq 2 -and $script:mutations[1].remove.Count -eq 1 -and $script:mutations[1].remove.member -ceq $baseline.directory.source_dn -and $null -eq $script:mutations[1].add) 'Remove was not the exact single-member delta.'
Wait-OnlineReplicas $false;$script:checks++
Reset-Fixture;$script:mutations=@();$script:members=@('foreign');$addCase=New-MembershipCase 'add-direct-membership';Invoke-OnlineMembershipChild $addCase
$record=Get-Content -LiteralPath (Join-Path $root 'add-direct-membership\membership.json') -Raw | ConvertFrom-Json
Check (-not $record.completed -and -not $record.mutation_invoked -and $script:mutations.Count -eq 0) 'Membership precondition failure still invoked mutation.'
Reset-Fixture;$script:members=@();$script:mutationThrow=$true;$addCase=New-MembershipCase 'add-direct-membership';Invoke-OnlineMembershipChild $addCase
$record=Get-Content -LiteralPath (Join-Path $root 'add-direct-membership\membership.json') -Raw | ConvertFrom-Json
Check (-not $record.completed -and $record.mutation_invoked -and $record.mutation_uncertain) 'Thrown directory mutation lost uncertainty.';$script:mutationThrow=$false

# Native/reference child result classification; no process is started.
function Read-OnlineFile([string]$Path) { return [ordered]@{path=$Path;exists=$false;length=$null;sha256=$null;sddl=$null;creation_utc=$null;last_write_utc=$null} }
$script:childScenario='group';$script:starts=0
function Invoke-OwnedChild($Executable,$Arguments,$Prefix,$Seconds) {
    $script:starts++
    $process=[ordered]@{pid=42;started_utc='2026-11-12T22:00:00Z';completed=$true;process_uncertain=$false;exit_code=1;stdout_path=($Prefix+'.stdout.txt');stderr_path=($Prefix+'.stderr.txt');stdout_sha256='A'*64;stderr_sha256='B'*64;error=$null}
    if($script:childScenario -ceq 'timeout') { $script:processUncertain=$true;$process.completed=$false;$process.process_uncertain=$true;return $process }
    $wire=[ordered]@{protocol_version=1;operation='generate_config';data=[ordered]@{checks_skipped=$false;outcome='not_written';prerequisites=[ordered]@{complete=$false;cloneable_group_member=$false}};error_details=[ordered]@{present=$true;prerequisite=$true;message='source is not a member'}}
    $text=if($script:childScenario -eq 'malformed'){'{'}else{$wire | ConvertTo-Json -Depth 12}
    [IO.File]::WriteAllText($process.stdout_path,$text);[IO.File]::WriteAllText($process.stderr_path,'')
    if($script:childScenario -eq 'reference-missing' -or $script:childScenario -eq 'membership-missing') { $process.exit_code=0 }
    return $process
}
Reset-Fixture;$script:childScenario='group';$case=Invoke-OnlineCase 'missing-group-sdk' 'sdk' 'group'
Check ($case.passed -and $case.process.completed -and -not $script:publicationUncertain) 'Confirmed native missing-group result failed.'
Check (Same-OnlineValue $case (Get-Content -LiteralPath (Join-Path $root 'missing-group-sdk\result.json') -Raw | ConvertFrom-Json)) 'Result file differs from summary case.'
foreach($scenario in @('timeout','malformed')) {
    Reset-Fixture;$script:childScenario=$scenario;$beforeStarts=$script:starts
    Reject { Invoke-OnlineCase 'missing-group-sdk' 'sdk' 'group' } 'Unknown native child was accepted.'
    Reject { Assert-CanRun } 'Unknown native child permitted further work.'
    Check ($script:starts -eq $beforeStarts+1 -and $script:state.cases.Count -eq 1 -and -not $script:state.cases[0].passed) 'Unknown child was retried or lost its failed prefix.'
}
foreach($kind in @('reference','membership')) {
    Reset-Fixture;$script:childScenario=$kind+'-missing'
    if($kind -eq 'reference') { $script:state.cases=@([ordered]@{name='prior'});$name='missing-group-reference';$expectation='group' }
    else { $script:state.cases=@([ordered]@{name='prior1'},[ordered]@{name='prior2'});$name='add-direct-membership';$expectation='member' }
    Reject { Invoke-OnlineCase $name $kind $expectation } 'Missing bounded-child publication/mutation record was accepted.'
    Check ($script:publicationUncertain -or $script:mutationUncertain) 'Missing child record did not retain uncertainty.'
}

# Deletion is allowed only for the exact recorded new-file identity.
Reset-Fixture;$script:removed=@();$script:owned=[ordered]@{path='C:\Windows\NTDS\DCCloneConfig.xml';exists=$true;length=8;sha256=('A'*64);sddl='fixture';creation_utc='created';last_write_utc='written'};$script:ownedMissing=$false
function Read-OnlineFile([string]$Path) { if($script:ownedMissing){return [ordered]@{path=$Path;exists=$false}};return (Clone $script:owned) }
function Remove-Item { param($LiteralPath,$ErrorAction) $script:removed+=@($LiteralPath);$script:ownedMissing=$true }
foreach($field in @('path','sha256','sddl','creation_utc','last_write_utc','length')) { $changed=Clone $script:owned;$changed.$field='changed';Reject { Remove-OnlineOwnedFile $changed } 'Changed file ownership was accepted for cleanup.' }
Check ($script:removed.Count -eq 0) 'Cleanup deleted an unowned/changed file.'
Remove-OnlineOwnedFile (Clone $script:owned)
Check ($script:removed.Count -eq 1 -and $script:removed[0] -ceq 'C:\Windows\NTDS\DCCloneConfig.xml') 'Cleanup did not target exactly the owned file.'
Reset-Fixture;$script:mutationUncertain=$true;Reject { Remove-OnlineOwnedFile (Clone $script:owned) } 'Unknown mutation still allowed file cleanup.'

# Real orchestration with instrumented safe primitives: prove exact ordering and
# that a terminal unknown result prevents subsequent children and all cleanup.
function Assert-OnlineWorld($Member,$Custom,$Config) { Assert-CanRun;$script:flow+=@('world-'+$Member) }
function Wait-OnlineReplicas($Member) { Assert-CanRun;$script:flow+=@('replicas-'+$Member) }
function Write-OnlineInclusion { Assert-CanRun;$script:flow+=@('inclusion');$script:state.recovery.custom_file=[ordered]@{path='C:\Windows\NTDS\CustomDCCloneAllowList.xml';exists=$true;sha256=('B'*64)} }
function Read-OnlineXML($Path) { return [ordered]@{name='DCCloneConfig';computer='ADSDK25CLONE'} }
function Remove-OnlineOwnedFile($Owned) { Assert-CanRun;$script:flow+=@('remove-'+$Owned.path);$script:cleanupCalls++ }
function Invoke-OnlineCase($Name,$Kind,$Expectation) {
    Assert-CanRun;$script:flow+=@($Name)
    $entry=[ordered]@{name=$Name;kind=$Kind;passed=$true;process=[ordered]@{completed=$true;process_uncertain=$false};output_after=[ordered]@{path='C:\Windows\NTDS\DCCloneConfig.xml';exists=$true;sha256=('A'*64)}}
    $script:state.cases+=@($entry)
    if($Name -ceq $script:failAt) { $entry.passed=$false;$script:processUncertain=$true;throw 'Simulated unknown bounded child.' }
    if($Name -ceq 'add-direct-membership') { $script:state.recovery.group_added=$true }
    if($Name -ceq 'remove-direct-membership') { $script:state.recovery.group_added=$false }
    if($Expectation -ceq 'written') { $script:state.recovery.config_file=$entry.output_after }
    return $entry
}
foreach($failure in @('','add-direct-membership','online-sdk-success','remove-direct-membership')) {
    Reset-Fixture;$script:root=Join-Path $fixtureRoot ([guid]::NewGuid().ToString('N'));$script:flow=@();$script:cleanupCalls=0;$script:failAt=$failure
    $summary=Invoke-OnlineQualification
    if(-not $failure) {
        Check ($summary.passed -and $summary.completed -and $summary.cleanup_complete -and $summary.cases.Count -eq 10 -and -not $summary.recovery.group_added -and $null -eq $summary.recovery.custom_file -and $null -eq $summary.recovery.config_file) 'Full flow did not complete with restored state.'
        Check ((($summary.cases | ForEach-Object {$_.name}) -join ',') -ceq ((Get-OnlineCaseNames) -join ',')) 'Full flow case order changed.'
        Check ($script:cleanupCalls -eq 3 -and $script:flow[-1] -ceq 'world-False') 'Full flow omitted exact file removals or final baseline verification.'
    } else {
        Check (-not $summary.passed -and -not $summary.completed -and -not $summary.cleanup_complete -and $summary.process_uncertain -and $summary.cases[-1].name -ceq $failure) 'Unknown child lost terminal partial state.'
        Check ($script:flow[-1] -ceq $failure) 'Unknown child triggered a later operation.'
        Check ($script:cleanupCalls -eq $(if($failure -ceq 'remove-direct-membership'){3}else{0})) 'Unknown child triggered additional cleanup.'
    }
}

# Direct raw evidence has the same uncertainty contract as JSON evidence.
# Keep the imported frozen writer intact and inject failures only in this test.
$rawCalls=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Write-NewBytes'},$true))
Check ($rawCalls.Count -eq 1) 'A raw evidence call bypasses the guest-owned capture guard.'
$script:frozenWriteNewBytes=(Get-Command Write-NewBytes).ScriptBlock;$script:failRawName=''
function Write-NewBytes([string]$Path,[byte[]]$Bytes) {
    if([IO.Path]::GetFileName($Path) -ceq $script:failRawName) { throw 'Injected raw evidence write failure.' }
    & $script:frozenWriteNewBytes $Path $Bytes
}
Reset-Fixture;$script:failRawName='output.xml'
$source=Join-Path $root 'source.xml';[IO.File]::WriteAllText($source,'<owned/>')
Reject { Write-OnlineEvidence -Path (Join-Path $root 'output.xml') -Source $source } 'Raw XML write failure was swallowed.'
Check $script:captureFailed 'Raw XML write failure did not mark capture uncertainty.'
Reject { Assert-CanRun } 'Raw XML write failure permitted another operation.'
Reset-Fixture;$script:failRawName=''
Reject { Write-OnlineEvidence -Path (Join-Path $root 'output.xml') -Source (Join-Path $root 'absent.xml') } 'Raw XML read failure was swallowed.'
Check $script:captureFailed 'Raw XML read failure did not mark capture uncertainty.'

# Reproduce the reviewed failure after the exact five completed cases. The
# actual inclusion function must stop before any supported-path publication.
Import-Definition 'Write-OnlineInclusion'
Reset-Fixture;$script:root=Join-Path $fixtureRoot ([guid]::NewGuid().ToString('N'));$script:flow=@();$script:cleanupCalls=0;$script:failAt='';$script:failRawName='inclusion.xml'
$summary=Invoke-OnlineQualification
Check ($summary.capture_failed -and -not $summary.passed -and -not $summary.completed -and -not $summary.cleanup_complete -and $summary.cases.Count -eq 5) 'Failed raw inclusion capture returned a capturable partial summary.'
Check ($summary.cases[-1].name -ceq 'excluded-apps-reference' -and 'online-sdk-success' -notin $script:flow -and 'remove-direct-membership' -notin $script:flow -and $script:cleanupCalls -eq 0) 'Failed raw inclusion capture triggered another case or cleanup mutation.'
Check ($summary.recovery.group_added -and $null -eq $summary.recovery.custom_file -and $null -eq $summary.recovery.config_file) 'Failed raw inclusion capture lost the exact recovery state.'
Reject { Assert-CanRun } 'Failed raw inclusion capture did not halt future guest operations.'

Reset-Fixture;$script:root=Join-Path $fixtureRoot ([guid]::NewGuid().ToString('N'));$script:flow=@();$script:cleanupCalls=0;$script:failRawName='owner.txt'
Reject { Invoke-OnlineQualification } 'Raw owner write failure was swallowed.'
Check ($script:captureFailed -and $script:state.cases.Count -eq 0 -and $script:flow.Count -eq 0 -and $script:cleanupCalls -eq 0) 'Raw owner write failure permitted prerequisite reads, cases or mutations.'
$script:failRawName=''

$record=[ordered]@{passed=$true;checks=$script:checks;collected_utc=[DateTime]::UtcNow.ToString('o');powershell=$PSVersionTable.PSVersion.ToString();scope='offline AST functions, synthetic local files, mocked directory mutations/native outcomes only; no guest/host entrypoint, actual AD, VM, registry, ACL change or child process';guest_sha256=(Get-FileHash -LiteralPath $guestPath -Algorithm SHA256).Hash;baseline_sha256=(Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash;fixture_directory=$fixtureRoot}
if($OutputPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($record | ConvertTo-Json),[Text.UTF8Encoding]::new($false)) }
$record | ConvertTo-Json
