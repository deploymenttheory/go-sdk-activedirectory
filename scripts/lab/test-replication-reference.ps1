#Requires -Version 5.1
# Offline projection/comparison checks only; no AD module import or lab calls.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'replication-reference.ps1')
$script:checks=0
function Assert-Test([bool]$Condition,[string]$Message) {$script:checks++;if (-not $Condition) {throw $Message}}
function Copy-JSON($Value) { return ($Value | ConvertTo-Json -Depth 16 | ConvertFrom-Json) }
function Assert-ComparisonRejected($Before,$Native,$After,[string]$Message) {
    $rejected=$false
    try {$result=Compare-ReplicationSnapshots $Before $Native $After ('a'*64);$rejected=-not $result.passed} catch {$rejected=$true}
    Assert-Test $rejected $Message
}
$time=[DateTime]::SpecifyKind([DateTime]'2026-11-13T00:00:00',[DateTimeKind]::Utc)
$record=[pscustomobject]@{PartnerType='Inbound';Partition='DC=ad,DC=sdk,DC=test';Partner='CN=NTDS Settings,CN=DC2';PartnerAddress='dc2.ad.sdk.test';PartnerGuid=[guid]'11111111-1111-1111-1111-111111111111';PartitionGuid=[guid]::Empty;PartnerInvocationId=[guid]'22222222-2222-2222-2222-222222222222';LastReplicationAttempt=$time;LastReplicationSuccess=$time;LastReplicationResult=0;ConsecutiveReplicationFailures=0;UsnFilter=[long]9007199254740993}
$partner=ConvertTo-ReplicationPartnerReference $record
Assert-Test ($partner.usn_filter -ceq '9007199254740993') 'USN was rounded through JSON/double.'
$negative=Copy-JSON $record;$negative.LastReplicationResult=-2146893022
Assert-Test ((ConvertTo-ReplicationPartnerReference $negative).last_result -ceq '2148074274') 'Signed native status bits were lost.'
$missing=[pscustomobject]@{PartnerType='Outbound';Partition='DC=x';PartnerGuid=[guid]::Empty}
$projection=ConvertTo-ReplicationPartnerReference $missing
Assert-Test ($null -eq $projection.invocation_guid -and $null -eq $projection.last_attempt -and $null -eq $projection.last_result) 'Absent reference fields became zero.'
$queue=ConvertTo-ReplicationQueueReference ([pscustomobject]@{OperationID=-1;Priority=99;OperationType=4;Options=[int]::MinValue;Partition='DC=x';Partner='CN=y';PartnerAddress=$null;EnqueueTime=$time})
Assert-Test ($queue.id -ceq '4294967295' -and $queue.options -ceq '2147483648' -and $queue.type -ceq '4') 'Queue identifiers/options changed bits.'
$failure=ConvertTo-ReplicationFailureReference ([pscustomobject]@{FailureType='Link';Partner='CN=y';PartnerGuid=$null;FirstFailureTime=$time;FailureCount=2;LastError=0})
Assert-Test ($failure.kind -ceq 'link' -and $failure.last_result -ceq '0' -and $null -eq $failure.partner_guid) 'Link failure or unavailable error/GUID was erased.'
$outbound=Copy-JSON $partner;$outbound.direction='outbound';$outbound.invocation_guid=$null;$outbound.usn_filter=$null
$before=[ordered]@{schema_version=1;purpose='go-sdk-activedirectory-replication-reference';phase='before';run_id='run1';fixture_id='fixture1';sdk_revision=('1'*40);binary_sha256=('2'*64);started='2026-11-13T00:01:00Z';finished='2026-11-13T00:02:00Z';passed=$true;full_ticket_complete=$false;servers=@('dc1.ad.sdk.test','dc2.ad.sdk.test');records=@()}
foreach ($server in $before.servers) {$before.records+=@([ordered]@{server=$server;partners=@((Copy-JSON $partner),(Copy-JSON $outbound));failures=@();queue=@();errors=[ordered]@{}})}
$after=Copy-JSON $before;$after.phase='after';$after.started='2026-11-13T00:04:00Z';$after.finished='2026-11-13T00:05:00Z'
$native=Copy-JSON $before;$native.purpose='go-sdk-activedirectory-replication-native';$native.started='2026-11-13T00:02:30Z';$native.finished='2026-11-13T00:03:00Z';$native | Add-Member NoteProperty reference_sha256 ('a'*64)
$result=Compare-ReplicationSnapshots $before $native $after ('a'*64)
Assert-Test ($result.passed -and @($result.checks).Count -gt 20) 'Positive pair failed meaningful comparisons.'
foreach ($mode in @('missing-partner','duplicate-partner','wrong-guid','wrong-status','out-of-bracket-time','wrong-usn','native-error','wrong-queue','failed-collection','wrong-run','wrong-pin','wrong-reference-hash','wrong-time-order','no-positive-inbound')) {
    $bad=Copy-JSON $native
    switch ($mode) {
        'missing-partner' {$bad.records[0].partners=@($bad.records[0].partners[0])}
        'duplicate-partner' {$bad.records[0].partners+=@($bad.records[0].partners[0])}
        'wrong-guid' {$bad.records[0].partners[0].partner_guid='33333333-3333-3333-3333-333333333333'}
        'wrong-status' {$bad.records[0].partners[0].last_result='1722'}
        'out-of-bracket-time' {$bad.records[0].partners[0].last_success='0'}
        'wrong-usn' {$bad.records[0].partners[0].usn_filter='9007199254740994'}
        'native-error' {$bad.records[0].errors | Add-Member NoteProperty queue 'native code 5'}
        'wrong-queue' {$bad.records[0].queue=@((Copy-JSON $queue))}
        'failed-collection' {$bad.passed=$false}
        'wrong-run' {$bad.run_id='foreign'}
        'wrong-pin' {$bad.binary_sha256=('b'*64)}
        'wrong-reference-hash' {$bad.reference_sha256=('b'*64)}
        'wrong-time-order' {$bad.started='2026-11-13T00:01:30Z'}
        'no-positive-inbound' {$bad.records[0].partners=@($bad.records[0].partners | Where-Object direction -ne 'inbound')}
    }
    Assert-ComparisonRejected $before $bad $after ('Accepted '+$mode+'.')
}
$queuedBefore=Copy-JSON $before;$queuedNative=Copy-JSON $native;$queuedAfter=Copy-JSON $after
foreach ($snapshot in @($queuedBefore,$queuedNative,$queuedAfter)) {$snapshot.records[0].queue=@((Copy-JSON $queue))}
Assert-Test (Compare-ReplicationSnapshots $queuedBefore $queuedNative $queuedAfter ('a'*64)).passed 'Stable nonempty queue fields did not compare.'
$queuedNative.records[0].queue[0].options='0'
Assert-ComparisonRejected $queuedBefore $queuedNative $queuedAfter 'Accepted changed queue option bits.'

# Fake only the external cmdlet boundary. Verify explicit endpoints and that a
# denied category stays failed while the other successful categories survive.
$script:referenceCalls=@();$script:denyFailures=$false;$script:partnerInput=$record
$script:referencePartitions=@('DC=ad,DC=sdk,DC=test','CN=Configuration,DC=ad,DC=sdk,DC=test','CN=Schema,CN=Configuration,DC=ad,DC=sdk,DC=test','DC=DomainDnsZones,DC=ad,DC=sdk,DC=test','DC=ForestDnsZones,DC=ad,DC=sdk,DC=test')
$script:omitPartitions=$false
function Get-ADRootDSE {
    param($Server,$ErrorAction)
    $script:referenceCalls+=@('partitions')
    if ($Server -cne 'dc2.ad.sdk.test' -or $ErrorAction -cne 'Stop') {throw 'Naming contexts were read from the wrong server.'}
    if ($script:omitPartitions) {return [pscustomobject]@{NamingContexts=@()}}
    return [pscustomobject]@{NamingContexts=$script:referencePartitions}
}
function Get-ADReplicationPartnerMetadata {
    param($Target,$Scope,$PartnerType,$Partition,$EnumerationServer,$ErrorAction)
    $script:referenceCalls+=@('partners')
    if ($Target -cne 'dc2.ad.sdk.test' -or $EnumerationServer -cne 'dc1.ad.sdk.test' -or $Scope -cne 'Server' -or $PartnerType -cne 'Both' -or ($Partition -join '|') -cne ($script:referencePartitions -join '|') -or $ErrorAction -cne 'Stop') {throw 'Unexpected partner command scope.'}
    return $script:partnerInput
}
function Get-ADReplicationFailure {
    param($Target,$Scope,$EnumeratingServer,$ErrorAction)
    $script:referenceCalls+=@('failures')
    if ($Target -cne 'dc2.ad.sdk.test' -or $EnumeratingServer -cne 'dc1.ad.sdk.test' -or $Scope -cne 'Server' -or $ErrorAction -cne 'Stop') {throw 'Unexpected failure command scope.'}
    if ($script:denyFailures) {throw [UnauthorizedAccessException]::new('Injected native reference denial.')}
}
function Get-ADReplicationQueueOperation {
    param($Server,$ErrorAction)
    $script:referenceCalls+=@('queue')
    if ($Server -cne 'dc2.ad.sdk.test' -or $ErrorAction -cne 'Stop') {throw 'Unexpected queue command scope.'}
}
$collected=Get-ReplicationReferenceServer 'dc2.ad.sdk.test' 'dc1.ad.sdk.test'
Assert-Test ($collected.errors.Count -eq 0 -and @($collected.partners).Count -eq 1 -and @($collected.failures).Count -eq 0 -and @($collected.queue).Count -eq 0) 'Healthy reference collection lost successful/empty states.'
$script:denyFailures=$true
$collected=Get-ReplicationReferenceServer 'dc2.ad.sdk.test' 'dc1.ad.sdk.test'
Assert-Test ($collected.errors.Contains('failures') -and $collected.errors.Count -eq 1 -and @($collected.partners).Count -eq 1) 'Denied reference category was accepted as healthy empty, or successful partner rows were lost.'
Assert-Test (($script:referenceCalls -join ',') -ceq 'partitions,partners,failures,queue,partitions,partners,failures,queue') 'Reference queries were duplicated or skipped.'
$script:denyFailures=$false;$script:omitPartitions=$true;$script:referenceCalls=@()
$collected=Get-ReplicationReferenceServer 'dc2.ad.sdk.test' 'dc1.ad.sdk.test'
Assert-Test ($collected.errors.Contains('partners') -and $collected.errors.Count -eq 1 -and @($collected.partners).Count -eq 0) 'Missing naming contexts were accepted as complete partner scope.'
Assert-Test (($script:referenceCalls -join ',') -ceq 'partitions,failures,queue') 'Partner query ran without a valid explicit NC list.'
foreach ($name in @('reference-replication.ps1','replication-reference.ps1')) {
    $tokens=$null;$parseErrors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$parseErrors)
    Assert-Test (@($parseErrors).Count -eq 0) ('PowerShell parse error in '+$name)
}
Write-Output "Replication reference offline checks passed: $script:checks"
