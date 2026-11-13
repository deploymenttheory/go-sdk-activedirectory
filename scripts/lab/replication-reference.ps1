#Requires -Version 5.1
# Functions only: loading this file performs no AD, process or VM operation.
. (Join-Path $PSScriptRoot 'directory-harness.ps1')

function Get-ReplicationProperty($Object,[string]$Name) {
    $names=$Object.PSObject.Properties['PropertyNames']
    if ($names -and $Name -notin @($names.Value)) { return $null }
    $property=$Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}
function ConvertTo-ReplicationText($Value) {
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    return ([string]$Value).ToLowerInvariant()
}
function ConvertTo-ReplicationNumber($Value,[bool]$Unsigned=$true) {
    if ($null -eq $Value) { return $null }
    if ($Unsigned) { return (ConvertTo-DirectoryMask $Value).ToString([Globalization.CultureInfo]::InvariantCulture) }
    return ([long]$Value).ToString([Globalization.CultureInfo]::InvariantCulture)
}
function ConvertTo-ReplicationTime($Value) {
    if ($null -eq $Value) { return $null }
    return ([DateTime]$Value).ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
}
function ConvertTo-ReplicationPartnerReference($Object) {
    $direction=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'PartnerType')
    if ($direction -notin @('inbound','outbound')) { throw 'Unknown replication partner direction.' }
    return [ordered]@{
        direction=$direction;partition=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'Partition')
        partner=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'Partner');address=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'PartnerAddress')
        partner_guid=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'PartnerGuid');partition_guid=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'PartitionGuid')
        invocation_guid=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'PartnerInvocationId')
        last_attempt=ConvertTo-ReplicationTime (Get-ReplicationProperty $Object 'LastReplicationAttempt');last_success=ConvertTo-ReplicationTime (Get-ReplicationProperty $Object 'LastReplicationSuccess')
        last_result=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'LastReplicationResult');failures=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'ConsecutiveReplicationFailures')
        usn_filter=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'UsnFilter') $false
    }
}
function ConvertTo-ReplicationFailureReference($Object) {
    $kind=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'FailureType')
    if ($kind -notin @('connection','link')) { throw 'Unknown replication failure kind.' }
    return [ordered]@{kind=$kind;partner=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'Partner');partner_guid=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'PartnerGuid');time=ConvertTo-ReplicationTime (Get-ReplicationProperty $Object 'FirstFailureTime');count=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'FailureCount');last_result=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'LastError')}
}
function ConvertTo-ReplicationQueueReference($Object) {
    return [ordered]@{id=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'OperationID');priority=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'Priority');type=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'OperationType');options=ConvertTo-ReplicationNumber (Get-ReplicationProperty $Object 'Options');partition=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'Partition');partner=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'Partner');address=ConvertTo-ReplicationText (Get-ReplicationProperty $Object 'PartnerAddress');enqueued=ConvertTo-ReplicationTime (Get-ReplicationProperty $Object 'EnqueueTime')}
}

function Get-ReplicationReferenceServer([string]$Server,[string]$EnumerationServer) {
    $record=[ordered]@{server=$Server;partners=@();failures=@();queue=@();errors=[ordered]@{}}
    try {
        $record.partners=@(Get-ADReplicationPartnerMetadata -Target $Server -Scope Server -PartnerType Both -Partition '*' -EnumerationServer $EnumerationServer -ErrorAction Stop | ForEach-Object {ConvertTo-ReplicationPartnerReference $_})
    } catch {$record.errors['partners']=$_.FullyQualifiedErrorId}
    try {
        $record.failures=@(Get-ADReplicationFailure -Target $Server -Scope Server -EnumeratingServer $EnumerationServer -ErrorAction Stop | ForEach-Object {ConvertTo-ReplicationFailureReference $_})
    } catch {$record.errors['failures']=$_.FullyQualifiedErrorId}
    try {
        $record.queue=@(Get-ADReplicationQueueOperation -Server $Server -ErrorAction Stop | ForEach-Object {ConvertTo-ReplicationQueueReference $_})
    } catch {$record.errors['queue']=$_.FullyQualifiedErrorId}
    return $record
}

function Compare-ReplicationSnapshots($Before,$Native,$After,[string]$ExpectedBeforeHash) {
    $checks=[Collections.Generic.List[object]]::new()
    foreach ($snapshot in @($Before,$Native,$After)) {
        if ($snapshot.schema_version -ne 1 -or $snapshot.passed -isnot [bool] -or -not $snapshot.passed -or $snapshot.full_ticket_complete -ne $false) { throw 'A collection failed or claimed full qualification.' }
        foreach ($name in @('run_id','fixture_id','sdk_revision','binary_sha256')) { if ($snapshot.$name -cne $Before.$name) { throw 'Snapshot identity or source/binary pins differ.' } }
        if (@($snapshot.servers).Count -ne 2 -or (@($snapshot.servers) -join ',') -cne (@($Before.servers) -join ',')) { throw 'Snapshot target pair differs.' }
    }
    if ($Before.purpose -cne 'go-sdk-activedirectory-replication-reference' -or $After.purpose -cne $Before.purpose -or $Before.phase -cne 'before' -or $After.phase -cne 'after' -or $Native.purpose -cne 'go-sdk-activedirectory-replication-native' -or $Native.reference_sha256 -ine $ExpectedBeforeHash -or $ExpectedBeforeHash -notmatch '\A[0-9a-fA-F]{64}\z') { throw 'Reference/native phases or reference hash differ.' }
    $ordered=([DateTimeOffset]$Before.started -le [DateTimeOffset]$Before.finished) -and ([DateTimeOffset]$Before.finished -le [DateTimeOffset]$Native.started) -and ([DateTimeOffset]$Native.started -le [DateTimeOffset]$Native.finished) -and ([DateTimeOffset]$Native.finished -le [DateTimeOffset]$After.started) -and ([DateTimeOffset]$After.started -le [DateTimeOffset]$After.finished)
    if (-not $ordered) { throw 'Reference/native observations do not bracket one another.' }
    $beforeServers=Get-ReplicationRowIndex $Before.records 'server';$nativeServers=Get-ReplicationRowIndex $Native.records 'server';$afterServers=Get-ReplicationRowIndex $After.records 'server'
    if ($beforeServers.Count -ne 2 -or $nativeServers.Count -ne 2 -or $afterServers.Count -ne 2) { throw 'Missing or duplicate server records.' }
    foreach ($server in $Before.servers) {
        foreach ($index in @($beforeServers,$nativeServers,$afterServers)) { if (-not $index.ContainsKey($server)) { throw 'Server observation is missing.' } }
        $b=$beforeServers[$server];$n=$nativeServers[$server];$a=$afterServers[$server]
        foreach ($row in @($b,$n,$a)) {
            $errorCount=if ($row.errors -is [Collections.IDictionary]) {$row.errors.Count} else {@($row.errors.PSObject.Properties).Count}
            if ($errorCount) { throw 'A failed category cannot be compared as an empty collection.' }
        }
        $bp=Get-ReplicationRowIndex $b.partners 'partner';$np=Get-ReplicationRowIndex $n.partners 'partner';$ap=Get-ReplicationRowIndex $a.partners 'partner'
        Add-ReplicationCheck $checks ($server+'/partner-count') ($bp.Count -eq $np.Count -and $bp.Count -eq $ap.Count)
        foreach ($direction in @('inbound','outbound')) {
            foreach ($rows in @($b.partners,$n.partners,$a.partners)) { Add-ReplicationCheck $checks ($server+'/'+$direction+'-positive-control') (@($rows | Where-Object direction -ceq $direction).Count -gt 0) }
        }
        foreach ($key in $bp.Keys) {
            if (-not $np.ContainsKey($key) -or -not $ap.ContainsKey($key)) { Add-ReplicationCheck $checks ($server+'/partner-identity') $false;continue }
            $expected=$bp[$key];$actual=$np[$key];$later=$ap[$key]
            $fields=@('partner','address');if ($expected.direction -ceq 'inbound') {$fields+=@('invocation_guid')}
            foreach ($field in $fields) { Add-ReplicationCheck $checks ($server+'/partner/'+$key+'/'+$field) ((Test-ReplicationSame $expected.$field $actual.$field) -and (Test-ReplicationSame $later.$field $actual.$field)) }
            foreach ($field in @('last_attempt','last_success')) { Add-ReplicationCheck $checks ($server+'/partner/'+$key+'/'+$field) (Test-ReplicationBetween $expected.$field $actual.$field $later.$field) }
            if ($expected.direction -ceq 'inbound') { Add-ReplicationCheck $checks ($server+'/partner/'+$key+'/usn_filter') (Test-ReplicationBetween $expected.usn_filter $actual.usn_filter $later.usn_filter) }
            foreach ($field in @('last_result','failures')) { Add-ReplicationCheck $checks ($server+'/healthy-partner/'+$key+'/'+$field) ($expected.$field -ceq '0' -and $actual.$field -ceq '0' -and $later.$field -ceq '0') }
        }
        Add-ReplicationCheck $checks ($server+'/healthy-empty-failures') ($null -ne $b.failures -and $null -ne $n.failures -and $null -ne $a.failures -and @($b.failures).Count -eq 0 -and @($n.failures).Count -eq 0 -and @($a.failures).Count -eq 0)
        $bq=Get-ReplicationRowIndex $b.queue 'queue';$nq=Get-ReplicationRowIndex $n.queue 'queue';$aq=Get-ReplicationRowIndex $a.queue 'queue'
        Add-ReplicationCheck $checks ($server+'/stable-queue-count') ($bq.Count -eq $nq.Count -and $bq.Count -eq $aq.Count)
        foreach ($key in $bq.Keys) {
            if (-not $nq.ContainsKey($key) -or -not $aq.ContainsKey($key)) { Add-ReplicationCheck $checks ($server+'/stable-queue-identity') $false;continue }
            foreach ($field in @('priority','type','options','partition','partner','address','enqueued')) { Add-ReplicationCheck $checks ($server+'/stable-queue/'+$key+'/'+$field) ((Test-ReplicationSame $bq[$key].$field $nq[$key].$field) -and (Test-ReplicationSame $aq[$key].$field $nq[$key].$field)) }
        }
    }
    return [ordered]@{schema_version=1;purpose='go-sdk-activedirectory-replication-comparison';run_id=$Before.run_id;fixture_id=$Before.fixture_id;sdk_revision=$Before.sdk_revision;binary_sha256=$Before.binary_sha256;passed=(@($checks | Where-Object {-not $_.passed}).Count -eq 0);full_ticket_complete=$false;checks=@($checks.ToArray());not_compared=@('partition GUID (query-dependent zero)','raw replica flags','native current-operation header','outbound inbound-only fields');remaining_live_scenarios=@('unavailable replication partner','nonempty controlled queue','partial multi-server failure','ordinary identity permission failure','AD LDS','other supported server versions')}
}

function Add-ReplicationCheck($Checks,[string]$Name,[bool]$Passed) { $Checks.Add([ordered]@{name=$Name;passed=$Passed}) }
function Test-ReplicationSame($Left,$Right) {
    if ($null -eq $Left -or $null -eq $Right) { return $null -eq $Left -and $null -eq $Right }
    return $Left -is [string] -and $Right -is [string] -and $Left -ceq $Right
}
function Test-ReplicationBetween($Before,$Value,$After) {
    foreach ($number in @($Before,$Value,$After)) { if ($number -isnot [string] -or $number -notmatch '\A-?[0-9]+\z') {return $false} }
    return [decimal]$Before -le [decimal]$Value -and [decimal]$Value -le [decimal]$After
}
function Get-ReplicationRowIndex($Rows,[ValidateSet('server','partner','queue')][string]$Kind) {
    if ($null -eq $Rows) { throw 'Missing replication collection.' }
    $index=@{}
    foreach ($row in $Rows) {
        switch ($Kind) {
            'server' {$key=[string]$row.server;Assert-DirectoryDNSName $key}
            'partner' {
                $guid=[guid]::Empty
                if ($row.direction -notin @('inbound','outbound') -or -not $row.partition -or -not [guid]::TryParse([string]$row.partner_guid,[ref]$guid) -or $guid -eq [guid]::Empty) {throw 'Incomplete partner identity.'}
                $key=$row.direction+'|'+$row.partition+'|'+$guid.ToString('D')
            }
            'queue' {$key=[string]$row.id;if ($key -notmatch '\A[0-9]+\z') {throw 'Incomplete queue identity.'}}
        }
        if ($index.ContainsKey($key)) { throw 'Duplicate replication record identity.' }
        $index[$key]=$row
    }
    return $index
}
