#Requires -Version 5.1
# PREPARE ONLY. Actual staged file for Run and bounded owned child modes.
# No VM lifecycle, role transfer, registry change, ACL change, or overwrite.
param(
    [ValidateSet('Run','ReferenceChild','MembershipChild')][string]$Mode='Run',
    [Parameter(Mandatory)][string]$StageDirectory,
    [Parameter(Mandatory)][string]$Run,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedScriptSHA256,
    [string]$NativeExecutable,[string]$HelperSource,[string]$InventoryPath,
    [string]$CasePath,[string]$ExpectedCaseSHA256,
    [ValidateRange(1,120)][int]$ProcessTimeoutSeconds=60,
    [ValidateRange(1,120)][int]$ReplicationTimeoutSeconds=90
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:processUncertain=$false;$script:publicationUncertain=$false;$script:mutationUncertain=$false;$script:captureFailed=$false
$script:eventNumber=0;$script:snapshotNumber=0
function Get-OnlinePins {
    return [ordered]@{
        'negative-process-support.ps1'='2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D'
        'inventory-support.ps1'='25A401E6BE5F57DD16AB7CB5887AD747010581AE15A0997F717419B2B9A6C049'
        'inventory.json'='12280A1773B53B317BDEC242362B79DC8E9AF44BAC7ECA8555822B5868B63A23'
        'clone-config-helper.exe'='9D2F0D3A3548E8CD719E741A46AB246B3E2AAF24430554F6EC1370DAD21C5D8F'
        'clone-config-helper.go'='F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1'
        'build.json'='8C1A3E99029AEADEDEE39904707E95B5C5C45599590A2BBF1EE0C61869E19579'
        'helper-v3-build.json'='AC7334366C218A2A708DCAAFDB9776A5557D5E293170482321AE789CF594D219'
        'schema-evidence.json'='A061F397D27B26563E6B4C7D611F707F5A3CA4A5B9CBD3353CB2CDC7BA9D7F35'
    }
}
function Import-OnlineFunctions([string]$Path,[string[]]$Names) {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count) { throw 'Pinned dependency parse failed.' }
    foreach($name in $Names) {
        $matches=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $name)
        if($matches.Count -ne 1) { throw 'Pinned dependency function cardinality differs.' }
        $text=$matches[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name)
        . ([scriptblock]::Create($text))
    }
}
function Assert-OnlineLocalPath([string]$Path) {
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.Contains('..') -or $Path.Substring(2).Contains(':')) { throw 'Expected an explicit local path.' }
    $full=[IO.Path]::GetFullPath($Path)
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        try { $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop }
        catch { if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { continue };throw }
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Online path traverses a reparse point.' }
    }
    return $full
}
function Assert-OnlineStage {
    if($env:COMPUTERNAME -cne 'ADSDK25DC1' -or $Run -cne 'clone-config-reviewed-20261112T215735Z-b4707e3f-online-qualification-server2025-v1' -or
        $StageDirectory -cne ('C:\ad-sdk-validation\'+$Run) -or $PSCommandPath -cne (Join-Path $StageDirectory 'guest-clone-config-online-qualification.ps1')) { throw 'Online guest/file identity differs.' }
    $null=Assert-OnlineLocalPath $StageDirectory
    if([IO.File]::ReadAllText((Join-Path $StageDirectory 'owner.txt')) -cne $Run -or (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash -cne $ExpectedScriptSHA256) { throw 'Online staged owner or script hash differs.' }
    foreach($name in (Get-OnlinePins).Keys) {
        $path=Assert-OnlineLocalPath (Join-Path $StageDirectory $name)
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne (Get-OnlinePins)[$name]) { throw "Online staged dependency hash differs: $name" }
    }
}
function Assert-CanRun {
    if($script:processUncertain -or $script:publicationUncertain -or $script:mutationUncertain -or $script:captureFailed) { throw 'Unknown process/publication/mutation/evidence; preserve recovery and halt all further operations.' }
}
function Write-OnlineEvidence {
    param([Parameter(Mandatory)][string]$Path,[byte[]]$Bytes,[string]$Source)
    try {
        if($PSBoundParameters.ContainsKey('Source')) { $Bytes=[IO.File]::ReadAllBytes($Source) }
        Write-NewBytes $Path $Bytes
    } catch { $script:captureFailed=$true;throw }
}
function Same-OnlineValue($Left,$Right) { return ($Left | ConvertTo-Json -Depth 24 -Compress) -ceq ($Right | ConvertTo-Json -Depth 24 -Compress) }
function Online-Entries($Entries) { return @($Entries | ForEach-Object { ([string]$_.type)+':'+([string]$_.name) } | Sort-Object -CaseSensitive) }
function Read-OnlineFile([string]$Path) {
    $full=Assert-OnlineLocalPath $Path
    if($full -cne 'C:\Windows\NTDS\DCCloneConfig.xml' -and $full -cne 'C:\Windows\NTDS\CustomDCCloneAllowList.xml' -and -not $full.StartsWith($StageDirectory+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'File is outside exact online targets or owned staging.' }
    $item=Read-InventoryItem $full
    if($null -eq $item) { return [ordered]@{path=$full;exists=$false;length=$null;sha256=$null;sddl=$null;creation_utc=$null;last_write_utc=$null} }
    if($item.PSIsContainer -or $item.Length -gt 2097152) { throw 'Online file type or length differs.' }
    return [ordered]@{path=$full;exists=$true;length=$item.Length;sha256=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash;sddl=(Get-Acl -LiteralPath $full -ErrorAction Stop).Sddl;creation_utc=$item.CreationTimeUtc.ToString('o');last_write_utc=$item.LastWriteTimeUtc.ToString('o')}
}
function Checkpoint-Online([string]$Phase) {
    $script:state.phase=$Phase;$script:eventNumber++
    Write-NewJson (Join-Path $root ('events\{0:D4}-{1}.json' -f $script:eventNumber,$Phase)) $script:state
}
function Snapshot-Online([string]$Name,$Value) {
    $script:snapshotNumber++
    Write-NewJson (Join-Path $root ('snapshots\{0:D4}-{1}.json' -f $script:snapshotNumber,$Name)) $Value
}
function Read-OnlineReplica([string]$Server) {
    Assert-CanRun
    if($Server -cnotin @('ADSDK25DC1.ad.sdk.test','ADSDK25DC2.ad.sdk.test')) { throw 'Unexpected replica.' }
    $group=Get-ADGroup -Identity ([guid]$baseline.directory.group_guid) -Properties member -Server $Server -ErrorAction Stop
    $source=Get-ADComputer -Identity ([guid]$baseline.directory.source_guid) -Properties tokenGroups,memberOf -Server $Server -ErrorAction Stop
    if($group.ObjectGUID.ToString() -cne $baseline.directory.group_guid -or $group.DistinguishedName -cne $baseline.directory.group_dn -or
        (Inventory-SID $group.SID) -cne $baseline.directory.group_sid -or $source.ObjectGUID.ToString() -cne $baseline.directory.source_guid -or
        $source.DistinguishedName -cne $baseline.directory.source_dn -or (Inventory-SID $source.SID) -cne $baseline.directory.source_sid) { throw 'Replica immutable source/group identity differs.' }
    $tokens=@($source.tokenGroups | ForEach-Object { Inventory-SID $_ } | Sort-Object)
    if($tokens.Count -eq 0 -or $tokens.Count -gt 1024) { throw 'Replica tokenGroups evidence is missing or excessive.' }
    $groups=@(Get-ADPrincipalGroupMembership -Identity $source.DistinguishedName -Server $Server -ErrorAction Stop | ForEach-Object { Inventory-SID $_.SID } | Sort-Object)
    return [ordered]@{server=$Server;group_guid=$group.ObjectGUID.ToString();source_guid=$source.ObjectGUID.ToString();members=@($group.member | Sort-Object);direct_groups=@($source.memberOf | Sort-Object);token_groups=$tokens;reference_groups=$groups}
}
function Assert-OnlineReplica($Observation,[bool]$Member) {
    $members=@();$direct=@($baseline.directory.source_direct_groups);$tokens=@($baseline.directory.source_token_groups);$reference=@($baseline.directory.source_reference_groups | ForEach-Object {$_.sid})
    if($Member) { $members=@($baseline.directory.source_dn);$direct+=@($baseline.directory.group_dn);$tokens+=@($baseline.directory.group_sid);$reference+=@($baseline.directory.group_sid) }
    foreach($pair in @(@($Observation.members,$members),@($Observation.direct_groups,@($direct | Sort-Object)),@($Observation.token_groups,@($tokens | Sort-Object)),@($Observation.reference_groups,@($reference | Sort-Object)))) {
        if(-not (Same-OnlineValue @($pair[0]) @($pair[1]))) { throw 'Replica member attribute or one of the membership views differs.' }
    }
}
function Wait-OnlineReplicas([bool]$Member) {
    Assert-CanRun;$watch=[Diagnostics.Stopwatch]::StartNew();$last=@()
    do {
        $last=@();$matches=$true
        foreach($server in @('ADSDK25DC1.ad.sdk.test','ADSDK25DC2.ad.sdk.test')) {
            $view=Read-OnlineReplica $server;$last+=@($view)
            try { Assert-OnlineReplica $view $Member } catch { $matches=$false }
        }
        if($matches) { Snapshot-Online ('replicas-'+$(if($Member){'member'}else{'restored'})) $last;return }
        if($watch.Elapsed.TotalSeconds -lt $ReplicationTimeoutSeconds) { Start-Sleep -Milliseconds 1000 }
    } while($watch.Elapsed.TotalSeconds -lt $ReplicationTimeoutSeconds)
    Snapshot-Online 'replication-not-converged' $last
    throw 'Bounded readonly replication observation did not converge; no mutation replay.'
}
function Assert-OnlineWorld([bool]$Member,$Custom,$Config) {
    Assert-CanRun
    $current=Read-CloneConfigOnlineInventory 'clone-config-reviewed-20261112T215735Z-b4707e3f-online-inventory-v1'
    Snapshot-Online 'world' $current
    if(-not $current.completed -or $current.error) { throw 'Current inventory is incomplete.' }
    foreach($field in @('server','domain_dn','domain_sid','pdc','source_dn','source_guid','source_sid','group_dn','group_guid','group_sid','source_read_only','dc_functionality')) { if(-not (Same-OnlineValue $current.directory.$field $baseline.directory.$field)) { throw "Online directory identity changed: $field" } }
    if(-not (Same-OnlineValue $current.files.directories $baseline.files.directories) -or -not (Same-OnlineValue $current.files.default_list $baseline.files.default_list) -or
        $current.files.dsa_directory -cne 'C:\Windows\NTDS' -or $current.files.windows_ntds -cne 'C:\Windows\NTDS' -or $null -ne $current.files.allow_list_folder -or @($current.files.removable).Count -ne 0 -or
        @($current.files.custom_lists).Count -ne 1 -or @($current.files.clone_configs).Count -ne 1 -or -not (Same-OnlineValue $current.versions $baseline.versions)) { throw 'Online locations, default list, directory ACL, or reference version changed.' }
    foreach($pair in @(@($current.files.custom_lists[0],$Custom),@($current.files.clone_configs[0],$Config))) {
        if($null -eq $pair[1]) { if($pair[0].exists) { throw 'Unowned online target exists.' } }
        elseif(-not $pair[0].exists -or $pair[0].sha256 -cne $pair[1].sha256 -or $pair[0].sddl -cne $pair[1].sddl -or $pair[0].length -ne $pair[1].length) { throw 'Owned online target changed.' }
    }
    $expectedEntries=@();if($null -eq $Custom) { $expectedEntries=Online-Entries $baseline.applications.reference_entries }
    if(-not (Same-OnlineValue (Online-Entries $current.applications.reference_entries) $expectedEntries)) { throw 'Reference exclusion inventory differs from expected fixture state.' }
    foreach($server in @('ADSDK25DC1.ad.sdk.test','ADSDK25DC2.ad.sdk.test')) { Assert-OnlineReplica (Read-OnlineReplica $server) $Member }
}
function Remove-OnlineOwnedFile($Owned) {
    Assert-CanRun
    if($null -eq $Owned -or $Owned.path -cnotin @('C:\Windows\NTDS\DCCloneConfig.xml','C:\Windows\NTDS\CustomDCCloneAllowList.xml') -or -not $Owned.exists -or -not (Same-OnlineValue (Read-OnlineFile $Owned.path) $Owned)) { throw 'Refuse removal without exact owned file identity, timestamps, bytes and ACL.' }
    Checkpoint-Online 'before-owned-file-removal'
    try { Remove-Item -LiteralPath $Owned.path -ErrorAction Stop;if((Read-OnlineFile $Owned.path).exists) { throw 'Owned file remained after removal.' } }
    catch { $script:mutationUncertain=$true;throw }
}
function Encode-OnlineInclusion($Entries) {
    $text=[Text.StringBuilder]::new();$settings=[Xml.XmlWriterSettings]::new();$settings.OmitXmlDeclaration=$true
    $writer=[Xml.XmlWriter]::Create($text,$settings)
    try {
        $writer.WriteStartElement('CustomDCCloneAllowList','uri:microsoft.com:schemas:CustomDCCloneAllowList')
        foreach($entry in $Entries) {
            if($entry.type -cne 'Service' -or -not $entry.name) { throw 'Unreviewed application inclusion type/name.' }
            $writer.WriteStartElement('Allow','');$writer.WriteElementString('Name','',$entry.name);$writer.WriteElementString('Type','',$entry.type);$writer.WriteEndElement()
        }
        $writer.WriteEndElement();$writer.Flush()
    } finally { $writer.Dispose() }
    return ,([Text.UTF8Encoding]::new($false).GetBytes($text.ToString()))
}
function Write-OnlineInclusion {
    Assert-CanRun;Assert-OnlineWorld $true $null $null
    $path='C:\Windows\NTDS\CustomDCCloneAllowList.xml'
    $bytes=Encode-OnlineInclusion $baseline.applications.reference_entries
    Write-OnlineEvidence (Join-Path $root 'inclusion.xml') $bytes
    $script:state.recovery.intent=[ordered]@{operation='create-new-inclusion';path=$path;sha256=(Bytes-Hash $bytes);vendor_approval_claimed=$false};Checkpoint-Online 'before-inclusion-create'
    try {
        $null=Assert-OnlineLocalPath $path;$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $file.Write($bytes,0,$bytes.Length);$file.Flush($true) } finally { $file.Dispose() }
        $owned=Read-OnlineFile $path
        if(-not $owned.exists -or $owned.sha256 -cne (Bytes-Hash $bytes)) { throw 'Created inclusion bytes differ.' }
        $script:state.recovery.custom_file=$owned;$script:state.recovery.intent=$null
    } catch { $script:publicationUncertain=$true;throw }
    Checkpoint-Online 'inclusion-created'
}
function Project-OnlineXML([Xml.XmlElement]$Element) {
    $children=@($Element.ChildNodes | Where-Object {$_ -is [Xml.XmlElement]} | ForEach-Object { Project-OnlineXML $_ })
    return [ordered]@{name=$Element.LocalName;namespace=$Element.NamespaceURI;value=$(if($children.Count){''}else{$Element.InnerText});children=$children}
}
function Read-OnlineXML([string]$Path) {
    $file=Read-OnlineFile $Path;if(-not $file.exists) { throw 'Expected owned XML is absent.' }
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create($file.path,$settings);$document=[Xml.XmlDocument]::new();$document.XmlResolver=$null
    try { $document.Load($reader) } finally { $reader.Dispose() }
    $evidence=Get-Content -LiteralPath (Join-Path $StageDirectory 'schema-evidence.json') -Raw | ConvertFrom-Json
    $schemas=@($evidence.observation.files | Where-Object {$_.path -match 'DCCloneConfigSchema\.xsd$'})
    if($schemas.Count -ne 1) { throw 'Expected one captured schema.' }
    $schemaReader=[Xml.XmlReader]::Create([IO.StringReader]::new([string]$schemas[0].text),$settings)
    try { $schema=[Xml.Schema.XmlSchema]::Read($schemaReader,$null) } finally { $schemaReader.Dispose() }
    [void]$document.Schemas.Add($schema);$document.Validate($null)
    $projection=Project-OnlineXML $document.DocumentElement
    if($projection.name -cne 'DCCloneConfig' -or $projection.namespace -cne 'uri:microsoft.com:schemas:DCCloneConfig' -or @($projection.children).Count -ne 1 -or
        $projection.children[0].name -cne 'ComputerName' -or $projection.children[0].namespace -cne '' -or $projection.children[0].value -cne 'ADSDK25CLONE') { throw 'Successful clone configuration projection differs.' }
    return $projection
}
function Get-OnlineCaseNames { return @('missing-group-sdk','missing-group-reference','add-direct-membership','excluded-apps-sdk','excluded-apps-reference','online-sdk-success','online-sdk-existing','online-reference-existing','online-reference-success','remove-direct-membership') }
function Assert-OnlineCase($Case) {
    if($Case.name -cnotin (Get-OnlineCaseNames) -or $Case.kind -cnotin @('sdk','reference','membership')) { throw 'Unknown online case.' }
    $kind=if($Case.name -like '*-sdk' -or $Case.name -like 'online-sdk-*'){'sdk'}elseif($Case.name -like '*-reference' -or $Case.name -like 'online-reference-*'){'reference'}else{'membership'}
    $expectation=if($Case.name -like 'missing-group-*'){'group'}elseif($Case.name -like 'excluded-apps-*'){'applications'}elseif($Case.name -like '*-success'){'written'}elseif($Case.name -like '*-existing'){'exists'}elseif($Case.name -ceq 'add-direct-membership'){'member'}else{'absent'}
    if($Case.kind -cne $kind -or $Case.expectation -cne $expectation) { throw 'Online case kind or expectation differs.' }
    $directory=Assert-StagePath (Join-Path $root $Case.name)
    $expected=if($Case.name -like 'missing-group-*' -or $Case.name -like 'excluded-apps-*'){Join-Path $directory 'output'}else{'C:\Windows\NTDS'}
    if($Case.output -cne $expected -or $Case.computer_name -cne 'ADSDK25CLONE') { throw 'Online case output or configuration differs.' }
    return $directory
}
function Read-OnlineReferenceTemplate($Assembly,[string]$Expectation) {
    $key=switch($Expectation) { 'group' {'NewADDCCloneConfigFileNoCloningPrivilegeMessage'} 'applications' {'NewADDCCloneConfigFileWhiteListNotCompleteMessage'} 'exists' {'NewADDCCloneConfigFileExistingMessage'} default {return $null} }
    $found=@()
    foreach($name in $Assembly.GetManifestResourceNames()) {
        if(-not $name.EndsWith('.resources',[StringComparison]::Ordinal)) { continue }
        $stream=$Assembly.GetManifestResourceStream($name);$reader=[Resources.ResourceReader]::new($stream)
        try { foreach($entry in $reader) { if($entry.Key -ceq $key) { $found+=@($entry.Value) } } }
        finally { $reader.Dispose();$stream.Dispose() }
    }
    if($found.Count -ne 1 -or $found[0] -isnot [string] -or -not $found[0].Trim() -or $found[0].Length -gt 4096) { throw 'Expected one bounded Microsoft rejection resource.' }
    return [ordered]@{key=$key;template=[string]$found[0]}
}
function Test-OnlineReferenceDiagnostic([string]$Diagnostic,[string]$Template) {
    if(-not $Template -or $Template.Length -gt 4096) { return $false }
    $text=$Diagnostic -replace '\s+',' ';$cursor=0;$meaningful=0
    foreach($fragment in [regex]::Split(($Template -replace '\s+',' '),'\{\d+(?:[^{}]*)\}')) {
        $literal=$fragment.Trim();if(-not $literal) { continue };$meaningful+=$literal.Length
        $index=$text.IndexOf($literal,$cursor,[StringComparison]::Ordinal)
        if($index -lt 0) { return $false };$cursor=$index+$literal.Length
    }
    return $meaningful -ge 20
}
function Invoke-OnlineReferenceChild($Case) {
    if($Case.kind -cne 'reference') { throw 'Reference mode requires a reference case.' }
    $directory=Assert-OnlineCase $Case;$path=Join-Path $Case.output 'DCCloneConfig.xml';$before=Read-OnlineFile $path
    $record=[ordered]@{completed=$false;cmdlet_invoked=$false;offline=$false;cmdlet_error=$null;harness_error=$null;before=$before;after=$null;streams_sha256=$null;rejection_resource=$null;publication_uncertain=$false}
    try {
        if(-not (Same-OnlineValue $before $Case.output_before)) { throw 'Reference output changed before child invocation.' }
        $command=Get-Command New-ADDCCloneConfigFile -ErrorAction Stop
        if((Get-FileHash -LiteralPath $command.ImplementingType.Assembly.Location -Algorithm SHA256).Hash -cne $baseline.versions.assembly_sha256) { throw 'Reference assembly changed.' }
        $record.rejection_resource=Read-OnlineReferenceTemplate $command.ImplementingType.Assembly $Case.expectation
        $record.cmdlet_invoked=$true
        try { New-ADDCCloneConfigFile -Path $Case.output -CloneComputerName $Case.computer_name -ErrorAction Stop *> (Join-Path $directory 'reference.streams.txt') }
        catch { $record.cmdlet_error=Error-Observation $_ }
        $record.after=Read-OnlineFile $path
        if(($before.exists -and -not (Same-OnlineValue $before $record.after)) -or (-not $before.exists -and $Case.expectation -cne 'written' -and $record.after.exists)) { $record.publication_uncertain=$true;throw 'Reference altered an existing file or published during a rejection case.' }
        if((Get-Item -LiteralPath (Join-Path $directory 'reference.streams.txt')).Length -gt 2097152) { throw 'Reference diagnostics exceed the bound.' }
        $record.streams_sha256=(Get-FileHash -LiteralPath (Join-Path $directory 'reference.streams.txt') -Algorithm SHA256).Hash
        $record.completed=$true
    } catch { $record.harness_error=Error-Observation $_;if($record.cmdlet_invoked -and $null -eq $record.after) { $record.publication_uncertain=$true } }
    Write-NewJson (Join-Path $directory 'reference.json') $record
}
function Invoke-OnlineMembershipChild($Case) {
    if($Case.kind -cne 'membership') { throw 'Membership mode requires a membership case.' }
    $directory=Assert-OnlineCase $Case;$add=($Case.name -ceq 'add-direct-membership')
    $record=[ordered]@{completed=$false;mutation_invoked=$false;mutation_uncertain=$false;operation=$(if($add){'add'}else{'remove'});before=$null;after=$null;error=$null}
    try {
        $record.before=Read-OnlineReplica 'ADSDK25DC1.ad.sdk.test';Assert-OnlineReplica $record.before (-not $add)
        # Apply only the one member-attribute delta to the immutable group GUID.
        # This is a checked precondition, not a claim of an atomic AD transaction.
        $record.mutation_invoked=$true
        if($add) { Set-ADObject -Identity ([guid]$baseline.directory.group_guid) -Server 'ADSDK25DC1.ad.sdk.test' -Add @{member=$baseline.directory.source_dn} -ErrorAction Stop }
        else { Set-ADObject -Identity ([guid]$baseline.directory.group_guid) -Server 'ADSDK25DC1.ad.sdk.test' -Remove @{member=$baseline.directory.source_dn} -ErrorAction Stop }
        $record.after=Read-OnlineReplica 'ADSDK25DC1.ad.sdk.test'
        $expected=@();if($add){$expected=@($baseline.directory.source_dn)}
        if(-not (Same-OnlineValue @($record.after.members) $expected)) { throw 'Exact member-attribute delta was not observed.' }
        $record.completed=$true
    } catch { $record.error=Error-Observation $_;if($record.mutation_invoked){$record.mutation_uncertain=$true} }
    Write-NewJson (Join-Path $directory 'membership.json') $record
}
function Invoke-OnlineCase([string]$Name,[string]$Kind,[string]$Expectation) {
    Assert-CanRun;Assert-OnlineStage
    if($Name -cne (Get-OnlineCaseNames)[$script:state.cases.Count]) { throw 'Online case order differs.' }
    $directory=Assert-StagePath (Join-Path $root $Name);if(Test-Path -LiteralPath $directory) { throw 'Existing online case is preserved.' };[void][IO.Directory]::CreateDirectory($directory)
    $output=if($Name -like 'missing-group-*' -or $Name -like 'excluded-apps-*'){Join-Path $directory 'output'}else{'C:\Windows\NTDS'}
    if($output -cne 'C:\Windows\NTDS') { [void][IO.Directory]::CreateDirectory($output) }
    $definition=[ordered]@{name=$Name;kind=$Kind;expectation=$Expectation;output=$output;computer_name='ADSDK25CLONE';output_before=(Read-OnlineFile (Join-Path $output 'DCCloneConfig.xml'))}
    $casePath=Join-Path $directory 'case.json';Write-NewJson $casePath $definition
    $entry=[ordered]@{name=$Name;kind=$Kind;process=$null;observation=$null;output_before=$definition.output_before;output_after=$null;passed=$false;error=$null};$script:state.cases+=@($entry)
    if($Expectation -ceq 'written') { $script:state.recovery.intent=[ordered]@{operation='generate-config';case=$Name;path=(Join-Path $output 'DCCloneConfig.xml')} }
    Checkpoint-Online ('before-'+$Name)
    try {
        if($Kind -ceq 'sdk') {
            $options=[ordered]@{Configuration=[ordered]@{computer_name='ADSDK25CLONE'};Directory=$output;Offline=$false;Timeout=30000000000}
            $optionsPath=Join-Path $directory 'options.json';Write-NewJson $optionsPath $options
            $entry.process=Invoke-OwnedChild $NativeExecutable ('-options "'+$optionsPath+'"') (Join-Path $directory 'child') $ProcessTimeoutSeconds
        } else {
            $childMode=if($Kind -ceq 'membership'){'MembershipChild'}else{'ReferenceChild'}
            $arguments='-NoLogo -NoProfile -NonInteractive -File "'+$PSCommandPath+'" -Mode '+$childMode+' -StageDirectory "'+$StageDirectory+'" -Run "'+$Run+'" -ExpectedScriptSHA256 '+$ExpectedScriptSHA256+' -CasePath "'+$casePath+'" -ExpectedCaseSHA256 '+(Get-FileHash -LiteralPath $casePath -Algorithm SHA256).Hash
            $entry.process=Invoke-OwnedChild (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') $arguments (Join-Path $directory 'child') $ProcessTimeoutSeconds
        }
        Assert-CanRun
        if($Kind -ceq 'sdk') {
            try {
                $wire=Get-Content -LiteralPath $entry.process.stdout_path -Raw | ConvertFrom-Json
                if($wire.protocol_version -ne 1 -or $wire.operation -cne 'generate_config' -or $wire.data.checks_skipped -isnot [bool] -or $wire.data.checks_skipped -or $wire.data.outcome -cnotin @('written','not_written') -or $wire.error_details.present -isnot [bool]) { throw 'Online SDK result lacks certain publication evidence.' }
                $entry.observation=$wire
            } catch { $script:publicationUncertain=$true;throw }
            $entry.output_after=Read-OnlineFile (Join-Path $output 'DCCloneConfig.xml')
            if($entry.output_before.exists -and -not (Same-OnlineValue $entry.output_before $entry.output_after)) { $script:publicationUncertain=$true;throw 'SDK altered an existing output.' }
            if(-not $entry.output_before.exists -and $Expectation -cne 'written' -and $entry.output_after.exists) { $script:publicationUncertain=$true;throw 'SDK published during a rejection case.' }
            if($Expectation -ceq 'written') { $entry.passed=($entry.process.exit_code -eq 0 -and -not $wire.error_details.present -and $wire.data.outcome -ceq 'written' -and $wire.data.prerequisites.complete -and $entry.output_after.exists) }
            elseif($Expectation -ceq 'exists') { $entry.passed=($entry.process.exit_code -eq 1 -and $wire.error_details.present -and $wire.error_details.output_exists -and $wire.data.outcome -ceq 'not_written' -and (Same-OnlineValue $entry.output_before $entry.output_after)) }
            else {
                $entry.passed=($entry.process.exit_code -eq 1 -and $wire.error_details.present -and $wire.error_details.prerequisite -and $wire.data.outcome -ceq 'not_written' -and -not $entry.output_after.exists -and -not $wire.data.prerequisites.complete)
                if($Expectation -ceq 'group') { $entry.passed=$entry.passed -and -not $wire.data.prerequisites.cloneable_group_member -and $wire.error_details.message.Contains('not a member') }
                else { $entry.passed=$entry.passed -and $wire.data.prerequisites.cloneable_group_member -and $wire.data.prerequisites.applications.complete -and (Same-OnlineValue (Online-Entries $wire.data.prerequisites.applications.entries) (Online-Entries $baseline.applications.reference_entries)) }
            }
        } elseif($Kind -ceq 'reference') {
            $ref=Get-Content -LiteralPath (Join-Path $directory 'reference.json') -Raw | ConvertFrom-Json;$entry.observation=$ref
            if($ref.publication_uncertain -isnot [bool] -or $ref.publication_uncertain -or $ref.completed -isnot [bool] -or -not $ref.completed) { $script:publicationUncertain=$true;throw 'Reference publication is uncertain.' }
            $entry.output_after=Read-OnlineFile (Join-Path $output 'DCCloneConfig.xml')
            $entry.passed=($entry.process.exit_code -eq 0 -and $ref.completed -and $ref.cmdlet_invoked -and -not $ref.offline -and $null -eq $ref.harness_error -and (Same-OnlineValue $entry.output_after $ref.after))
            if($Expectation -ceq 'written') { $entry.passed=$entry.passed -and $null -eq $ref.cmdlet_error -and $entry.output_after.exists }
            else {
                $diagnostics=Get-Content -LiteralPath (Join-Path $directory 'reference.streams.txt') -Raw
                $diagnostics+=' '+($ref.cmdlet_error | ConvertTo-Json -Depth 12 -Compress)
                $entry.passed=$entry.passed -and $null -ne $ref.rejection_resource -and (Test-OnlineReferenceDiagnostic $diagnostics $ref.rejection_resource.template)
                if($Expectation -ceq 'exists') { $entry.passed=$entry.passed -and (Same-OnlineValue $entry.output_before $entry.output_after) }
                else { $entry.passed=$entry.passed -and -not $entry.output_after.exists }
            }
        } else {
            $mutation=Get-Content -LiteralPath (Join-Path $directory 'membership.json') -Raw | ConvertFrom-Json;$entry.observation=$mutation
            if($mutation.mutation_uncertain -isnot [bool] -or $mutation.mutation_uncertain -or $mutation.completed -isnot [bool] -or -not $mutation.completed -or $entry.process.exit_code -ne 0) { $script:mutationUncertain=$true;throw 'Directory mutation completion is uncertain.' }
            $entry.passed=($mutation.mutation_invoked -and $null -eq $mutation.error)
            $script:state.recovery.group_added=($Name -ceq 'add-direct-membership');$script:state.recovery.intent=$null
        }
        if($Kind -ne 'membership' -and $entry.output_after.exists) { Write-OnlineEvidence -Path (Join-Path $directory 'output.xml') -Source $entry.output_after.path }
        if($Expectation -ceq 'written' -and $entry.output_after.exists) { $script:state.recovery.config_file=$entry.output_after;$script:state.recovery.intent=$null }
        if(-not $entry.passed) { throw 'Observed online case failed its expectation; retain evidence and recovery state.' }
    } catch {
        if($null -ne $entry.process -and $entry.process.completed) {
            if($Kind -ceq 'membership' -and $null -eq $entry.observation) { $script:mutationUncertain=$true }
            elseif($Kind -cne 'membership' -and ($null -eq $entry.observation -or $null -eq $entry.output_after)) { $script:publicationUncertain=$true }
        }
        $entry.error=Error-Observation $_;throw
    }
    finally { Write-NewJson (Join-Path $directory 'result.json') $entry }
    Checkpoint-Online ('after-'+$Name)
    return $entry
}
function Invoke-OnlineQualification {
    if(Test-Path -LiteralPath $root) { throw 'Online fixture subtree exists; no replay.' }
    [void][IO.Directory]::CreateDirectory($root);[void][IO.Directory]::CreateDirectory((Join-Path $root 'events'));[void][IO.Directory]::CreateDirectory((Join-Path $root 'snapshots'))
    Write-OnlineEvidence (Join-Path $root 'owner.txt') ([Text.Encoding]::UTF8.GetBytes($Run));Write-NewJson (Join-Path $root 'started.json') $script:state
    try {
        Assert-OnlineWorld $false $null $null
        $null=Invoke-OnlineCase 'missing-group-sdk' 'sdk' 'group'
        $null=Invoke-OnlineCase 'missing-group-reference' 'reference' 'group'
        Assert-OnlineWorld $false $null $null
        $script:state.recovery.intent=[ordered]@{operation='add-member';group_guid=$baseline.directory.group_guid;member_guid=$baseline.directory.source_guid;member_dn=$baseline.directory.source_dn}
        $null=Invoke-OnlineCase 'add-direct-membership' 'membership' 'member';Wait-OnlineReplicas $true
        Assert-OnlineWorld $true $null $null
        $null=Invoke-OnlineCase 'excluded-apps-sdk' 'sdk' 'applications'
        $null=Invoke-OnlineCase 'excluded-apps-reference' 'reference' 'applications'
        Write-OnlineInclusion
        Assert-OnlineWorld $true $script:state.recovery.custom_file $null
        $sdk=Invoke-OnlineCase 'online-sdk-success' 'sdk' 'written';$sdkProjection=Read-OnlineXML $sdk.output_after.path
        Assert-OnlineWorld $true $script:state.recovery.custom_file $script:state.recovery.config_file
        $null=Invoke-OnlineCase 'online-sdk-existing' 'sdk' 'exists'
        $null=Invoke-OnlineCase 'online-reference-existing' 'reference' 'exists'
        Remove-OnlineOwnedFile $script:state.recovery.config_file;$script:state.recovery.config_file=$null;Checkpoint-Online 'sdk-output-removed'
        Assert-OnlineWorld $true $script:state.recovery.custom_file $null
        $reference=Invoke-OnlineCase 'online-reference-success' 'reference' 'written';$referenceProjection=Read-OnlineXML $reference.output_after.path
        if(-not (Same-OnlineValue $sdkProjection $referenceProjection)) { throw 'Native and reference online XML projections differ.' }
        Remove-OnlineOwnedFile $script:state.recovery.config_file;$script:state.recovery.config_file=$null;Checkpoint-Online 'reference-output-removed'
        Remove-OnlineOwnedFile $script:state.recovery.custom_file;$script:state.recovery.custom_file=$null;Checkpoint-Online 'inclusion-removed'
        Assert-OnlineWorld $true $null $null
        $script:state.recovery.intent=[ordered]@{operation='remove-member';group_guid=$baseline.directory.group_guid;member_guid=$baseline.directory.source_guid;member_dn=$baseline.directory.source_dn}
        $null=Invoke-OnlineCase 'remove-direct-membership' 'membership' 'absent';Wait-OnlineReplicas $false
        Assert-OnlineWorld $false $null $null
        $script:state.cleanup_complete=$true;$script:state.completed=$true;$script:state.passed=$true;Checkpoint-Online 'restored'
    } catch { $script:state.error=Error-Observation $_ }
    finally {
        $script:state.process_uncertain=$script:processUncertain;$script:state.publication_uncertain=$script:publicationUncertain;$script:state.mutation_uncertain=$script:mutationUncertain;$script:state.capture_failed=$script:captureFailed
        if($script:state.process_uncertain -or $script:state.publication_uncertain -or $script:state.mutation_uncertain -or $script:state.capture_failed) { $script:state.passed=$false }
        Write-NewJson (Join-Path $root 'summary.json') $script:state
    }
    return $script:state
}

Assert-OnlineStage
Import-OnlineFunctions (Join-Path $StageDirectory 'negative-process-support.ps1') @('Assert-StagePath','Bytes-Hash','Write-NewBytes','Write-NewJson','Error-Observation','Wait-OwnedProcess','Start-OwnedProcess','Invoke-OwnedChild')
Import-OnlineFunctions (Join-Path $StageDirectory 'inventory-support.ps1') @('Read-InventoryItem','Assert-InventoryPath','Read-InventoryFile','Inventory-SID','Get-InventoryRemovable','Read-CloneConfigOnlineInventory')
Import-Module ActiveDirectory -ErrorAction Stop
$baseline=Get-Content -LiteralPath (Join-Path $StageDirectory 'inventory.json') -Raw | ConvertFrom-Json
$root=Join-Path $StageDirectory 'online-cases'
if($Mode -ne 'Run') {
    $CasePath=Assert-StagePath $CasePath
    if($ExpectedCaseSHA256 -notmatch '^[A-F0-9]{64}$' -or (Get-FileHash -LiteralPath $CasePath -Algorithm SHA256).Hash -cne $ExpectedCaseSHA256) { throw 'Child case bytes changed.' }
    $case=Get-Content -LiteralPath $CasePath -Raw | ConvertFrom-Json;$directory=Assert-OnlineCase $case
    if($CasePath -cne (Join-Path $directory 'case.json')) { throw 'Child case path differs.' }
    if($Mode -ceq 'ReferenceChild') { Invoke-OnlineReferenceChild $case } else { Invoke-OnlineMembershipChild $case }
    exit
}
if($NativeExecutable -cne (Join-Path $StageDirectory 'clone-config-helper.exe') -or $HelperSource -cne (Join-Path $StageDirectory 'clone-config-helper.go') -or $InventoryPath -cne (Join-Path $StageDirectory 'inventory.json')) { throw 'Online payload arguments differ.' }
$build=Get-Content -LiteralPath (Join-Path $StageDirectory 'build.json') -Raw | ConvertFrom-Json
$pins=Get-OnlinePins
$script:state=[ordered]@{schema_version=1;run=$Run;computer=$env:COMPUTERNAME;source_commit=$build.source_commit;source_archive_sha256=$build.source_archive_sha256;build_manifest_sha256=$pins['build.json'];helper_build_manifest_sha256=$pins['helper-v3-build.json'];helper_source_sha256=$pins['clone-config-helper.go'];helper_binary_sha256=$pins['clone-config-helper.exe'];harness_sha256=$ExpectedScriptSHA256;inventory_sha256=$pins['inventory.json'];process_support_sha256=$pins['negative-process-support.ps1'];inventory_support_sha256=$pins['inventory-support.ps1'];schema_evidence_sha256=$pins['schema-evidence.json'];toolchain=$build.toolchain;phase='prepared';completed=$false;passed=$false;process_uncertain=$false;publication_uncertain=$false;mutation_uncertain=$false;capture_failed=$false;cleanup_complete=$false;staging_preserved=$true;error=$null;cases=@();recovery=[ordered]@{group_added=$false;custom_file=$null;config_file=$null;intent=$null;baseline_group_guid=$baseline.directory.group_guid;baseline_source_guid=$baseline.directory.source_guid;baseline_inventory_sha256=$pins['inventory.json'];unknown_means_no_retry_or_cleanup=$true}}
Invoke-OnlineQualification | ConvertTo-Json -Depth 24 -Compress
