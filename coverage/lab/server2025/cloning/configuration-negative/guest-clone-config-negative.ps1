#Requires -Version 5.1
# PREPARED qualification only. The host owns staging and review; this script
# never deletes evidence, changes ACLs/groups/NTDS settings, or uses online mode.
# Stage payloads: this script, clone-config-helper.exe, clone-config-helper.go,
# original build.json, helper-v2-build.json, and owner.txt containing Run.
param(
    [ValidateSet('Run','ReferenceChild')][string]$Mode='Run',
    [Parameter(Mandatory)][string]$StageDirectory,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,120}$')][string]$Run,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedScriptSHA256,
    [string]$NativeExecutable,
    [string]$HelperSource,
    [string]$CasePath,
    [ValidateRange(1,300)][int]$ProcessTimeoutSeconds=60
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:processUncertain=$false;$script:publicationUncertain=$false;$script:captureFailed=$false

function Assert-StagePath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    $stage=[IO.Path]::GetFullPath($StageDirectory)
    if($stage -cne (Join-Path 'C:\ad-sdk-validation' $Run) -or ($full -cne $stage -and -not $full.StartsWith($stage+'\',[StringComparison]::OrdinalIgnoreCase))) { throw 'Path escaped the owned non-NTDS staging directory.' }
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Owned path traverses a reparse point.' }
    }
    return $full
}
function Bytes-Hash([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($Bytes)).Replace('-','') } finally { $hasher.Dispose() }
}
function Write-NewBytes([string]$Path,[byte[]]$Bytes) {
    $full=Assert-StagePath $Path
    if(Test-Path -LiteralPath $full) { throw 'Existing evidence is preserved; no replay.' }
    $pending=$full+'.pending-'+[guid]::NewGuid().ToString('N')
    $stream=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Move($pending,$full)
}
function Write-NewJson([string]$Path,$Value) {
    try { Write-NewBytes $Path ([Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 24))) }
    catch { $script:captureFailed=$true;throw }
}
function Error-Observation($ErrorRecord) {
    $chain=@();$exception=$ErrorRecord.Exception
    while($null -ne $exception) {
        $chain+=@([ordered]@{type=$exception.GetType().FullName;message=$exception.Message;hresult=$exception.HResult;native_error_code=$(if($exception -is [ComponentModel.Win32Exception]){$exception.NativeErrorCode}else{$null})})
        $exception=$exception.InnerException
    }
    return [ordered]@{id=$ErrorRecord.FullyQualifiedErrorId;category=$ErrorRecord.CategoryInfo.Category.ToString();text=$ErrorRecord.ToString();exceptions=$chain}
}
function Assert-CanRun {
    if($script:processUncertain -or $script:publicationUncertain -or $script:captureFailed) { throw 'An earlier child, publication, or capture is uncertain; no further child may start.' }
}
function Wait-OwnedProcess($Process,[int]$Seconds) {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($watch.Elapsed.TotalSeconds -lt $Seconds) { if($Process.WaitForExit(250)) { return $true } }
    return $false
}
function Start-OwnedProcess([string]$Executable,[string]$Arguments,[string]$Stdout,[string]$Stderr,$Record) {
    $process=Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr -ErrorAction Stop
    try { $null=$process.Handle;$Record.pid=$process.Id;$Record.started_utc=$process.StartTime.ToUniversalTime().ToString('o');return $process }
    catch { $process.Dispose();throw }
}
function Invoke-OwnedChild([string]$Executable,[string]$Arguments,[string]$Prefix,[int]$Seconds) {
    Assert-CanRun
    $stdout=Assert-StagePath ($Prefix+'.stdout.txt');$stderr=Assert-StagePath ($Prefix+'.stderr.txt')
    foreach($path in @($stdout,$stderr,($Prefix+'.requested.json'),($Prefix+'.started.json'),($Prefix+'.finished.json'))) { if(Test-Path -LiteralPath $path) { throw 'Existing child evidence is preserved.' } }
    $record=[ordered]@{pid=$null;started_utc=$null;completed=$false;process_uncertain=$true;exit_code=$null;stdout_path=$stdout;stderr_path=$stderr;stdout_sha256=$null;stderr_sha256=$null;error=$null;timeout_seconds=$Seconds}
    Write-NewJson ($Prefix+'.requested.json') $record
    $process=$null
    try {
        $process=Start-OwnedProcess $Executable $Arguments $stdout $stderr $record
        Write-NewJson ($Prefix+'.started.json') $record
        if(-not (Wait-OwnedProcess $process $Seconds)) { throw 'Owned child exceeded its deadline; preserve it and all files without retry or termination.' }
        $record.exit_code=$process.ExitCode
        if($null -eq $record.exit_code) { throw 'Owned child exit status is unavailable.' }
        $record.completed=$true;$record.process_uncertain=$false
        foreach($path in @($stdout,$stderr)) { if((Get-Item -LiteralPath $path).Length -gt 2097152) { throw 'Completed child raw stream exceeds the capture bound.' } }
        $record.stdout_sha256=(Get-FileHash -LiteralPath $stdout).Hash;$record.stderr_sha256=(Get-FileHash -LiteralPath $stderr).Hash
    } catch { $record.error=Error-Observation $_;if(-not $record.completed){$script:processUncertain=$true}else{$script:captureFailed=$true} }
    finally {
        # Disposing our held handle never terminates the child or resolves uncertainty.
        if($null -ne $process) { $process.Dispose() }
        Write-NewJson ($Prefix+'.finished.json') $record
    }
    return $record
}
function Get-NegativeCases {
    $cases=[Collections.Generic.List[object]]::new()
    $static=[ordered]@{static=$true;ipv4_address='192.0.2.20';ipv4_subnet_mask='255.255.255.0';ipv4_default_gateway='192.0.2.1';ipv4_dns_resolvers=@('192.0.2.10')}
    function Add-Case([string]$Name,$Configuration,[string]$Reference,[string]$Shape,[string]$Difference,[bool]$Control=$false) {
        $cases.Add([ordered]@{name=$Name;configuration=$Configuration;positive_control=$Control;sdk_expectation=$(if($Control){'written'}else{'invalid_configuration'});reference_expectation=$Reference;reference_shape=$Shape;reference_no_file_error_policy=$(if($Name -ceq 'static-empty-dns'){'parameter_validation_or_none'}else{'none'});intentional_difference=$Difference})
    }
    Add-Case 'control-v4-static' $static 'written' 'v4-static' '' $true
    Add-Case 'control-four-v6-dns' ([ordered]@{static=$false;ipv6_dns_resolvers=@('2001:db8::10','2001:db8::11','2001:db8::12','2001:db8::13')}) 'written' 'v6-dynamic' '' $true
    foreach($change in @(
        @('dynamic-with-static-fields','static',$false,'no_file','none',''),
        @('static-missing-address','ipv4_address',$null,'no_file','none',''),
        @('static-missing-mask','ipv4_subnet_mask',$null,'no_file','none',''),
        @('static-missing-dns','ipv4_dns_resolvers',$null,'no_file','none',''),
        @('static-empty-dns','ipv4_dns_resolvers',@(),'no_file','none',''),
        @('malformed-ipv4-address','ipv4_address','not-an-ip','written','v4-static','SDK rejects malformed address literals; inspected reference serializes strings.'),
        @('broadcast-address','ipv4_address','255.255.255.255','written','v4-static','SDK rejects the IPv4 broadcast address; reference serializes it.'),
        @('broadcast-gateway','ipv4_default_gateway','255.255.255.255','written','v4-static','SDK rejects the IPv4 broadcast gateway; reference serializes it.'),
        @('noncontiguous-mask','ipv4_subnet_mask','255.0.255.0','written','v4-static','SDK requires a contiguous IPv4 mask; reference serializes the supplied mask.')
    )) {
        $configuration=[ordered]@{};foreach($key in $static.Keys){$configuration[$key]=$static[$key]}
        if($null -eq $change[2]){$configuration.Remove($change[1])}else{$configuration[$change[1]]=$change[2]}
        Add-Case $change[0] $configuration $change[3] $change[4] $change[5]
    }
    Add-Case 'dynamic-with-gateway' ([ordered]@{static=$false;ipv4_default_gateway='192.0.2.1'}) 'no_file' 'none' ''
    Add-Case 'five-v4-dns' ([ordered]@{static=$false;ipv4_dns_resolvers=@('192.0.2.10','192.0.2.11','192.0.2.12','192.0.2.13','192.0.2.14')}) 'no_file' 'none' ''
    Add-Case 'five-v6-dns' ([ordered]@{static=$false;ipv6_dns_resolvers=@('2001:db8::10','2001:db8::11','2001:db8::12','2001:db8::13','2001:db8::14')}) 'no_file' 'none' ''
    Add-Case 'static-without-family' ([ordered]@{static=$true}) 'written' 'none' 'SDK rejects Static without a family; reference mode selection emits no IPSettings.'
    Add-Case 'static-v4-dns-only' ([ordered]@{static=$true;ipv4_dns_resolvers=@('192.0.2.10')}) 'written' 'v4-dynamic' 'SDK requires complete static IPv4 settings; reference falls back to dynamic IPv4 when only DNS is supplied.'
    Add-Case 'broadcast-dns' ([ordered]@{static=$false;ipv4_dns_resolvers=@('255.255.255.255')}) 'written' 'v4-dynamic' 'SDK rejects a broadcast DNS address; reference serializes it.'
    Add-Case 'malformed-v4-dns' ([ordered]@{static=$false;ipv4_dns_resolvers=@('not-an-ip')}) 'written' 'v4-dynamic' 'SDK validates DNS literals; reference serializes strings.'
    Add-Case 'malformed-v6-dns' ([ordered]@{static=$false;ipv6_dns_resolvers=@('not-an-ipv6')}) 'written' 'v6-dynamic' 'SDK validates DNS literals; reference serializes strings.'
    return @($cases.ToArray())
}
function Reference-Arguments($Configuration,[string]$OutputDirectory) {
    $null=Assert-StagePath $OutputDirectory
    $arguments=@{Offline=$true;Path=$OutputDirectory;ErrorAction='Stop'}
    $map=@{static='Static';ipv4_address='IPv4Address';ipv4_subnet_mask='IPv4SubnetMask';ipv4_default_gateway='IPv4DefaultGateway';ipv4_dns_resolvers='IPv4DNSResolver';ipv6_dns_resolvers='IPv6DNSResolver'}
    foreach($property in $Configuration.PSObject.Properties) {
        if(-not $map.ContainsKey($property.Name)) { throw 'Unexpected configuration field in reference case.' }
        $arguments[$map[$property.Name]]=$property.Value
    }
    return $arguments
}
function Expected-Projection($Case) {
    $result=[ordered]@{ip_settings=($Case.reference_shape -cne 'none');v4_mode='';v6_mode='';address='';mask='';gateway='';v4_dns=@();v6_dns=@()}
    $configuration=$Case.configuration
    if($Case.reference_shape -like 'v4-*') {
        $result.v4_mode=if($Case.reference_shape -ceq 'v4-static'){'StaticSettings'}else{'DynamicSettings'}
        $result.v4_dns=@($configuration.ipv4_dns_resolvers)
        if($Case.reference_shape -ceq 'v4-static') { $result.address=$configuration.ipv4_address;$result.mask=$configuration.ipv4_subnet_mask;$result.gateway=$configuration.ipv4_default_gateway }
    }
    if($Case.reference_shape -ceq 'v6-dynamic') { $result.v6_mode='DynamicSettings';$result.v6_dns=@($configuration.ipv6_dns_resolvers) }
    return $result
}
function Read-OutputFile([string]$Path) {
    $path=Assert-StagePath $Path
    $file=[ordered]@{exists=(Test-Path -LiteralPath $path);sha256=$null;bytes_base64=$null;schema_valid=$false;projection=$null;xml_error=$null}
    if(-not $file.exists) { return $file }
    if((Get-Item -LiteralPath $path).Length -gt 2097152) { throw 'Output exceeds the capture bound.' }
    $bytes=[IO.File]::ReadAllBytes($path);$file.sha256=Bytes-Hash $bytes;$file.bytes_base64=[Convert]::ToBase64String($bytes)
    try {
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
        $stream=[IO.MemoryStream]::new($bytes);$reader=[Xml.XmlReader]::Create($stream,$settings)
        $document=[Xml.XmlDocument]::new();$document.XmlResolver=$null
        try { $document.Load($reader) } finally { $reader.Dispose();$stream.Dispose() }
        if($document.DocumentElement.LocalName -cne 'DCCloneConfig' -or $document.DocumentElement.NamespaceURI -cne 'uri:microsoft.com:schemas:DCCloneConfig') { throw 'Unexpected clone XML root.' }
        $null=$document.Schemas.Add('uri:microsoft.com:schemas:DCCloneConfig',(Join-Path $env:windir 'System32\DCCloneConfigSchema.xsd'))
        $document.Validate($null);$file.schema_valid=$true
        $root=$document.DocumentElement;$v4=$root.SelectSingleNode('IPSettings/IPv4Settings/*');$v6=$root.SelectSingleNode('IPSettings/IPv6Settings/*')
        $projection=[ordered]@{ip_settings=($null -ne $root.SelectSingleNode('IPSettings'));v4_mode=$(if($v4){$v4.LocalName}else{''});v6_mode=$(if($v6){$v6.LocalName}else{''});address='';mask='';gateway='';v4_dns=@();v6_dns=@()}
        foreach($pair in @(@('address','Address'),@('mask','SubnetMask'),@('gateway','DefaultGateway'))) { if($v4 -and $v4.SelectSingleNode($pair[1])) { $projection[$pair[0]]=$v4.SelectSingleNode($pair[1]).InnerText } }
        if($v4) { $projection.v4_dns=@($v4.SelectNodes('DNSResolver') | ForEach-Object {$_.InnerText}) }
        if($v6) { $projection.v6_dns=@($v6.SelectNodes('DNSResolver') | ForEach-Object {$_.InnerText}) }
        $file.projection=$projection
    } catch { $file.xml_error=Error-Observation $_ }
    return $file
}
function Same-Projection($Left,$Right) { return ($Left | ConvertTo-Json -Depth 8 -Compress) -ceq ($Right | ConvertTo-Json -Depth 8 -Compress) }
function Assert-SdkEnvelope($Observation,$Wire) {
    try {
    if(-not $Observation.completed -or $Observation.process_uncertain -or $Observation.error -or $Wire.protocol_version -ne 1 -or $Wire.operation -cne 'generate_config' -or
        $null -eq $Wire.data -or $Wire.data.outcome -notin @('written','not_written') -or $Wire.data.checks_skipped -isnot [bool] -or -not $Wire.data.checks_skipped -or
        $Wire.data.prerequisites.complete -isnot [bool] -or $Wire.data.prerequisites.complete -or $Wire.error_details.present -isnot [bool]) { throw 'SDK publication or explicit Offline evidence is uncertain.' }
    } catch { $script:publicationUncertain=$true;throw }
}
function Test-CaseOutcome($Case,$SdkProcess,$Wire,$SdkFile,$ReferenceProcess,$Reference) {
    if(-not $SdkProcess.completed -or $SdkProcess.process_uncertain -or $SdkProcess.error -or -not $ReferenceProcess.completed -or $ReferenceProcess.process_uncertain -or $ReferenceProcess.error -or
        $ReferenceProcess.exit_code -ne 0 -or -not $Reference.completed -or -not $Reference.cmdlet_invoked -or $Reference.harness_error -or $Reference.offline -ne $true) { return $false }
    $expected=Expected-Projection $Case
    if($Case.positive_control) {
        return $SdkProcess.exit_code -eq 0 -and -not $Wire.error_details.present -and $Wire.data.outcome -ceq 'written' -and $SdkFile.exists -and $SdkFile.schema_valid -and
            $null -eq $Reference.cmdlet_error -and $Reference.file.exists -and $Reference.file.schema_valid -and (Same-Projection $SdkFile.projection $expected) -and (Same-Projection $Reference.file.projection $expected)
    }
    $sdkRejected=($SdkProcess.exit_code -eq 1 -and $Wire.error_details.present -and $Wire.error_details.invalid_configuration -and -not $Wire.error_details.invalid_path -and -not $Wire.error_details.permission -and
        -not $Wire.error_details.prerequisite -and -not $Wire.error_details.unsupported -and -not $Wire.error_details.deadline -and $null -eq $Wire.error_details.native_error -and $null -eq $Wire.error_details.errno_code -and
        $Wire.data.outcome -ceq 'not_written' -and -not $SdkFile.exists)
    if(-not $sdkRejected) { return $false }
    if($Case.reference_expectation -ceq 'no_file') {
        if($Reference.file.exists) { return $false }
        if($null -eq $Reference.cmdlet_error) { return $true }
        # Empty DNS may be rejected by the cmdlet's ValidateNotNullOrEmpty binder.
        # Other shared validators are expected to return without publication;
        # an arbitrary reference I/O/access exception must never pass this case.
        return $Case.reference_no_file_error_policy -ceq 'parameter_validation_or_none' -and
            @($Reference.cmdlet_error.exceptions | Where-Object type -ceq 'System.Management.Automation.ParameterBindingValidationException').Count -gt 0
    }
    return $Case.intentional_difference -ne '' -and $null -eq $Reference.cmdlet_error -and $Reference.file.exists -and $Reference.file.schema_valid -and (Same-Projection $Reference.file.projection $expected)
}
function Invoke-ReferenceChild($Case,[string]$Directory) {
    $output=Join-Path $Directory 'reference';$null=Assert-StagePath $output
    $record=[ordered]@{name=$Case.name;offline=$true;completed=$false;cmdlet_invoked=$false;cmdlet_error=$null;harness_error=$null;file=$null;publication=$null;module_version=$null;assembly_version=$null;assembly_sha256=$null;schema_sha256=$null;streams_sha256=$null}
    $savedDefaultDrive=$env:ADPS_LoadDefaultDrive
    try {
        $env:ADPS_LoadDefaultDrive='0';Import-Module ActiveDirectory -ErrorAction Stop
        $command=Get-Command New-ADDCCloneConfigFile -ErrorAction Stop
        if(-not $command.Parameters.ContainsKey('Offline')) { throw 'Reference command lacks explicit Offline mode.' }
        $assembly=$command.ImplementingType.Assembly.Location
        $record.module_version=$command.Module.Version.ToString();$record.assembly_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($assembly).FileVersion;$record.assembly_sha256=(Get-FileHash -LiteralPath $assembly).Hash
        $record.schema_sha256=(Get-FileHash -LiteralPath (Join-Path $env:windir 'System32\DCCloneConfigSchema.xsd')).Hash
        $arguments=Reference-Arguments $Case.configuration $output
        $record.cmdlet_invoked=$true
        try { & $command @arguments *> (Join-Path $Directory 'reference.streams.txt') } catch { $record.cmdlet_error=Error-Observation $_ }
        $record.file=Read-OutputFile (Join-Path $output 'DCCloneConfig.xml')
        $record.publication=if($record.file.exists){if($record.cmdlet_error){'published_with_exception'}else{'published'}}else{if($record.cmdlet_error){'exception_without_file'}else{'nonthrowing_without_file'}}
        $record.streams_sha256=(Get-FileHash -LiteralPath (Join-Path $Directory 'reference.streams.txt')).Hash
        $record.completed=$true
    } catch { $record.harness_error=Error-Observation $_ }
    finally { $env:ADPS_LoadDefaultDrive=$savedDefaultDrive;Write-NewJson (Join-Path $Directory 'reference.json') $record }
}

# The outer host wrapper must supply the owned profile guards and its mutex.
if($env:COMPUTERNAME -cne 'ADSDK25DC1') { throw 'Unexpected qualification computer.' }
$StageDirectory=Assert-StagePath $StageDirectory
if([IO.File]::ReadAllText((Assert-StagePath (Join-Path $StageDirectory 'owner.txt'))) -cne $Run) { throw 'Staging owner differs.' }
if((Get-FileHash -LiteralPath (Assert-StagePath $PSCommandPath)).Hash -cne $ExpectedScriptSHA256) { throw 'Guest source differs from the reviewed snapshot.' }
$cases=Get-NegativeCases
if($Mode -ceq 'ReferenceChild') {
    $CasePath=Assert-StagePath $CasePath
    $caseDirectory=[IO.Path]::GetDirectoryName($CasePath)
    if([IO.Path]::GetFileName($CasePath) -cne 'case.json' -or [IO.Path]::GetDirectoryName($caseDirectory) -cne (Join-Path $StageDirectory 'negative-cases')) { throw 'Reference case path differs.' }
    $case=Get-Content -LiteralPath $CasePath -Raw | ConvertFrom-Json
    $expected=@($cases | Where-Object name -ceq $case.name)
    if($expected.Count -ne 1 -or [IO.Path]::GetFileName($caseDirectory) -cne $case.name -or ($case | ConvertTo-Json -Depth 12 -Compress) -cne ($expected[0] | ConvertTo-Json -Depth 12 -Compress)) { throw 'Reference case is not the frozen definition.' }
    foreach($path in @((Join-Path $caseDirectory 'reference.json'),(Join-Path $caseDirectory 'reference.streams.txt'),(Join-Path $caseDirectory 'reference\DCCloneConfig.xml'))) { if(Test-Path -LiteralPath $path) { throw 'Reference case was already attempted; preserve its evidence without replay.' } }
    Invoke-ReferenceChild $case $caseDirectory
    exit 0
}
$NativeExecutable=Assert-StagePath $NativeExecutable;$HelperSource=Assert-StagePath $HelperSource
if((Get-FileHash -LiteralPath $NativeExecutable).Hash -cne '6E2DB3902038DF408192E3137CF541F86F2D43E99E3F455BA01C884140D4BEC9' -or
    (Get-FileHash -LiteralPath $HelperSource).Hash -cne 'F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1') { throw 'Frozen public-API helper identity differs.' }
$manifestPath=Assert-StagePath (Join-Path $StageDirectory 'build.json');$build=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if((Get-FileHash -LiteralPath $manifestPath).Hash -cne '6AB9B1B9129A39BC9C68FB4B00CB38D6DB4A31C4E925BB1C3790431927AD9E29') { throw 'Original SDK build manifest bytes differ.' }
if($build.source_commit -cne '4120ce5d13dd49de490cef67d41767ac3b409715' -or $build.source_archive_sha256 -cne '1FA1A904FDEE8ED7F49428117C8215989F895E3EBCF7AC3554827248654C2E19') { throw 'Frozen SDK build provenance differs.' }
$helperManifest=Assert-StagePath (Join-Path $StageDirectory 'helper-v2-build.json')
if((Get-FileHash -LiteralPath $helperManifest).Hash -cne '0D9B53AF8EDDD7E942144158D6BE56E343B5A4C2F576A0D4D79CA7F594907C75') { throw 'Separate helper-v2 build manifest bytes differ.' }
$root=Assert-StagePath (Join-Path $StageDirectory 'negative-cases')
if(Test-Path -LiteralPath $root) { throw 'Negative case run already exists; preserve it without replay.' }
[void][IO.Directory]::CreateDirectory($root)
Write-NewBytes (Join-Path $root 'owner.txt') ([Text.Encoding]::UTF8.GetBytes($Run))
$record=[ordered]@{schema_version=1;run=$Run;computer=$env:COMPUTERNAME;mode='explicit Offline only';source_commit=$build.source_commit;source_archive_sha256=$build.source_archive_sha256;build_manifest_sha256=(Get-FileHash -LiteralPath $manifestPath).Hash;helper_build_manifest_sha256=(Get-FileHash -LiteralPath $helperManifest).Hash;toolchain=$build.toolchain;helper_source_sha256=(Get-FileHash -LiteralPath $HelperSource).Hash;helper_binary_sha256=(Get-FileHash -LiteralPath $NativeExecutable).Hash;harness_sha256=$ExpectedScriptSHA256;os_version=[Environment]::OSVersion.Version.ToString();powershell=$PSVersionTable.PSVersion.ToString();contract_assembly_sha256='0DF8B9B0B77C652BB65971C3745B2B7E99AA899A0390CDDAB12142ED96EB1FC7';cases=@();completed=$false;process_uncertain=$false;publication_uncertain=$false;capture_failed=$false;passed=$false;error=$null;staging_preserved=$true}
Write-NewJson (Join-Path $root 'started.json') $record
try {
    foreach($definition in $cases) {
        Assert-CanRun
        $case=$definition | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        $directory=Assert-StagePath (Join-Path $root $case.name)
        [void][IO.Directory]::CreateDirectory($directory)
        foreach($child in @('sdk','reference')) { [void][IO.Directory]::CreateDirectory((Join-Path $directory $child)) }
        $casePath=Join-Path $directory 'case.json';Write-NewJson $casePath $case
        $options=[ordered]@{Configuration=$case.configuration;Directory=(Join-Path $directory 'sdk');Offline=$true}
        $optionsPath=Join-Path $directory 'options.json';Write-NewJson $optionsPath $options
        $entry=[ordered]@{name=$case.name;expectations=$case;sdk_process=$null;sdk=$null;sdk_file=$null;reference_process=$null;reference=$null;passed=$false;error=$null};$record.cases+=@($entry)
        Write-NewJson (Join-Path $directory 'before.json') $entry
        $entry.sdk_process=Invoke-OwnedChild $NativeExecutable ('-options "'+$optionsPath+'"') (Join-Path $directory 'sdk') $ProcessTimeoutSeconds
        Assert-CanRun
        try {
            $entry.sdk=[IO.File]::ReadAllText($entry.sdk_process.stdout_path) | ConvertFrom-Json -ErrorAction Stop
            Assert-SdkEnvelope $entry.sdk_process $entry.sdk
        } catch { $script:publicationUncertain=$true;throw }
        $entry.sdk_file=Read-OutputFile (Join-Path $options.Directory 'DCCloneConfig.xml')
        Write-NewJson (Join-Path $directory 'sdk-observed.json') $entry
        $powerShell=Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments='-NoLogo -NoProfile -NonInteractive -File "'+$PSCommandPath+'" -Mode ReferenceChild -StageDirectory "'+$StageDirectory+'" -Run "'+$Run+'" -ExpectedScriptSHA256 "'+$ExpectedScriptSHA256+'" -CasePath "'+$casePath+'"'
        $entry.reference_process=Invoke-OwnedChild $powerShell $arguments (Join-Path $directory 'reference-child') $ProcessTimeoutSeconds
        Assert-CanRun
        $entry.reference=Get-Content -LiteralPath (Join-Path $directory 'reference.json') -Raw | ConvertFrom-Json
        Write-NewJson (Join-Path $directory 'observations.json') $entry
        $entry.passed=Test-CaseOutcome $case $entry.sdk_process $entry.sdk $entry.sdk_file $entry.reference_process $entry.reference
        Write-NewJson (Join-Path $directory 'result.json') $entry
        if($case.positive_control -and -not $entry.passed) { throw 'An independent positive control failed; negative cases will not run.' }
        if($entry.reference.harness_error -or -not $entry.reference.completed) { throw 'Reference infrastructure failed; preserve all evidence.' }
    }
    $record.completed=$true
} catch { $record.error=Error-Observation $_ }
finally {
    $record.process_uncertain=[bool]$script:processUncertain;$record.publication_uncertain=[bool]$script:publicationUncertain;$record.capture_failed=[bool]$script:captureFailed
    $record.passed=($record.completed -and -not $record.process_uncertain -and -not $record.publication_uncertain -and -not $record.capture_failed -and $null -eq $record.error -and $record.cases.Count -eq $cases.Count -and @($record.cases | Where-Object {-not $_.passed}).Count -eq 0)
    Write-NewJson (Join-Path $root 'summary.json') $record
}
$record | ConvertTo-Json -Depth 24 -Compress
