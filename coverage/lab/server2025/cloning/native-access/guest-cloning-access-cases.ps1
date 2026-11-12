#Requires -Version 5.1
# Prepared qualification helper. Run only through the reviewed owned-lab host runner.
# CLI protocol v1 (cloning-access-helper.go): no arguments calls public Inspect;
# -generate-directory <owned directory> -overwrite calls public Generate.
# stdout = {protocol_version:1, operation:inspect|generate, data:<Result|Generated>,
# error_details:{present,message,permission,incomplete,native_error:{operation,code}|null,
# errno_code:number|null}}. Error details use errors.Is/As; stderr is separate evidence.
# Every native observation and generation file bytes are atomically checkpointed.
param(
    [Parameter(Mandatory)][string]$ExpectedComputer,
    [Parameter(Mandatory)][string]$NativeExecutable,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedExecutableSHA256,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9-]+$')][string]$Run,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string]$ExpectedHelperSHA256
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Assert-UnlinkedLocal([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Path escaped validation root.' }
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Validation path traverses a reparse point.' }
    }
    return $full
}
function Assert-OwnedFiles {
    $null=Assert-UnlinkedLocal $root
    if([IO.File]::ReadAllText($owner) -cne $token) { throw 'Fixture ownership changed.' }
    foreach($path in @($custom,$sentinel)) { $null=Assert-UnlinkedLocal $path }
}
function Write-NewJson([string]$Path,$Value) {
    try {
    $null=Assert-UnlinkedLocal $Path
    if(Test-Path -LiteralPath $Path) { throw 'Existing evidence is preserved.' }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 24))
    $pending=$Path+'.pending-'+[guid]::NewGuid().ToString('N')
    $stream=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    # Same-directory Move is atomic and refuses an existing destination on PS5/.NET.
    # On failure the pending file remains as evidence; previous checkpoints survive.
    [IO.File]::Move($pending,$Path)
    } catch { $script:preserveFixture=$true;$script:evidenceFailure=$true;throw }
}
function Write-Checkpoint([string]$Label) {
    $script:checkpointSequence++
    try {
        Write-NewJson (Join-Path $stage ('access-checkpoint-{0:d4}.json' -f $script:checkpointSequence)) ([ordered]@{label=$Label;timestamp=[DateTime]::UtcNow.ToString('o');record=$record})
    } catch { $script:preserveFixture=$true;$script:evidenceFailure=$true;throw }
}
function File-Observation {
    $observation=[ordered]@{exists=$false;sha256=$null;bytes_base64=$null;error=$null}
    try {
        $null=Assert-UnlinkedLocal $custom
        $observation.exists=Test-Path -LiteralPath $custom
        if($observation.exists) {
            $bytes=[IO.File]::ReadAllBytes($custom)
            $hasher=[Security.Cryptography.SHA256]::Create()
            try { $observation.sha256=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','') } finally { $hasher.Dispose() }
            $observation.bytes_base64=[Convert]::ToBase64String($bytes)
        }
    } catch { $observation.error=Error-Observation $_;$script:preserveFixture=$true;$script:evidenceFailure=$true }
    return $observation
}
function Assert-KnownPublication($Native) {
    try {
    if($Native.error -or $Native.timed_out -or $null -eq $Native.data -or $Native.data.outcome -notin @('written','not_written') -or
        $Native.file_observation.error -or $script:evidenceFailure -or $script:ownedProcessUncertain) {
        throw 'Publication or its evidence is uncertain; preserve output and do not invoke another writer.'
    }
    } catch { $script:preserveFixture=$true;throw }
}
function Assert-PositiveNativeGeneration($Native,$Entries,$Expected) {
    Assert-KnownPublication $Native
    if($Native.exit_code -ne 0 -or $Native.error_details.present -or $Native.data.outcome -cne 'written' -or -not $Native.data.result.complete -or
        -not (Same-Entries $Native.data.result.entries $Expected) -or -not (Same-Entries $Entries $Expected)) {
        $script:preserveFixture=$true
        throw 'Native positive generation failed; preserve output before the reference writer.'
    }
}
function Error-Observation($ErrorRecord) {
    $chain=@();$exception=$ErrorRecord.Exception
    while($null -ne $exception) {
        $nativeCode=if($exception -is [ComponentModel.Win32Exception]){$exception.NativeErrorCode}else{$null}
        $chain+=@([ordered]@{type=$exception.GetType().FullName;message=$exception.Message;hresult=$exception.HResult;hresult_low_word=($exception.HResult -band 65535);native_error_code=$nativeCode})
        $exception=$exception.InnerException
    }
    return [ordered]@{id=$ErrorRecord.FullyQualifiedErrorId;category=$ErrorRecord.CategoryInfo.Category.ToString();exceptions=$chain}
}
function Entry-Keys($Entries) { return @($Entries | ForEach-Object { @([string]$_.type,[string]$_.name) | ConvertTo-Json -Compress } | Sort-Object -CaseSensitive) }
function Same-Entries($Left,$Right) {
    $a=@(Entry-Keys $Left);$b=@(Entry-Keys $Right)
    return $a.Count -eq $b.Count -and (($a -join "`n") -ceq ($b -join "`n"))
}
function Is-Subset($Entries,$Expected) {
    $remaining=[Collections.Generic.List[string]]::new()
    foreach($key in @(Entry-Keys $Expected)) { $remaining.Add($key) }
    foreach($key in @(Entry-Keys $Entries)) { if(-not $remaining.Remove($key)) { return $false } }
    return $true
}
function Assert-ObservationAllowed {
    if($script:ownedProcessUncertain -or $script:evidenceFailure -or $script:preserveFixture) {
        throw 'Fixture preservation is required; no further inventory observer or writer may start.'
    }
}
function Reference-Observation([string]$Directory='') {
    Assert-ObservationAllowed
    $observation=[ordered]@{entries=@();output=@();error=$null}
    try {
        if($Directory) { $observation.output=@(Get-ADDCCloningExcludedApplicationList -GenerateXml -Path $Directory -Force -ErrorAction Stop | ForEach-Object {[string]$_}) }
        else { $observation.entries=@(Get-ADDCCloningExcludedApplicationList -ErrorAction Stop | ForEach-Object {[ordered]@{name=[string]$_.Name;type=[string]$_.Type}}) }
    } catch { $observation.error=Error-Observation $_ }
    return $observation
}
function Native-Observation([string]$Directory='') {
    Assert-ObservationAllowed
    if((Get-FileHash -LiteralPath $NativeExecutable).Hash -cne $ExpectedExecutableSHA256) { throw 'Native binary changed.' }
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$NativeExecutable;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false);$start.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
    if($Directory) {
        $null=Assert-UnlinkedLocal $Directory
        if($Directory -cne $root -or $Directory.Contains('"')) { throw 'Unexpected generation directory.' }
        $start.Arguments='-generate-directory "'+$Directory+'" -overwrite'
    }
    $result=[ordered]@{exit_code=$null;stdout=$null;stderr=$null;data=$null;error_details=$null;error=$null;timed_out=$false;file_observation=$null}
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false;$stdout=$null;$stderr=$null
    try {
        if(-not $process.Start()) { throw 'Native child did not start.' }
        $started=$true;$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        $watch=[Diagnostics.Stopwatch]::StartNew();$exited=$false
        while($watch.Elapsed.TotalSeconds -lt 60) { if($process.WaitForExit(250)) { $exited=$true;break } }
        if(-not $exited) { $result.timed_out=$true;throw 'Owned native child timed out; no retry.' }
        $result.exit_code=$process.ExitCode
        if(-not $stdout.Wait(1000) -or -not $stderr.Wait(1000)) { throw 'Native pipes did not close.' }
        $result.stdout=$stdout.Result;$result.stderr=$stderr.Result
        # Helper protocol v1 wraps the unmodified public Result/Generated in data.
        # error_details comes from errors.Is/As, never from parsing stderr wording.
        $wire=$stdout.Result | ConvertFrom-Json -ErrorAction Stop
        $expectedOperation=if($Directory){'generate'}else{'inspect'}
        if($null -eq $wire -or $wire.protocol_version -ne 1 -or $wire.operation -cne $expectedOperation -or $null -eq $wire.data -or $null -eq $wire.error_details) { throw 'Native helper protocol differs.' }
        $result.data=$wire.data;$result.error_details=$wire.error_details
    } catch { $result.error=Error-Observation $_ }
    finally {
        if($started -and -not $process.HasExited) {
            $script:ownedProcessUncertain=$true
            try { $process.Kill();if(-not $process.WaitForExit(2000)) { throw 'Owned native child remains.' };$script:ownedProcessUncertain=$false }
            catch { $result.error=Error-Observation $_ }
        }
        # Preserve raw completed pipes even after timeout or malformed protocol.
        foreach($pipe in @(@('stdout',$stdout),@('stderr',$stderr))) {
            if($null -ne $pipe[1]) {
                try { if($pipe[1].Wait(1000)) { $result[$pipe[0]]=$pipe[1].Result } else { throw 'Raw native pipe capture remained incomplete.' } } catch { $script:preserveFixture=$true;$script:evidenceFailure=$true }
            }
        }
        $process.Dispose()
        if($Directory -and -not $script:ownedProcessUncertain) { $result.file_observation=File-Observation }
        elseif($Directory) { $result.file_observation=[ordered]@{exists=$null;sha256=$null;bytes_base64=$null;error='File capture deferred: native child may still be writing.'} }
        if($result.error -or $result.timed_out -or $script:ownedProcessUncertain) { $script:preserveFixture=$true }
        $script:nativeSequence++
        try { Write-NewJson (Join-Path $stage ('access-native-{0:d4}.json' -f $script:nativeSequence)) $result }
        catch { $script:preserveFixture=$true;$script:evidenceFailure=$true;throw }
    }
    return $result
}
function Assert-PositiveInspection($Native,$Reference,$Expected) {
    if($Native.exit_code -ne 0 -or $Native.error -or $Native.error_details.present -or $Native.stderr -or -not $Native.data.complete -or -not $Native.data.authorization_limited -or
        $Reference.error -or -not (Same-Entries $Native.data.entries $Expected) -or -not (Same-Entries $Reference.entries $Expected)) { throw 'Positive inspection failed; denial must not begin.' }
}
function Generated-Entries([string]$Path) {
    $document=[Xml.XmlDocument]::new();$document.XmlResolver=$null;$document.LoadXml([IO.File]::ReadAllText($Path))
    $null=$document.Schemas.Add('uri:microsoft.com:schemas:CustomDCCloneAllowList',(Join-Path $env:windir 'System32\CustomDCCloneAllowListSchema.xsd'))
    $document.Validate($null)
    return @($document.DocumentElement.SelectNodes('Allow') | ForEach-Object { [ordered]@{name=[string]$_.SelectSingleNode('Name').InnerText;type=[string]$_.SelectSingleNode('Type').InnerText} })
}
function Assert-PositiveGeneration($Native,$Reference,$NativeEntries,$ReferenceEntries,$Expected) {
    if($Native.exit_code -ne 0 -or $Native.error -or $Native.error_details.present -or $Native.stderr -or $Native.data.outcome -cne 'written' -or -not $Native.data.result.complete -or
        $Reference.error -or -not (Same-Entries $Native.data.result.entries $Expected) -or -not (Same-Entries $NativeEntries $Expected) -or -not (Same-Entries $ReferenceEntries $Expected)) { throw 'Positive overwrite generation failed; denial must not begin.' }
}
function Test-RegistryDenial($Native,$Expected,[string]$DeniedName) {
    return $null -eq $Native.error -and $Native.exit_code -eq 1 -and -not $Native.data.complete -and $Native.data.authorization_limited -and
        $Native.error_details.present -and $Native.error_details.permission -and $Native.error_details.incomplete -and $Native.error_details.errno_code -eq 5 -and
        $null -ne $Native.error_details.native_error -and $Native.error_details.native_error.code -eq 5 -and $Native.error_details.native_error.operation -ceq 'RegOpenKeyExW(program)' -and
        (Is-Subset $Native.data.entries $Expected) -and
        (Same-Entries @($Native.data.entries | Where-Object type -cne 'Program') @($Expected | Where-Object type -cne 'Program')) -and
        @($Native.data.entries | Where-Object {$_.name -ceq $DeniedName -and $_.type -ceq 'Program'}).Count -eq 0 -and
        @($Native.data.entries | Where-Object {$_.name -ceq $DeniedName -and $_.type -ceq 'WoW64Program'}).Count -eq 1
}
function Test-ReadDenial($Native,[string]$Path) {
    return $null -eq $Native.error -and $Native.exit_code -eq 1 -and -not $Native.data.complete -and $Native.data.authorization_limited -and
        @($Native.data.entries).Count -eq 0 -and $Native.error_details.present -and $Native.error_details.permission -and $Native.error_details.errno_code -eq 5 -and
        $Native.error_details.message.Contains('read custom inclusion list:') -and $Native.error_details.message.Contains($Path)
}
function Test-WriteDenial($Native,$Expected,[string]$BeforeHash,[string]$AfterHash) {
    return $null -eq $Native.error -and $Native.exit_code -eq 1 -and $Native.data.outcome -ceq 'not_written' -and $Native.data.result.complete -and
        (Same-Entries $Native.data.result.entries $Expected) -and $Native.error_details.present -and $Native.error_details.permission -and $Native.error_details.errno_code -eq 5 -and
        $Native.error_details.message.Contains('create inclusion temporary file:') -and $BeforeHash -ceq $AfterHash
}
function Get-Descriptor($Security) {
    return [ordered]@{sddl=$Security.GetSecurityDescriptorSddlForm($sections);binary_base64=[Convert]::ToBase64String($Security.GetSecurityDescriptorBinaryForm());sections='Access, Owner, Group; SACL not read or changed'}
}
function File-Security([string]$Path) {
    $null=Assert-UnlinkedLocal $Path
    if($Path -ceq $root) { return [IO.Directory]::GetAccessControl($Path,$sections) }
    if($Path -cne $custom) { throw 'ACL target is not an owned fixture.' }
    return [IO.File]::GetAccessControl($Path,$sections)
}
function Apply-FileSecurity([string]$Path,$Security) {
    Assert-OwnedFiles
    if($Path -ceq $root) { [IO.Directory]::SetAccessControl($Path,$Security) }
    elseif($Path -ceq $custom) { [IO.File]::SetAccessControl($Path,$Security) }
    else { throw 'ACL target is not an owned fixture.' }
}
function Restore-FileSecurity([string]$Path,$Saved) {
    $security=File-Security $Path
    $security.SetSecurityDescriptorBinaryForm([Convert]::FromBase64String($Saved.binary_base64),[Security.AccessControl.AccessControlSections]::Access)
    Apply-FileSecurity $Path $security
    if((Get-Descriptor (File-Security $Path)).sddl -cne $Saved.sddl) { throw 'File descriptor was not restored exactly.' }
}
function Deny-FileRight([string]$Path,[Security.AccessControl.FileSystemRights]$Right) {
    Assert-OwnedFiles
    $security=File-Security $Path
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,([Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::ReadPermissions),[Security.AccessControl.AccessControlType]::Allow))
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,$Right,[Security.AccessControl.AccessControlType]::Deny))
    Apply-FileSecurity $Path $security
}
function Denial-Probe([scriptblock]$Action,[switch]$RegistryQueryValuesPositiveControl) {
    try { & $Action;return [ordered]@{succeeded=$true;denied=$false;classification=$null;error=$null} }
    catch {
        $errorData=Error-Observation $_;$exception=$_.Exception;$classification=$null
        while($null -ne $exception) {
            if($exception -is [UnauthorizedAccessException]) { $classification='UnauthorizedAccessException';break }
            if($exception -is [ComponentModel.Win32Exception] -and $exception.NativeErrorCode -eq 5) { $classification='Win32Exception.NativeErrorCode=5';break }
            if($RegistryQueryValuesPositiveControl -and $exception -is [Security.SecurityException]) { $classification='RegistryQueryValues.SecurityExceptionAfterPositiveControl';break }
            $exception=$exception.InnerException
        }
        return [ordered]@{succeeded=$false;denied=($null -ne $classification);classification=$classification;error=$errorData}
    }
}
function Registry-QueryValuesProbe([switch]$PositiveControlPassed) {
    # OpenSubKey may use SecurityException for invalid rights OR denied access:
    # https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registrykey.opensubkey?view=netframework-4.8.1
    # This operation fixes valid rights and must succeed before the denial ACL.
    # The separate SDK assertion still requires actual NativeError/errno code 5.
    $probe=Denial-Probe -RegistryQueryValuesPositiveControl:$PositiveControlPassed -Action {
        if($created.Count -lt 1 -or $created[0].view -ne [Microsoft.Win32.RegistryView]::Registry64 -or $created[0].name -cne "ADSDK-Access-$token-Registry64") { throw 'Registry probe ownership differs.' }
        $probeBase=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
        try {
            $probeKey=$probeBase.OpenSubKey($uninstallPrefix+$created[0].name,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,[Security.AccessControl.RegistryRights]::QueryValues)
            if($null -eq $probeKey) { throw 'Owned registry probe key is missing.' }
            try { if($probeKey.GetValue('ADSDKFixture') -cne $token -or $probeKey.GetValue('DisplayName') -cne $programName) { throw 'Owned registry probe contents changed.' } }
            finally { $probeKey.Dispose() }
        } finally { $probeBase.Dispose() }
    }
    $probe.operation='Registry64.OpenSubKey(ReadSubTree, QueryValues)'
    $probe.positive_control_passed=[bool]$PositiveControlPassed
    return $probe
}
function Assert-CaseRestored {
    Assert-ObservationAllowed
    Assert-OwnedFiles
    if((Get-FileHash -LiteralPath $custom).Hash -cne $seedHash -or (Get-FileHash -LiteralPath $sentinel).Hash -cne $sentinelHash -or
        (Get-FileHash -LiteralPath $default).Hash -cne $defaultHash -or
        (Get-Descriptor (File-Security $root)).sddl -cne $snapshots.directory.sddl -or
        (Get-Descriptor (File-Security $custom)).sddl -cne $snapshots.custom_file.sddl) { throw 'Fixture content or descriptor was not restored.' }
    $native=Native-Observation;$reference=Reference-Observation
    Assert-PositiveInspection $native $reference $expectedCustom
    return [ordered]@{native=$native;reference=$reference;hashes_and_descriptors_restored=$true}
}
function Restore-RegistrySecurity {
    $security=$keyHandle.GetAccessControl($sections)
    $security.SetSecurityDescriptorBinaryForm([Convert]::FromBase64String($keyOriginal.binary_base64),[Security.AccessControl.AccessControlSections]::Access)
    $keyHandle.SetAccessControl($security)
    if((Get-Descriptor ($keyHandle.GetAccessControl($sections))).sddl -cne $keyOriginal.sddl) { throw 'Registry descriptor was not restored exactly.' }
}
function Complete-DenialCase($Case,[scriptblock[]]$RecoveryActions) {
    $recovery=[ordered]@{attempted=$false;deferred_for_live_child=$false;acls_restored=$false;observers_skipped=$true;errors=@()}
    $Case.recovery=$recovery
    # This checkpoint contains the probes and both raw observations before any
    # ACL restoration or post-restoration native/PowerShell observer begins.
    try { Write-Checkpoint ($Case.name+'-raw-results-before-recovery') }
    catch { $recovery.errors+=@($_.Exception.Message) }
    if($script:ownedProcessUncertain) {
        $script:preserveFixture=$true;$recovery.deferred_for_live_child=$true
        throw 'ACL restoration deferred: restoring access could allow an unconfirmed live child to publish.'
    }
    $recovery.attempted=$true;$aclErrors=@()
    foreach($action in $RecoveryActions) {
        try { & $action } catch { $aclErrors+=@($_.Exception.Message) }
    }
    $recovery.acls_restored=($aclErrors.Count -eq 0);$recovery.errors+=@($aclErrors)
    if($aclErrors.Count) { $script:preserveFixture=$true;throw 'Owned ACL recovery failed; preserve the fixture.' }
    # A failed evidence write still permits the ACL recovery above, but never
    # starts fresh observers, resets output, or certifies fixture cleanup.
    Assert-ObservationAllowed
    $Case.restored=Assert-CaseRestored;$recovery.observers_skipped=$false
}

if($env:COMPUTERNAME -cne $ExpectedComputer -or $ExpectedComputer -cne 'ADSDK25DC1') { throw 'Access fixture computer differs.' }
if((Get-CimInstance Win32_ComputerSystem -Property DomainRole).DomainRole -notin @(4,5)) { throw 'Access fixture requires a domain controller.' }
if((Get-FileHash -LiteralPath $NativeExecutable).Hash -cne $ExpectedExecutableSHA256) { throw 'Reviewed access helper binary differs.' }
$NativeExecutable=Assert-UnlinkedLocal $NativeExecutable
$stage=[IO.Path]::GetDirectoryName($NativeExecutable)
if([IO.Path]::GetFileName($stage) -cne ($Run+'-access') -or [IO.File]::ReadAllText((Join-Path $stage 'owner.txt')) -cne $Run) { throw 'Staging ownership differs.' }
foreach($name in @('native-access.json','access-observations.json','access-acl-snapshots.json','fixture')) { if(Test-Path -LiteralPath (Join-Path $stage $name)) { throw 'Existing access evidence or fixture is preserved.' } }
Import-Module ActiveDirectory
$token=[guid]::NewGuid().ToString('N');$root=Join-Path $stage 'fixture';$owner=Join-Path $root 'owner.txt';$custom=Join-Path $root 'CustomDCCloneAllowList.xml';$sentinel=Join-Path $root 'unrelated.txt'
$parameters='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters';$uninstallPrefix='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
$programName='ADSDK Access '+$token
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$sections=[Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group
$script:ownedProcessUncertain=$false;$script:preserveFixture=$false;$script:evidenceFailure=$false;$script:checkpointSequence=0;$script:nativeSequence=0
$created=@();$overrideCreated=$false;$rootCreated=$false;$snapshots=$null;$keyHandle=$null;$keyOriginal=$null;$cleanupErrors=@();$checkpointWritten=$false;$denialStarted=$false;$baselineCaptured=$false
$record=[ordered]@{schema_version=1;helper_protocol_version=1;helper_source_sha256=$ExpectedHelperSHA256;sdk_source_commit='34b043bc69463fe0b4df32bceac3a1050e952a7b';run=$Run;fixture=$token;computer=$env:COMPUTERNAME;sid=$sid.Value;native_executable_sha256=$ExpectedExecutableSHA256;started=[DateTime]::UtcNow.ToString('o');positive=@();cases=@();before=@();after=@();error=$null;cleanup=[ordered]@{acl_restored=$false;registry_keys_absent=$false;override_absent=$false;baseline_restored=$false;safe_to_remove_files=$false;errors=@()};passed=$false}
try {
    $ntds=Get-Item -LiteralPath $parameters
    if('AllowListFolder' -in $ntds.GetValueNames()) { throw 'Pre-existing AllowListFolder is preserved.' }
    foreach($folder in @($ntds.GetValue('DSA Working Directory'),(Join-Path $env:windir 'NTDS'))) {
        if($folder -and (Test-Path -LiteralPath (Join-Path $folder 'CustomDCCloneAllowList.xml'))) { throw 'Pre-existing custom list is preserved.' }
    }
    foreach($drive in [IO.DriveInfo]::GetDrives()) { if($drive.DriveType -eq 'Removable' -and $drive.IsReady -and (Test-Path -LiteralPath (Join-Path $drive.RootDirectory.FullName 'CustomDCCloneAllowList.xml'))) { throw 'Pre-existing removable custom list is preserved.' } }
    $command=Get-Command Get-ADDCCloningExcludedApplicationList;$assembly=$command.ImplementingType.Assembly.Location
    $build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $record.os_full_build="$($build.CurrentBuildNumber).$($build.UBR)";$record.module_version=$command.Module.Version.ToString();$record.module_file_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($assembly).FileVersion;$record.module_file_sha256=(Get-FileHash -LiteralPath $assembly).Hash
    $default=Join-Path $env:windir 'System32\DefaultDCCloneAllowList.xml';$defaultHash=(Get-FileHash -LiteralPath $default).Hash;$record.default_sha256=$defaultHash
    $baseline=Reference-Observation;$nativeBaseline=Native-Observation
    Assert-PositiveInspection $nativeBaseline $baseline $baseline.entries
    $record.before=$baseline.entries;$baselineCaptured=$true;$record.positive+=@([ordered]@{name='original-baseline';native=$nativeBaseline;reference=$baseline})
    if(@($record.before | Where-Object {$_.name -ceq 'ClipSVC' -and $_.type -ceq 'Service'}).Count -ne 1) { throw 'Expected positive custom-list service is absent.' }
    $null=New-Item -ItemType Directory -Path $root;$rootCreated=$true
    [IO.File]::WriteAllText($owner,$token);[IO.File]::WriteAllText($sentinel,'Owned access sentinel '+$token);$sentinelHash=(Get-FileHash -LiteralPath $sentinel).Hash
    $programPositive=[ordered]@{name='both-program-views';native=$null;reference=$null};$record.positive+=@($programPositive)
    Write-Checkpoint 'before-program-fixtures'
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $name="ADSDK-Access-$token-$view";$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        try {
            $existing=$base.OpenSubKey($uninstallPrefix+$name,$false);if($existing) { $existing.Dispose();throw 'Fixture program key exists.' }
            $item=$base.CreateSubKey($uninstallPrefix+$name,$true);$created+=@([pscustomobject]@{view=$view;name=$name;marker_written=$false})
            try { $item.SetValue('ADSDKFixture',$token,[Microsoft.Win32.RegistryValueKind]::String);$created[-1].marker_written=$true;$item.SetValue('DisplayName',$programName,[Microsoft.Win32.RegistryValueKind]::String) } finally { $item.Dispose() }
        } finally { $base.Dispose() }
    }
    $expectedPrograms=@($record.before)+@([ordered]@{name=$programName;type='Program'},[ordered]@{name=$programName;type='WoW64Program'})
    $programNative=Native-Observation;$programReference=Reference-Observation;$programPositive.native=$programNative;$programPositive.reference=$programReference
    Assert-PositiveInspection $programNative $programReference $expectedPrograms
    $seed=[Text.UTF8Encoding]::new($false).GetBytes('<dc:CustomDCCloneAllowList xmlns:dc="uri:microsoft.com:schemas:CustomDCCloneAllowList"><Allow><Name>ClipSVC</Name><Type>Service</Type></Allow></dc:CustomDCCloneAllowList>')
    $record.seed_bytes_base64=[Convert]::ToBase64String($seed)
    $customPositive=[ordered]@{name='readable-custom';native=$null;reference=$null};$record.positive+=@($customPositive)
    Write-Checkpoint 'before-custom-fixture-and-override'
    [IO.File]::WriteAllBytes($custom,$seed);$seedHash=(Get-FileHash -LiteralPath $custom).Hash
    if('AllowListFolder' -in (Get-Item -LiteralPath $parameters).GetValueNames()) { throw 'AllowListFolder appeared before setup.' }
    $null=New-ItemProperty -LiteralPath $parameters -Name AllowListFolder -Value $root -PropertyType String;$overrideCreated=$true
    $expectedCustom=@($expectedPrograms | Where-Object {-not ($_.name -ceq 'ClipSVC' -and $_.type -ceq 'Service')})
    $customNative=Native-Observation;$customReference=Reference-Observation;$customPositive.native=$customNative;$customPositive.reference=$customReference
    Assert-PositiveInspection $customNative $customReference $expectedCustom
    $generationPositive=[ordered]@{name='writable-overwrite';native=$null;reference=$null;native_entries=$null;reference_entries=$null;reference_file=$null};$record.positive+=@($generationPositive)
    Write-Checkpoint 'before-positive-native-overwrite'
    $restoreSeed=$false
    try {
        $generationNative=Native-Observation $root;$generationPositive.native=$generationNative
        Assert-KnownPublication $generationNative
        Write-Checkpoint 'positive-native-output-captured'
        $nativeEntries=Generated-Entries $custom;$generationPositive.native_entries=$nativeEntries
        Assert-PositiveNativeGeneration $generationNative $nativeEntries $expectedPrograms
        Write-Checkpoint 'before-reference-overwrite'
        [IO.File]::WriteAllBytes($custom,$seed)
        $generationReference=Reference-Observation $root;$generationPositive.reference=$generationReference;$generationPositive.reference_file=File-Observation
        Write-Checkpoint 'positive-reference-output-captured'
        if($generationPositive.reference_file.error) { throw 'Reference output evidence capture failed.' }
        $referenceEntries=Generated-Entries $custom;$generationPositive.reference_entries=$referenceEntries
        Assert-PositiveGeneration $generationNative $generationReference $nativeEntries $referenceEntries $expectedPrograms
        Write-Checkpoint 'positive-generation-verified'
        $restoreSeed=$true
    } catch { $script:preserveFixture=$true;throw }
    finally { if($restoreSeed -and -not $script:preserveFixture) { [IO.File]::WriteAllBytes($custom,$seed) } }
    $record.registry_query_positive_control=Registry-QueryValuesProbe
    if(-not $record.registry_query_positive_control.succeeded -or $record.registry_query_positive_control.error) { throw 'The fixed owned QueryValues probe must succeed before permission denial.' }
    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    try { $keyHandle=$base.OpenSubKey($uninstallPrefix+$created[0].name,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,([Security.AccessControl.RegistryRights]::ReadPermissions -bor [Security.AccessControl.RegistryRights]::ChangePermissions)) } finally { $base.Dispose() }
    if($null -eq $keyHandle) { throw 'Owned registry restoration handle is missing.' }
    $keyOriginal=Get-Descriptor ($keyHandle.GetAccessControl($sections))
    $snapshots=[ordered]@{fixture=$token;sid=$sid.Value;registry64_path=$uninstallPrefix+$created[0].name;registry64=$keyOriginal;directory_path=$root;directory=(Get-Descriptor (File-Security $root));custom_file_path=$custom;custom_file=(Get-Descriptor (File-Security $custom));custom_sha256=$seedHash;sentinel_sha256=$sentinelHash;default_sha256=$defaultHash}
    Write-NewJson (Join-Path $stage 'access-acl-snapshots.json') $snapshots
    $record.acl_snapshot_sha256=(Get-FileHash -LiteralPath (Join-Path $stage 'access-acl-snapshots.json')).Hash

    $case=[ordered]@{name='registry64-queryvalues-denied';expected='NativeError code 5; incomplete valid partial inventory; other source types retained';native=$null;reference=$null;probe=$null;restored=$null;passed=$false};$record.cases+=@($case)
    Write-Checkpoint 'before-registry-denial'
    try {
        $security=$keyHandle.GetAccessControl($sections)
        $security.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($sid,([Security.AccessControl.RegistryRights]::ChangePermissions -bor [Security.AccessControl.RegistryRights]::ReadPermissions),[Security.AccessControl.AccessControlType]::Allow))
        $security.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($sid,[Security.AccessControl.RegistryRights]::QueryValues,[Security.AccessControl.AccessControlType]::Deny))
        $denialStarted=$true
        $keyHandle.SetAccessControl($security)
        $case.probe=Registry-QueryValuesProbe -PositiveControlPassed:$record.registry_query_positive_control.succeeded
        Write-Checkpoint 'registry-denial-probe-recorded'
        $case.native=Native-Observation
        Write-Checkpoint 'registry-denial-native-recorded'
        $case.reference=Reference-Observation
        $case.passed=$case.probe.denied -and (Test-RegistryDenial $case.native $expectedCustom $programName)
    } finally {
        Complete-DenialCase $case @({ Restore-RegistrySecurity })
    }
    if(-not $case.passed) { throw 'Registry denial qualification failed.' }

    $case=[ordered]@{name='custom-readdata-denied';expected='Explicit custom read error; incomplete; no invented entries';native=$null;reference=$null;probe=$null;restored=$null;passed=$false};$record.cases+=@($case)
    Write-Checkpoint 'before-custom-read-denial'
    try {
        Deny-FileRight $custom ([Security.AccessControl.FileSystemRights]::ReadData)
        $case.probe=Denial-Probe { $stream=[IO.File]::Open($custom,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$stream.Dispose() }
        Write-Checkpoint 'custom-read-denial-probe-recorded'
        $case.native=Native-Observation
        Write-Checkpoint 'custom-read-denial-native-recorded'
        $case.reference=Reference-Observation
        $case.passed=$case.probe.denied -and (Test-ReadDenial $case.native $custom)
    } finally { Complete-DenialCase $case @({ Restore-FileSecurity $custom $snapshots.custom_file }) }
    if(-not $case.passed) { throw 'Custom read denial qualification failed.' }

    $case=[ordered]@{name='generate-createfiles-and-writedata-denied';expected='Overwrite NotWritten; complete default-only inventory; existing file preserved';native=$null;reference=$null;directory_probe=$null;file_probe=$null;native_sha256=$null;reference_sha256=$null;restored=$null;passed=$false};$record.cases+=@($case)
    Write-Checkpoint 'before-generation-denial'
    try {
        Deny-FileRight $root ([Security.AccessControl.FileSystemRights]::CreateFiles)
        Deny-FileRight $custom ([Security.AccessControl.FileSystemRights]::WriteData)
        $case.directory_probe=Denial-Probe { $probePath=Join-Path $root ('unexpected-create-'+$token);$stream=[IO.File]::Open($probePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$stream.Dispose() }
        $case.file_probe=Denial-Probe { $stream=[IO.File]::Open($custom,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read);$stream.Dispose() }
        Write-Checkpoint 'generation-denial-probes-recorded'
        $case.native=Native-Observation $root
        Assert-KnownPublication $case.native
        Write-Checkpoint 'denied-native-output-captured'
        $case.native_sha256=(Get-FileHash -LiteralPath $custom).Hash
        # Both probes and native publication leave the same seed in place for PowerShell.
        if($case.native_sha256 -cne $seedHash) { throw 'Native failure changed the existing file.' }
        $case.reference=Reference-Observation $root;$case.reference_file=File-Observation
        Write-Checkpoint 'denied-reference-output-captured'
        $case.reference_sha256=(Get-FileHash -LiteralPath $custom).Hash
        $case.passed=$case.directory_probe.denied -and $case.file_probe.denied -and (Test-WriteDenial $case.native $expectedPrograms $seedHash $case.native_sha256) -and $case.reference_sha256 -ceq $seedHash
    } finally { Complete-DenialCase $case @({ Restore-FileSecurity $custom $snapshots.custom_file },{ Restore-FileSecurity $root $snapshots.directory }) }
    if(-not $case.passed) { throw 'Generation denial qualification failed.' }
} catch { $record.error=Error-Observation $_ }
finally {
    # Never restore write access while an unconfirmed child could resume writing.
    # Once the child is known stopped, recover owned ACLs even after capture failure.
    $record.cleanup.acl_recovery_deferred=$script:ownedProcessUncertain
    if($script:ownedProcessUncertain) { $script:preserveFixture=$true }
    if($keyHandle -and $keyOriginal -and -not $script:ownedProcessUncertain) {
        try { Restore-RegistrySecurity } catch { $cleanupErrors+=@($_.Exception.Message) }
    }
    if($keyHandle) {
        try { $keyHandle.Dispose() } catch { $cleanupErrors+=@($_.Exception.Message) }
    }
    if($snapshots -and -not $script:ownedProcessUncertain) {
        foreach($target in @(@($custom,$snapshots.custom_file),@($root,$snapshots.directory))) {
            try { Restore-FileSecurity $target[0] $target[1] } catch { $cleanupErrors+=@($_.Exception.Message) }
        }
        $record.cleanup.acl_restored=($cleanupErrors.Count -eq 0)
        if(-not $script:evidenceFailure -and -not $script:preserveFixture) {
            try { $record.final_fixture=Assert-CaseRestored } catch { $cleanupErrors+=@($_.Exception.Message) }
        }
    }
    elseif(-not $denialStarted) { $record.cleanup.acl_restored=$true }
    $record.cleanup.errors=$cleanupErrors
    try { Write-NewJson (Join-Path $stage 'access-observations.json') $record;$checkpointWritten=$true } catch { $cleanupErrors+=@($_.Exception.Message) }
    # No keys or override are removed unless durable observations and restoration exist.
    if($checkpointWritten -and $record.cleanup.acl_restored -and -not $script:ownedProcessUncertain -and -not $script:preserveFixture -and -not $script:evidenceFailure) {
        if($overrideCreated) {
            try { $key=Get-Item -LiteralPath $parameters;if($key.GetValueKind('AllowListFolder') -ne [Microsoft.Win32.RegistryValueKind]::String -or $key.GetValue('AllowListFolder') -cne $root) { throw 'Override ownership changed.' };Remove-ItemProperty -LiteralPath $parameters -Name AllowListFolder;$record.cleanup.override_absent=('AllowListFolder' -notin (Get-Item -LiteralPath $parameters).GetValueNames()) } catch { $cleanupErrors+=@($_.Exception.Message) }
        }
        elseif($baselineCaptured) { try { $record.cleanup.override_absent=('AllowListFolder' -notin (Get-Item -LiteralPath $parameters).GetValueNames()) } catch { $cleanupErrors+=@($_.Exception.Message) } }
        foreach($fixture in $created) {
            try {
                if($fixture.name -cne "ADSDK-Access-$token-$($fixture.view)") { throw 'Registry cleanup identity differs.' }
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$fixture.view)
                try {
                    $item=$base.OpenSubKey($uninstallPrefix+$fixture.name,$false)
                    if(-not $item) { throw 'Owned program key unexpectedly absent.' }
                    try { if(-not $fixture.marker_written -or $item.GetValue('ADSDKFixture') -cne $token -or $item.GetValue('DisplayName') -cne $programName -or $item.SubKeyCount -ne 0 -or $item.ValueCount -ne 2) { throw 'Owned program contents changed.' } } finally { $item.Dispose() }
                    $base.DeleteSubKey($uninstallPrefix+$fixture.name,$true)
                    $remaining=$base.OpenSubKey($uninstallPrefix+$fixture.name,$false);if($remaining) { $remaining.Dispose();throw 'Program key remains.' }
                } finally { $base.Dispose() }
            } catch { $cleanupErrors+=@($_.Exception.Message) }
        }
        $record.cleanup.registry_keys_absent=($cleanupErrors.Count -eq 0)
        try {
            if(-not $baselineCaptured) { throw 'Original baseline was not captured.' }
            $afterNative=Native-Observation;$afterReference=Reference-Observation
            Assert-PositiveInspection $afterNative $afterReference $record.before
            $record.after=[ordered]@{native=$afterNative;reference=$afterReference};$record.cleanup.baseline_restored=$true
        } catch { $cleanupErrors+=@($_.Exception.Message) }
    }
    if($script:ownedProcessUncertain) { $cleanupErrors+=@('Owned native process state is uncertain; fixture files preserved.') }
    if($script:preserveFixture -or $script:evidenceFailure) { $cleanupErrors+=@('Publication or evidence requires preservation; no fixture deletion is permitted.') }
    $record.cleanup.errors=$cleanupErrors
    $record.cleanup.safe_to_remove_files=($null -ne $snapshots -and $record.cleanup.acl_restored -and $record.cleanup.override_absent -and $record.cleanup.registry_keys_absent -and $record.cleanup.baseline_restored -and $cleanupErrors.Count -eq 0)
    $record.passed=($null -eq $record.error -and $record.cleanup.safe_to_remove_files -and $record.positive.Count -eq 4 -and $record.cases.Count -eq 3 -and @($record.cases | Where-Object {-not $_.passed}).Count -eq 0)
    $record.finished=[DateTime]::UtcNow.ToString('o')
    # Final observers may have changed process ownership after ACL recovery.
    $record.process_uncertain=[bool]$script:ownedProcessUncertain
    if($record.process_uncertain) { $record.passed=$false;$record.cleanup.safe_to_remove_files=$false }
    Write-NewJson (Join-Path $stage 'native-access.json') $record
}
$record | ConvertTo-Json -Depth 24 -Compress
