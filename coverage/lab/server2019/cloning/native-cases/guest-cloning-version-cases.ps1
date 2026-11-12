#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$ExpectedComputer,
    [Parameter(Mandatory)][string]$NativeExecutable,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedExecutableSHA256,
    [Parameter(Mandatory)][ValidateSet('2016','2019','2022')][string]$ServerVersion,
    [Parameter(Mandatory)][string]$ReportPath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]+$')][string]$ExpectedRun
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Assert-VersionController([string]$Computer,[string]$Caption,[int]$DomainRole) {
    if($Computer -cne $ExpectedComputer -or $ExpectedComputer -cne ('ADSDK'+$ServerVersion.Substring(2)+'DC1')) { throw 'Unexpected version fixture computer.' }
    if($Caption -notmatch ('Windows Server '+[regex]::Escape($ServerVersion)+'(?:\s|$)')) { throw 'Unexpected Windows Server version.' }
    if($DomainRole -notin @(4,5)) { throw 'Fixture requires a domain controller.' }
}
Assert-VersionController $env:COMPUTERNAME (Get-CimInstance Win32_OperatingSystem -Property Caption).Caption (Get-CimInstance Win32_ComputerSystem -Property DomainRole).DomainRole
if ((Get-FileHash -LiteralPath $NativeExecutable).Hash -cne $ExpectedExecutableSHA256) { throw 'Native fixture binary differs.' }
Import-Module ActiveDirectory
$token=[guid]::NewGuid().ToString('N')
$validationRoot='C:\ad-sdk-validation'
$root=Join-Path $validationRoot "cloning-$token"
$alternate=Join-Path $root 'alternate'
$custom=Join-Path $root 'CustomDCCloneAllowList.xml'
$owner=Join-Path $root 'owner.txt'
$sentinel=Join-Path $root 'unrelated.txt'
$parameters='HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$uninstallPrefix='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
$programName="ADSDK Clone $token & <"+[char]0x00c5+" Program>"
$script:cloningOwnedProcessUncertain=$false
$script:cloningCaptureFailed=$false
$script:cloningWriteUncertain=$false
$script:checkpointFailed=$false
$script:reportHash=$null
$created=@();$errors=@();$failure=$null;$overrideCreated=$false;$rootCreated=$false
$record=[ordered]@{schema_version=2;server_version=$ServerVersion;stage='initialized';registry_fixture=@();native_executable_sha256=$ExpectedExecutableSHA256;fixture=$token;computer=$env:COMPUTERNAME;started=[DateTime]::UtcNow.ToString('o');before=@();with_programs=@();cases=@();generation=@();after=@();cleanup=[ordered]@{allow_list_override_absent=$false;directory_absent=$false;baseline_restored=$false};sentinel_unchanged=$false;default_unchanged=$false;error=$null;passed=$false}
function Assert-LocalPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($validationRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture path escaped validation root.'}
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Fixture path traverses a reparse point.'}
    }
    return $full
}
function Assert-ReportOwner {
    $null=Assert-LocalPath $ReportPath
    $stageDirectory=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($NativeExecutable))
    if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ReportPath)) -cne $stageDirectory -or
        [IO.Path]::GetFileName($ReportPath) -cne 'reference.json' -or
        [IO.Path]::GetFileName($stageDirectory) -cne $ExpectedRun -or
        [IO.File]::ReadAllText((Join-Path $stageDirectory 'owner.txt')) -cne $ExpectedRun) { throw 'Report or staging ownership differs.' }
}
function Write-ReportTemporary([string]$Path,[byte[]]$Bytes) {
    $null=Assert-LocalPath $Path
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
}
function Save-GuestReport([switch]$Initial) {
    if($script:checkpointFailed) { throw 'A checkpoint publication failed; preserve the last valid report and owned temporary file.' }
    try {
        Assert-ReportOwner
        if($Initial) {
            if(Test-Path -LiteralPath $ReportPath) { throw 'Existing guest report is preserved.' }
        } elseif(-not $script:reportHash -or (Get-FileHash -LiteralPath $ReportPath).Hash -cne $script:reportHash) {
            throw 'Guest report ownership/content changed.'
        }
        $record.write_uncertain=$script:cloningWriteUncertain
        $record.process_uncertain=$script:cloningOwnedProcessUncertain
        $record.capture_failed=$script:cloningCaptureFailed
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 20 -Compress))
        $temporary=Join-Path ([IO.Path]::GetDirectoryName($ReportPath)) ('.reference-'+[guid]::NewGuid().ToString('N')+'.tmp')
        # Failure leaves the old report untouched and retains only this owned
        # temporary file. Never truncate the previously durable checkpoint.
        Write-ReportTemporary $temporary $bytes
        Assert-ReportOwner
        if($Initial) {
            if(Test-Path -LiteralPath $ReportPath) { throw 'Guest report appeared before publication.' }
            [IO.File]::Move($temporary,$ReportPath)
        } else {
            if((Get-FileHash -LiteralPath $ReportPath).Hash -cne $script:reportHash) { throw 'Guest report changed before replacement.' }
            [IO.File]::Replace($temporary,$ReportPath,[NullString]::Value)
        }
        $script:reportHash=(Get-FileHash -LiteralPath $ReportPath).Hash
    } catch {
        $script:cloningCaptureFailed=$true
        $script:checkpointFailed=$true
        throw
    }
}
function Open-GuestReport {
    Assert-ReportOwner
    if(Test-Path -LiteralPath $ReportPath) { throw 'Existing guest report is preserved.' }
    Save-GuestReport -Initial
}
function Test-FixtureCleanupAllowed {
    return -not ($script:cloningOwnedProcessUncertain -or $script:cloningWriteUncertain -or $script:cloningCaptureFailed)
}
function Assert-FixtureCanMutate {
    if(-not (Test-FixtureCleanupAllowed)) { throw 'Uncertain write/process or failed capture: preserve fixtures without further mutation.' }
}
function Select-ServiceCaseNames($Entries) {
    $services=@($Entries | Where-Object { $_.type -ceq 'Service' -and $_.name -match '[A-Za-z]' -and -not $_.name.Contains('*') })
    $preferred=@($services | Where-Object { $_.name -ceq 'ClipSVC' })
    if($preferred.Count -eq 1) { $name=[string]$preferred[0].name }
    elseif($services.Count) { $name=[string](@($services | Sort-Object name -CaseSensitive)[0].name) }
    else { throw 'No suitable observed excluded service is available; no fixture was created.' }
    $mixed=-join @($name.ToCharArray() | ForEach-Object {
        if([char]::IsUpper($_)) { [char]::ToLowerInvariant($_) } else { [char]::ToUpperInvariant($_) }
    })
    if($mixed -ceq $name) { throw 'Service does not support a distinct case fixture.' }
    return [pscustomobject]@{name=$name;mixed_case=$mixed;wildcard=($name.Substring(0,[Math]::Max(1,[int]($name.Length/2)))+'*')}
}
function Read-Exclusions {return @(Get-ADDCCloningExcludedApplicationList -ErrorAction Stop | ForEach-Object {[ordered]@{name=[string]$_.Name;type=[string]$_.Type}})}
function Error-Observation($ErrorRecord) {
    $exception=$ErrorRecord.Exception
    return [ordered]@{type=$exception.GetType().FullName;message=$exception.Message;id=$ErrorRecord.FullyQualifiedErrorId;category=$ErrorRecord.CategoryInfo.Category.ToString();hresult=$exception.HResult;error_code=$(if($exception.PSObject.Properties['ErrorCode']){$exception.ErrorCode}else{$null});native_error_code=$(if($exception.PSObject.Properties['NativeErrorCode']){$exception.NativeErrorCode}else{$null})}
}
function Wrap-Custom([string]$Entries) {return '<dc:CustomDCCloneAllowList xmlns:dc="uri:microsoft.com:schemas:CustomDCCloneAllowList">'+$Entries+'</dc:CustomDCCloneAllowList>'}
function Allow-Entry([string]$Name,[string]$Type) {return '<Allow><Name>'+[Security.SecurityElement]::Escape($Name)+'</Name><Type>'+[Security.SecurityElement]::Escape($Type)+'</Type></Allow>'}
function Entry-Keys($Entries) {
    return @($Entries | ForEach-Object { @([string]$_.type,[string]$_.name) | ConvertTo-Json -Compress } | Sort-Object -CaseSensitive)
}
function Same-Entries($Left,$Right) {
    $leftKeys=@(Entry-Keys $Left);$rightKeys=@(Entry-Keys $Right)
    return $leftKeys.Count -eq $rightKeys.Count -and (($leftKeys -join "`n") -ceq ($rightKeys -join "`n"))
}
function Native-Observation([string]$Directory='', [bool]$Overwrite=$false, [Collections.IDictionary]$Capture=$null) {
    if($null -eq $Capture) { $Capture=[ordered]@{} }
    $Capture.started=$false;$Capture.process_stopped=$false;$Capture.timed_out=$false
    $Capture.exit_code=$null;$Capture.error=$null;$Capture.raw_stdout=$null;$Capture.data=$null;$Capture.exception=$null;$Capture.elapsed_ms=$null
    if ((Get-FileHash -LiteralPath $NativeExecutable).Hash -cne $ExpectedExecutableSHA256) { throw 'Native fixture binary changed.' }
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$NativeExecutable;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding=[Text.UTF8Encoding]::new($false)
    if ($Directory) {
        $null=Assert-LocalPath $Directory
        if ($Directory.Contains('"')) { throw 'Invalid fixture argument.' }
        $start.Arguments='-generate-directory "'+$Directory+'"'
        if ($Overwrite) { $start.Arguments+=' -overwrite' }
    }
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false;$stdout=$null;$stderr=$null
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $process.Start()) { throw 'Native fixture process did not start.' }
        $started=$true;$Capture.started=$true
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        $exited=$false
        while ($watch.Elapsed.TotalSeconds -lt 60) {
            if ($process.WaitForExit(250)) { $exited=$true;break }
        }
        if (-not $exited) { $Capture.timed_out=$true;throw 'Owned native fixture process timed out; no retry will be attempted.' }
        if (-not $stdout.Wait(1000) -or -not $stderr.Wait(1000)) { throw 'Native fixture pipes did not close.' }
        $Capture.raw_stdout=$stdout.Result;$Capture.error=$stderr.Result;$Capture.exit_code=$process.ExitCode
        $Capture.data=$Capture.raw_stdout | ConvertFrom-Json -ErrorAction Stop
        if (-not $Capture.data) { throw 'Native fixture returned no structured outcome.' }
        return $Capture
    } catch {
        $Capture.exception=Error-Observation $_
        throw
    } finally {
        try {
            if ($started -and -not $process.HasExited) {
                $script:cloningOwnedProcessUncertain=$true
                $process.Kill()
                if (-not $process.WaitForExit(2000)) { throw 'Owned native child remains after termination; preserve fixture for investigation.' }
                $script:cloningOwnedProcessUncertain=$false
                # A stopped child does not establish its generation outcome.
                # Run-Generation's separate write-uncertainty latch stays set.
            }
            if($started -and $process.HasExited) { $Capture.process_stopped=$true;$Capture.exit_code=$process.ExitCode }
            if($stdout -and $stdout.Status -eq 'RanToCompletion') { $Capture.raw_stdout=$stdout.Result }
            if($stderr -and $stderr.Status -eq 'RanToCompletion') { $Capture.error=$stderr.Result }
            $Capture.elapsed_ms=$watch.ElapsedMilliseconds
        } finally { $process.Dispose() }
    }
}
function Generated-Entries([string]$Xml) {
    $document=[Xml.XmlDocument]::new();$document.XmlResolver=$null
    $document.LoadXml($Xml)
    $schema=Join-Path $env:windir 'System32\CustomDCCloneAllowListSchema.xsd'
    $null=$document.Schemas.Add('uri:microsoft.com:schemas:CustomDCCloneAllowList',$schema)
    $document.Validate($null)
    return @($document.DocumentElement.SelectNodes('Allow') | ForEach-Object { [ordered]@{name=[string]$_.SelectSingleNode('Name').InnerText;type=[string]$_.SelectSingleNode('Type').InnerText} })
}
function Run-Case([string]$Name,[string]$Xml,[switch]$UTF16) {
    Assert-FixtureCanMutate
    $null=Assert-LocalPath $custom
    $encoding=if($UTF16){[Text.UnicodeEncoding]::new($false,$true)}else{[Text.UTF8Encoding]::new($false)}
    $requestedBytes=@($encoding.GetPreamble())+@($encoding.GetBytes($Xml))
    $case=[ordered]@{
        name=$Name;xml=$Xml;encoding=$(if($UTF16){'UTF-16LE-BOM'}else{'UTF-8-no-BOM'})
        requested_bytes_base64=[Convert]::ToBase64String([byte[]]$requestedBytes)
        phase='requested';source_sha256=$null;source_bytes_base64=$null;source_after=$null;source_unchanged=$false
        entries=@();error=$null;native=[ordered]@{};native_requested=$false;native_error=$null
        capture_errors=@();flow_error=$null;passed=$false
        documented_validation_difference=($Name -in @('wrong-root','wrong-namespace'))
        expected_reference_error=($Name -in @('unknown-type','empty-name','empty-root','missing-name','missing-type','duplicate-name-child','extra-version-child','truncated-xml','internal-entity','trailing-document'))
    }
    $record.cases+=@($case)
    try {
        # The requested XML and exact intended encoding are durable before the
        # fixture file changes or either read-only observer is called.
        $record.stage='custom-case-requested';Save-GuestReport
        [IO.File]::WriteAllText($custom,$Xml,$encoding)
        $source=Get-GenerationSnapshot $custom
        $case.source_sha256=$source.sha256;$case.source_bytes_base64=$source.bytes_base64
        $case.phase='input-written';Save-GuestReport
        try { $case.entries=@(Read-Exclusions) } catch { $case.error=Error-Observation $_ }
        $case.phase='reference-finished';Save-GuestReport
        $case.native_requested=$true;$case.phase='native-requested';Save-GuestReport
        try {
            # Inspect does not write: preserve its partial capture without
            # turning a failed read into a native write-uncertainty claim.
            $null=Native-Observation '' $false $case.native
        } catch {
            $case.native_error=Error-Observation $_
            throw
        }
        $referenceOutcomeMatches=($case.expected_reference_error -eq ($null -ne $case.error))
        if($case.expected_reference_error -or $case.documented_validation_difference) {
            $case.passed=($referenceOutcomeMatches -and $case.native.exit_code -eq 1 -and -not $case.native.data.complete -and $case.native.error.Contains('invalid DC cloning inclusion list'))
        } else {
            $case.passed=($referenceOutcomeMatches -and $case.native.exit_code -eq 0 -and $case.native.data.complete -and
                $case.native.data.authorization_limited -and (Same-Entries $case.entries $case.native.data.entries))
        }
        $case.phase='complete'
    } catch {
        $case.flow_error=Error-Observation $_
        throw
    } finally {
        try {
            $case.source_after=Get-GenerationSnapshot $custom
            $case.source_unchanged=($null -ne $case.source_sha256 -and $case.source_after.sha256 -ceq $case.source_sha256)
        } catch { $case.capture_errors+=@(Error-Observation $_) }
        $case.passed=$case.passed -and $case.source_unchanged
        $record.stage='custom-case-checkpoint';Save-GuestReport
    }
}
function Get-GenerationSnapshot([string]$Path) {
    try {
        $null=Assert-LocalPath $Path
        $snapshot=[ordered]@{exists=$false;sha256=$null;bytes_base64=$null;xml=$null;text_error=$null}
        if(Test-Path -LiteralPath $Path) {
            if((Get-Item -LiteralPath $Path).PSIsContainer) { throw 'Generation output is a directory.' }
            $bytes=[IO.File]::ReadAllBytes($Path)
            $sha=[Security.Cryptography.SHA256]::Create()
            try { $snapshot.sha256=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','') } finally { $sha.Dispose() }
            $snapshot.exists=$true;$snapshot.bytes_base64=[Convert]::ToBase64String($bytes)
            try { $snapshot.xml=[Text.UTF8Encoding]::new($false,$true).GetString($bytes) } catch { $snapshot.text_error=Error-Observation $_ }
        }
        return $snapshot
    } catch { $script:cloningCaptureFailed=$true;throw }
}
function Reset-GenerationSeed([string]$Path,$Before) {
    Assert-FixtureCanMutate
    $null=Assert-LocalPath $Path
    if($Before.exists) { [IO.File]::WriteAllBytes($Path,[Convert]::FromBase64String($Before.bytes_base64)) }
    elseif(Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
}
function Run-Generation([string]$Name,[string]$Directory,[switch]$Force) {
    Assert-FixtureCanMutate
    $null=Assert-LocalPath $Directory
    $path=Join-Path $Directory 'CustomDCCloneAllowList.xml'
    $case=[ordered]@{
        name=$Name;directory=$Directory;force=[bool]$Force;phase='requested';passed=$false
        before=$null;before_sha256=$null;native=[ordered]@{};native_requested=$false;native_error=$null
        native_after=$null;native_after_sha256=$null;native_xml=$null;native_bytes_base64=$null
        reference_requested=$false;reference_called=$false;error=$null;output=@()
        reference_after=$null;after_sha256=$null;xml=$null;bytes_base64=$null
        write_uncertain=$false;capture_errors=@();flow_error=$null
    }
    # Register before either writer runs. Every later failure updates this same
    # object, so the report never silently loses an in-flight generation case.
    $record.generation+=@($case)
    try {
        $case.before=Get-GenerationSnapshot $path
        $case.before_sha256=$case.before.sha256
        $record.stage='generation-requested';Save-GuestReport
        $case.native_requested=$true;$case.phase='native-requested'
        $script:cloningWriteUncertain=$true;$case.write_uncertain=$true
        Save-GuestReport
        try {
            $null=Native-Observation $Directory ([bool]$Force) $case.native
            if($null -eq $case.native.data -or -not $case.native.data.PSObject.Properties['outcome'] -or
                $case.native.data.outcome -notin @('written','not_written')) {
                throw 'Native generation write outcome is uncertain or missing; preserve output and stop.'
            }
            $script:cloningWriteUncertain=$false
        } catch {
            $case.native_error=Error-Observation $_
            throw
        } finally {
            try {
                $case.native_after=Get-GenerationSnapshot $path
                $case.native_after_sha256=$case.native_after.sha256
                $case.native_xml=$case.native_after.xml
                $case.native_bytes_base64=$case.native_after.bytes_base64
            } catch { $case.capture_errors+=@(Error-Observation $_) }
            $case.write_uncertain=$script:cloningWriteUncertain
            $case.phase='native-finished';$record.stage='generation-native-finished';Save-GuestReport
        }
        # Only a known SDK outcome plus durable native bytes permits the seed
        # reset and the independent reference writer.
        Assert-FixtureCanMutate
        $case.reference_requested=$true;$case.phase='reference-requested';Save-GuestReport
        try {
            Reset-GenerationSeed $path $case.before
            $case.reference_called=$true
            try {
                $case.output=@(Get-ADDCCloningExcludedApplicationList -GenerateXml -Path $Directory -Force:$Force -ErrorAction Stop | ForEach-Object {[string]$_})
            } catch { $case.error=Error-Observation $_ }
        } finally {
            try {
                $case.reference_after=Get-GenerationSnapshot $path
                $case.after_sha256=$case.reference_after.sha256
                $case.xml=$case.reference_after.xml
                $case.bytes_base64=$case.reference_after.bytes_base64
            } catch { $case.capture_errors+=@(Error-Observation $_) }
            $case.phase='reference-finished';$record.stage='generation-reference-finished';Save-GuestReport
        }
        Assert-FixtureCanMutate
        $case.raw_bytes_equal=($case.native_bytes_base64 -ceq $case.bytes_base64)
        $case.expected_success=($Name -in @('same-rank-new-without-force','same-rank-existing-with-force'))
        if(-not $case.expected_success) {
            $case.passed=($case.reference_called -and $null -ne $case.error -and $case.native.exit_code -eq 1 -and
                $case.native.data.outcome -eq 'not_written' -and $case.native_after_sha256 -eq $case.before_sha256 -and $case.after_sha256 -eq $case.before_sha256)
        } elseif($null -eq $case.error -and $case.native.exit_code -eq 0) {
            $nativeEntries=@(Generated-Entries $case.native_xml)
            $referenceEntries=@(Generated-Entries $case.xml)
            $case.semantic_xml_equal=Same-Entries $nativeEntries $referenceEntries
            $case.passed=($case.native.data.outcome -eq 'written' -and $case.native.data.result.complete -and
                $case.semantic_xml_equal -and $case.raw_bytes_equal -and
                (Same-Entries $nativeEntries $record.with_programs) -and (Same-Entries $case.native.data.result.entries $record.with_programs))
        }
        $case.phase='complete'
    } catch {
        $case.flow_error=Error-Observation $_
        throw
    } finally {
        $case.write_uncertain=$script:cloningWriteUncertain
        $record.stage='generation-case-checkpoint'
        Save-GuestReport
    }
}
Open-GuestReport
try {
    $null=Assert-LocalPath $root
    if(Test-Path -LiteralPath $root){throw 'Fixture root already exists.'}
    $ntds=Get-Item -LiteralPath $parameters
    if('AllowListFolder' -in $ntds.GetValueNames()){throw 'Pre-existing AllowListFolder is preserved; fixture refuses to replace it.'}
    foreach($folder in @($ntds.GetValue('DSA Working Directory'),(Join-Path $env:windir 'NTDS'))) {
        if($folder -and (Test-Path -LiteralPath (Join-Path $folder 'CustomDCCloneAllowList.xml'))){throw 'Pre-existing custom allow list is preserved.'}
    }
    foreach($drive in [IO.DriveInfo]::GetDrives()) {if($drive.DriveType -eq 'Removable' -and $drive.IsReady -and (Test-Path -LiteralPath (Join-Path $drive.RootDirectory.FullName 'CustomDCCloneAllowList.xml'))){throw 'Pre-existing removable custom allow list is preserved.'}}
    $command=Get-Command Get-ADDCCloningExcludedApplicationList;$assembly=$command.ImplementingType.Assembly.Location
    $build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $record.os_full_build="$($build.CurrentBuildNumber).$($build.UBR)";$record.module_version=$command.Module.Version.ToString();$record.module_file_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($assembly).FileVersion;$record.module_file_sha256=(Get-FileHash -LiteralPath $assembly).Hash
    $default=Join-Path $env:windir 'System32\DefaultDCCloneAllowList.xml';$record.default_sha256=(Get-FileHash -LiteralPath $default).Hash
    $record.before=Read-Exclusions
    $serviceNames=Select-ServiceCaseNames $record.before
    $selectedService=$serviceNames.name;$mixedService=$serviceNames.mixed_case;$wildcardService=$serviceNames.wildcard
    $escapedService=[Security.SecurityElement]::Escape($selectedService)
    $record.selected_service=$serviceNames
    $record.default_bytes_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($default))
    $schema=Join-Path $env:windir 'System32\\CustomDCCloneAllowListSchema.xsd'
    $record.schema_sha256=(Get-FileHash -LiteralPath $schema).Hash
    $record.schema_bytes_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($schema))
    $record.fixture_root=$root;$record.stage='pre-mutation';Save-GuestReport
    $null=New-Item -ItemType Directory -Path $root;$rootCreated=$true
    $null=New-Item -ItemType Directory -Path $alternate
    [IO.File]::WriteAllText($owner,$token);[IO.File]::WriteAllText($sentinel,'Unrelated fixture sentinel '+$token)
    $sentinelHash=(Get-FileHash -LiteralPath $sentinel).Hash
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $name="ADSDK-Cloning-$token-$view";$base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        try {
            $existing=$base.OpenSubKey($uninstallPrefix+$name,$false);if($existing){$existing.Dispose();throw 'Fixture program key exists.'}
            $item=$base.CreateSubKey($uninstallPrefix+$name,$true)
            $created+=@([pscustomobject]@{view=$view;name=$name;marker_written=$false})
            try {$item.SetValue('ADSDKFixture',$token,[Microsoft.Win32.RegistryValueKind]::String);$created[-1].marker_written=$true;$item.SetValue('DisplayName',$programName,[Microsoft.Win32.RegistryValueKind]::String);$item.SetValue('DisplayVersion','7.3.1',[Microsoft.Win32.RegistryValueKind]::String)} finally {$item.Dispose()}
        } finally {$base.Dispose()}
    }
    $record.registry_fixture=@($created | ForEach-Object { [ordered]@{
        view=$_.view.ToString();key=('HKEY_LOCAL_MACHINE\\'+$uninstallPrefix+$_.name);marker_written=$_.marker_written
        values=@([ordered]@{name='ADSDKFixture';kind='String';value=$token},
                 [ordered]@{name='DisplayName';kind='String';value=$programName},
                 [ordered]@{name='DisplayVersion';kind='String';value='7.3.1'})
    } })
    $record.program_name=$programName;$record.with_programs=Read-Exclusions
    $record.stage='program-fixtures-created';Save-GuestReport
    if($record.with_programs.Count -ne $record.before.Count+2 -or
        @($record.with_programs | Where-Object {$_.name -ceq $programName -and $_.type -ceq 'Program'}).Count -ne 1 -or
        @($record.with_programs | Where-Object {$_.name -ceq $programName -and $_.type -ceq 'WoW64Program'}).Count -ne 1 -or
        -not (Same-Entries $record.before @($record.with_programs | Where-Object {$_.name -cne $programName}))) { throw 'Both program views must produce one additional typed exclusion with the original baseline preserved.' }
    $null=New-ItemProperty -LiteralPath $parameters -Name AllowListFolder -Value $root -PropertyType String;$overrideCreated=$true
    Run-Case 'exact-service' (Wrap-Custom (Allow-Entry $selectedService 'Service'))
    Run-Case 'case-service-name' (Wrap-Custom (Allow-Entry $mixedService 'Service'))
    Run-Case 'case-service-type' (Wrap-Custom (Allow-Entry $selectedService 'service'))
    Run-Case 'wildcard-service-name' (Wrap-Custom (Allow-Entry $wildcardService 'Service'))
    Run-Case 'whitespace-service-name' (Wrap-Custom (Allow-Entry (' '+$selectedService+' ') 'Service'))
    Run-Case 'duplicate-allow' (Wrap-Custom ((Allow-Entry $selectedService 'Service')+(Allow-Entry $selectedService 'Service')))
    Run-Case 'unknown-type' (Wrap-Custom (Allow-Entry $selectedService 'Unknown'))
    Run-Case 'empty-name' (Wrap-Custom (Allow-Entry '' 'Service'))
    Run-Case 'empty-root' (Wrap-Custom '')
    Run-Case 'wrong-root' '<Unknown />'
    Run-Case 'wrong-namespace' ('<dc:CustomDCCloneAllowList xmlns:dc="urn:wrong">'+(Allow-Entry $selectedService 'Service')+'</dc:CustomDCCloneAllowList>')
    Run-Case 'missing-name' (Wrap-Custom '<Allow><Type>Service</Type></Allow>')
    Run-Case 'missing-type' (Wrap-Custom ('<Allow><Name>'+$escapedService+'</Name></Allow>'))
    Run-Case 'duplicate-name-child' (Wrap-Custom ('<Allow><Name>'+$escapedService+'</Name><Name>'+$escapedService+'</Name><Type>Service</Type></Allow>'))
    Run-Case 'extra-version-child' (Wrap-Custom ('<Allow><Name>'+$escapedService+'</Name><Type>Service</Type><Version>7.3.1</Version></Allow>'))
    Run-Case 'truncated-xml' '<dc:CustomDCCloneAllowList xmlns:dc="uri:microsoft.com:schemas:CustomDCCloneAllowList"><Allow>'
    Run-Case 'utf16-bom' (Wrap-Custom (Allow-Entry $selectedService 'Service')) -UTF16
    Run-Case 'internal-entity' (('<!DOCTYPE dc:CustomDCCloneAllowList [<!ENTITY fixture "'+$escapedService+'">]>')+ (Wrap-Custom '<Allow><Name>&fixture;</Name><Type>Service</Type></Allow>'))
    Run-Case 'trailing-document' ((Wrap-Custom (Allow-Entry $selectedService 'Service'))+'<Extra/>')
    Run-Case 'exact-program64' (Wrap-Custom (Allow-Entry $programName 'Program'))
    Run-Case 'exact-program32' (Wrap-Custom (Allow-Entry $programName 'WoW64Program'))
    Run-Case 'case-program-name' (Wrap-Custom (Allow-Entry $programName.ToLowerInvariant() 'Program'))
    Run-Case 'case-program-type' (Wrap-Custom (Allow-Entry $programName 'program'))
    Run-Case 'program-both-views' (Wrap-Custom ((Allow-Entry $programName 'Program')+(Allow-Entry $programName 'WoW64Program')))
    Run-Case 'generation-seed' (Wrap-Custom (Allow-Entry $selectedService 'Service'))
    # A fresh output is generated first, then reset to the controlled custom seed.
    Remove-Item -LiteralPath $custom -Force
    Run-Generation 'same-rank-new-without-force' $root
    [IO.File]::WriteAllText($custom,(Wrap-Custom (Allow-Entry $selectedService 'Service')),[Text.UTF8Encoding]::new($false))
    Run-Generation 'same-rank-existing-without-force' $root
    Run-Generation 'same-rank-existing-with-force' $root -Force
    Run-Generation 'existing-generated-without-force' $root
    Run-Generation 'unconfigured-alternate-with-force' $alternate -Force
    $record.sentinel_unchanged=((Get-FileHash -LiteralPath $sentinel).Hash -eq $sentinelHash)
    $record.default_unchanged=((Get-FileHash -LiteralPath $default).Hash -eq $record.default_sha256)
} catch {$failure=$_;$record.error=Error-Observation $_}
finally {
    # Persist diagnostic/source bytes before deleting any owned fixture. If
    # persistence fails, preserve all resources for an explicit recovery.
    try {
        $record.stage='before-cleanup'
        $record.created_keys=@($created | ForEach-Object {[ordered]@{view=$_.view.ToString();name=$_.name;marker_written=$_.marker_written}})
        Save-GuestReport
    } catch { $script:cloningCaptureFailed=$true;$errors+=@('Guest report persistence failed; fixture resources preserved: '+$_.Exception.Message) }
    if(Test-FixtureCleanupAllowed) {
    if($overrideCreated) {
        try {$key=Get-Item -LiteralPath $parameters;if($key.GetValueKind('AllowListFolder') -ne [Microsoft.Win32.RegistryValueKind]::String -or $key.GetValue('AllowListFolder') -cne $root){throw 'AllowListFolder ownership changed.'};Remove-ItemProperty -LiteralPath $parameters -Name AllowListFolder;if('AllowListFolder' -in (Get-Item -LiteralPath $parameters).GetValueNames()){throw 'AllowListFolder remains.'};$record.cleanup.allow_list_override_absent=$true} catch {$errors+=@($_.Exception.Message)}
    }
    foreach($fixture in $created) {
        try {
            if($fixture.name -cne "ADSDK-Cloning-$token-$($fixture.view)"){throw 'Program cleanup identity mismatch.'}
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$fixture.view)
            try {
                $item=$base.OpenSubKey($uninstallPrefix+$fixture.name,$false)
                if(-not $item){throw 'Fixture program unexpectedly absent.'}
                try {
                    if($fixture.marker_written) {
                        if($item.GetValue('ADSDKFixture') -cne $token -or $item.SubKeyCount -ne 0 -or @($item.GetValueNames() | Where-Object {$_ -notin @('ADSDKFixture','DisplayName','DisplayVersion')}).Count){throw 'Program cleanup ownership changed.'}
                    } elseif($item.SubKeyCount -ne 0 -or $item.ValueCount -ne 0) {
                        throw 'New program key has no confirmed marker and is nonempty; preserve for investigation.'
                    }
                } finally {$item.Dispose()}
                $base.DeleteSubKey($uninstallPrefix+$fixture.name,$true)
                $remaining=$base.OpenSubKey($uninstallPrefix+$fixture.name,$false)
                if($remaining){$remaining.Dispose();throw 'Program key remains.'}
            } finally {$base.Dispose()}
        } catch {$errors+=@($_.Exception.Message)}
    }
    if($rootCreated) {
        try {
            $null=Assert-LocalPath $root
            if([IO.File]::ReadAllText($owner) -cne $token){throw 'Fixture directory owner differs.'}
            $allowed=@($owner,$sentinel,$custom,(Join-Path $alternate 'CustomDCCloneAllowList.xml'))
            foreach($directory in @(Get-ChildItem -LiteralPath $root -Directory -Recurse)) {if($directory.FullName -cne $alternate){throw 'Unexpected fixture directory is preserved.'};$null=Assert-LocalPath $directory.FullName}
            foreach($file in @(Get-ChildItem -LiteralPath $root -File -Recurse)) {if($file.FullName -notin $allowed){throw 'Unexpected fixture file is preserved.'};$null=Assert-LocalPath $file.FullName}
            foreach($file in $allowed){if(Test-Path -LiteralPath $file){$null=Assert-LocalPath $file;Remove-Item -LiteralPath $file -Force}}
            if(Test-Path -LiteralPath $alternate){$null=Assert-LocalPath $alternate;[IO.Directory]::Delete($alternate,$false)}
            [IO.Directory]::Delete($root,$false)
            $record.cleanup.directory_absent=(-not (Test-Path -LiteralPath $root))
        } catch {$errors+=@($_.Exception.Message)}
    }
    try {$record.after=Read-Exclusions;$before=@($record.before | ForEach-Object {"$($_.type)`t$($_.name)"} | Sort-Object);$after=@($record.after | ForEach-Object {"$($_.type)`t$($_.name)"} | Sort-Object);$record.cleanup.baseline_restored=(@(Compare-Object $before $after).Count -eq 0)} catch {$errors+=@($_.Exception.Message)}
}
    }
if($script:cloningOwnedProcessUncertain) { $errors+=@('Owned child state is uncertain; fixture resources preserved.'); $record.passed=$false }
if($script:cloningWriteUncertain) { $errors+=@('Native write outcome is uncertain; all fixture resources preserved.');$record.passed=$false }
$record.cleanup.errors=$errors
$record.passed=($null -eq $failure -and $errors.Count -eq 0 -and $record.cleanup.baseline_restored -and $record.cleanup.directory_absent -and $record.cleanup.allow_list_override_absent -and $record.sentinel_unchanged -and $record.default_unchanged -and @($record.cases | Where-Object {-not $_.source_unchanged}).Count -eq 0)
$record.passed=$record.passed -and @($record.cases | Where-Object {-not $_.passed}).Count -eq 0 -and
    @($record.generation | Where-Object {-not $_.passed}).Count -eq 0 -and
    $record.cases.Count -eq 25 -and $record.generation.Count -eq 5 -and
    (Get-FileHash -LiteralPath $NativeExecutable).Hash -ceq $ExpectedExecutableSHA256
$record.finished=[DateTime]::UtcNow.ToString('o')
$record.stage='finished'
Save-GuestReport
[pscustomobject]@{report_path=$ReportPath;report_sha256=(Get-FileHash -LiteralPath $ReportPath).Hash;passed=$record.passed;stage=$record.stage;fixture=$token} | ConvertTo-Json -Compress
