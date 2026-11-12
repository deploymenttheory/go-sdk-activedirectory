#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$ExpectedComputer,
    [Parameter(Mandatory)][string]$NativeExecutable,
    [Parameter(Mandatory)][string]$ExpectedExecutableSHA256
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:COMPUTERNAME -ne $ExpectedComputer -or $ExpectedComputer -ne 'ADSDK25DC1'){throw 'Unexpected fixture computer.'}
if((Get-CimInstance Win32_ComputerSystem -Property DomainRole).DomainRole -notin @(4,5)){throw 'Fixture requires a domain controller.'}
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
$created=@();$errors=@();$failure=$null;$overrideCreated=$false;$rootCreated=$false
$record=[ordered]@{schema_version=1;native_executable_sha256=$ExpectedExecutableSHA256;fixture=$token;computer=$env:COMPUTERNAME;started=[DateTime]::UtcNow.ToString('o');before=@();with_programs=@();cases=@();generation=@();after=@();cleanup=[ordered]@{allow_list_override_absent=$false;directory_absent=$false;baseline_restored=$false};sentinel_unchanged=$false;default_unchanged=$false;error=$null;passed=$false}
function Assert-LocalPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($validationRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture path escaped validation root.'}
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Fixture path traverses a reparse point.'}
    }
    return $full
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
function Native-Observation([string]$Directory='', [bool]$Overwrite=$false) {
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
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false
    try {
        if (-not $process.Start()) { throw 'Native fixture process did not start.' }
        $started=$true
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        $watch=[Diagnostics.Stopwatch]::StartNew();$exited=$false
        while ($watch.Elapsed.TotalSeconds -lt 60) {
            if ($process.WaitForExit(250)) { $exited=$true;break }
        }
        if (-not $exited) { throw 'Owned native fixture process timed out; no retry will be attempted.' }
        if (-not $stdout.Wait(1000) -or -not $stderr.Wait(1000)) { throw 'Native fixture pipes did not close.' }
        $data=$stdout.Result | ConvertFrom-Json -ErrorAction Stop
        if (-not $data) { throw 'Native fixture returned no structured outcome.' }
        return [ordered]@{exit_code=$process.ExitCode;error=$stderr.Result;data=$data;elapsed_ms=$watch.ElapsedMilliseconds}
    } finally {
        if ($started -and -not $process.HasExited) {
            $script:cloningOwnedProcessUncertain=$true
            $process.Kill()
            if (-not $process.WaitForExit(2000)) { throw 'Owned native child remains after termination; preserve fixture for investigation.' }
            $script:cloningOwnedProcessUncertain=$false
        }
        $process.Dispose()
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
    $null=Assert-LocalPath $custom
    $encoding=if($UTF16){[Text.UnicodeEncoding]::new($false,$true)}else{[Text.UTF8Encoding]::new($false)}
    [IO.File]::WriteAllText($custom,$Xml,$encoding)
    $case=[ordered]@{name=$Name;xml=$Xml;encoding=$(if($UTF16){'UTF-16LE-BOM'}else{'UTF-8-no-BOM'});source_sha256=(Get-FileHash -LiteralPath $custom).Hash;entries=@();error=$null}
    try {$case.entries=Read-Exclusions} catch {$case.error=Error-Observation $_}
    $case.source_unchanged=((Get-FileHash -LiteralPath $custom).Hash -eq $case.source_sha256)
    $case.native=Native-Observation
    $case.documented_validation_difference=($Name -in @('wrong-root','wrong-namespace'))
    $case.expected_reference_error=($Name -in @('unknown-type','empty-name','empty-root','missing-name','missing-type','duplicate-name-child','extra-version-child','truncated-xml','internal-entity','trailing-document'))
    $referenceOutcomeMatches=($case.expected_reference_error -eq ($null -ne $case.error))
    if ($case.expected_reference_error -or $case.documented_validation_difference) {
        $case.passed=($referenceOutcomeMatches -and $case.native.exit_code -eq 1 -and -not $case.native.data.complete -and $case.native.error.Contains('invalid DC cloning inclusion list'))
    } else {
        $case.passed=($referenceOutcomeMatches -and $case.native.exit_code -eq 0 -and $case.native.data.complete -and
            $case.native.data.authorization_limited -and (Same-Entries $case.entries $case.native.data.entries))
    }
    $case.source_unchanged=$case.source_unchanged -and ((Get-FileHash -LiteralPath $custom).Hash -eq $case.source_sha256)
    $case.passed=$case.passed -and $case.source_unchanged
    $record.cases+=@($case)
}
function Run-Generation([string]$Name,[string]$Directory,[switch]$Force) {
    $null=Assert-LocalPath $Directory
    $path=Join-Path $Directory 'CustomDCCloneAllowList.xml'
    $case=[ordered]@{name=$Name;directory=$Directory;force=[bool]$Force;before_sha256=$(if(Test-Path -LiteralPath $path){(Get-FileHash -LiteralPath $path).Hash}else{$null});error=$null;output=@();after_sha256=$null;xml=$null;bytes_base64=$null}
    $beforeBytes=if(Test-Path -LiteralPath $path){[IO.File]::ReadAllBytes($path)}else{$null}
    $case.native=Native-Observation $Directory ([bool]$Force)
    $case.native_after_sha256=if(Test-Path -LiteralPath $path){(Get-FileHash -LiteralPath $path).Hash}else{$null}
    $case.native_xml=if(Test-Path -LiteralPath $path){[IO.File]::ReadAllText($path)}else{$null}
    $case.native_bytes_base64=if(Test-Path -LiteralPath $path){[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))}else{$null}
    # Run PowerShell from the identical initial file state, within this owned root.
    if ($null -ne $beforeBytes) { [IO.File]::WriteAllBytes($path,$beforeBytes) }
    elseif (Test-Path -LiteralPath $path) { $null=Assert-LocalPath $path;Remove-Item -LiteralPath $path -Force }
    try {
        $case.output=@(Get-ADDCCloningExcludedApplicationList -GenerateXml -Path $Directory -Force:$Force -ErrorAction Stop | ForEach-Object {[string]$_})
    } catch {$case.error=Error-Observation $_}
    if(Test-Path -LiteralPath $path) {$case.after_sha256=(Get-FileHash -LiteralPath $path).Hash;$case.xml=[IO.File]::ReadAllText($path);$case.bytes_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))}
    $case.raw_bytes_equal=($case.native_bytes_base64 -ceq $case.bytes_base64)
    $case.expected_success=($Name -in @('same-rank-new-without-force','same-rank-existing-with-force'))
    if (-not $case.expected_success) {
        $case.passed=($null -ne $case.error -and $case.native.exit_code -eq 1 -and $case.native.data.outcome -eq 'not_written' -and
            $case.native_after_sha256 -eq $case.before_sha256 -and $case.after_sha256 -eq $case.before_sha256)
    } elseif ($null -eq $case.error -and $case.native.exit_code -eq 0) {
        $nativeEntries=@(Generated-Entries $case.native_xml)
        $referenceEntries=@(Generated-Entries $case.xml)
        $case.semantic_xml_equal=Same-Entries $nativeEntries $referenceEntries
        $case.passed=($case.native.exit_code -eq 0 -and $case.native.data.outcome -eq 'written' -and
            $case.native.data.result.complete -and $case.semantic_xml_equal -and
            (Same-Entries $nativeEntries $record.with_programs) -and
            (Same-Entries $case.native.data.result.entries $record.with_programs))
    } else {
        $case.passed=$false
    }
    $record.generation+=@($case)
}
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
    if(@($record.before | Where-Object {$_.name -ceq 'ClipSVC' -and $_.type -ceq 'Service'}).Count -ne 1){throw 'Expected reference service is not an exclusion.'}
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
    $record.program_name=$programName;$record.with_programs=Read-Exclusions
    if($record.with_programs.Count -ne $record.before.Count+2 -or
        @($record.with_programs | Where-Object {$_.name -ceq $programName -and $_.type -ceq 'Program'}).Count -ne 1 -or
        @($record.with_programs | Where-Object {$_.name -ceq $programName -and $_.type -ceq 'WoW64Program'}).Count -ne 1 -or
        -not (Same-Entries $record.before @($record.with_programs | Where-Object {$_.name -cne $programName}))) { throw 'Both program views must produce one additional typed exclusion with the original baseline preserved.' }
    $null=New-ItemProperty -LiteralPath $parameters -Name AllowListFolder -Value $root -PropertyType String;$overrideCreated=$true
    Run-Case 'exact-service' (Wrap-Custom (Allow-Entry 'ClipSVC' 'Service'))
    Run-Case 'case-service-name' (Wrap-Custom (Allow-Entry 'clipsvc' 'Service'))
    Run-Case 'case-service-type' (Wrap-Custom (Allow-Entry 'ClipSVC' 'service'))
    Run-Case 'wildcard-service-name' (Wrap-Custom (Allow-Entry 'Clip*' 'Service'))
    Run-Case 'whitespace-service-name' (Wrap-Custom (Allow-Entry ' ClipSVC ' 'Service'))
    Run-Case 'duplicate-allow' (Wrap-Custom ((Allow-Entry 'ClipSVC' 'Service')+(Allow-Entry 'ClipSVC' 'Service')))
    Run-Case 'unknown-type' (Wrap-Custom (Allow-Entry 'ClipSVC' 'Unknown'))
    Run-Case 'empty-name' (Wrap-Custom (Allow-Entry '' 'Service'))
    Run-Case 'empty-root' (Wrap-Custom '')
    Run-Case 'wrong-root' '<Unknown />'
    Run-Case 'wrong-namespace' ('<dc:CustomDCCloneAllowList xmlns:dc="urn:wrong">'+(Allow-Entry 'ClipSVC' 'Service')+'</dc:CustomDCCloneAllowList>')
    Run-Case 'missing-name' (Wrap-Custom '<Allow><Type>Service</Type></Allow>')
    Run-Case 'missing-type' (Wrap-Custom '<Allow><Name>ClipSVC</Name></Allow>')
    Run-Case 'duplicate-name-child' (Wrap-Custom '<Allow><Name>ClipSVC</Name><Name>ClipSVC</Name><Type>Service</Type></Allow>')
    Run-Case 'extra-version-child' (Wrap-Custom '<Allow><Name>ClipSVC</Name><Type>Service</Type><Version>7.3.1</Version></Allow>')
    Run-Case 'truncated-xml' '<dc:CustomDCCloneAllowList xmlns:dc="uri:microsoft.com:schemas:CustomDCCloneAllowList"><Allow>'
    Run-Case 'utf16-bom' (Wrap-Custom (Allow-Entry 'ClipSVC' 'Service')) -UTF16
    Run-Case 'internal-entity' ('<!DOCTYPE dc:CustomDCCloneAllowList [<!ENTITY fixture "ClipSVC">]>'+ (Wrap-Custom '<Allow><Name>&fixture;</Name><Type>Service</Type></Allow>'))
    Run-Case 'trailing-document' ((Wrap-Custom (Allow-Entry 'ClipSVC' 'Service'))+'<Extra/>')
    Run-Case 'exact-program64' (Wrap-Custom (Allow-Entry $programName 'Program'))
    Run-Case 'exact-program32' (Wrap-Custom (Allow-Entry $programName 'WoW64Program'))
    Run-Case 'case-program-name' (Wrap-Custom (Allow-Entry $programName.ToLowerInvariant() 'Program'))
    Run-Case 'case-program-type' (Wrap-Custom (Allow-Entry $programName 'program'))
    Run-Case 'program-both-views' (Wrap-Custom ((Allow-Entry $programName 'Program')+(Allow-Entry $programName 'WoW64Program')))
    Run-Case 'generation-seed' (Wrap-Custom (Allow-Entry 'ClipSVC' 'Service'))
    # A fresh output is generated first, then reset to the controlled custom seed.
    Remove-Item -LiteralPath $custom -Force
    Run-Generation 'same-rank-new-without-force' $root
    [IO.File]::WriteAllText($custom,(Wrap-Custom (Allow-Entry 'ClipSVC' 'Service')),[Text.UTF8Encoding]::new($false))
    Run-Generation 'same-rank-existing-without-force' $root
    Run-Generation 'same-rank-existing-with-force' $root -Force
    Run-Generation 'existing-generated-without-force' $root
    Run-Generation 'unconfigured-alternate-with-force' $alternate -Force
    $record.sentinel_unchanged=((Get-FileHash -LiteralPath $sentinel).Hash -eq $sentinelHash)
    $record.default_unchanged=((Get-FileHash -LiteralPath $default).Hash -eq $record.default_sha256)
} catch {$failure=$_;$record.error=Error-Observation $_}
finally {
    if(-not $script:cloningOwnedProcessUncertain) {
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
$record.cleanup.errors=$errors
$record.passed=($null -eq $failure -and $errors.Count -eq 0 -and $record.cleanup.baseline_restored -and $record.cleanup.directory_absent -and $record.cleanup.allow_list_override_absent -and $record.sentinel_unchanged -and $record.default_unchanged -and @($record.cases | Where-Object {-not $_.source_unchanged}).Count -eq 0)
$record.passed=$record.passed -and @($record.cases | Where-Object {-not $_.passed}).Count -eq 0 -and
    @($record.generation | Where-Object {-not $_.passed}).Count -eq 0 -and
    $record.cases.Count -eq 25 -and $record.generation.Count -eq 5 -and
    (Get-FileHash -LiteralPath $NativeExecutable).Hash -ceq $ExpectedExecutableSHA256
$record.finished=[DateTime]::UtcNow.ToString('o')
$record | ConvertTo-Json -Depth 12 -Compress
