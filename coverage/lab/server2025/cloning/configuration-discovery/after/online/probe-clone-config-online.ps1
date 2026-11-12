#Requires -Version 5.1
# One native online readyness observation. The explicit ordinary scratch path
# is outside every supported clone output location. No prerequisites are changed.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$guardPath=Join-Path $PSScriptRoot 'run-clone-config-offline.ps1'
if((Get-FileHash -LiteralPath $guardPath).Hash -cne '116353985A315D63E60B16B3386B8E305B965F9D36FEA131D80A6B8F999C06BE') { throw 'Reviewed shared guards changed.' }
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($guardPath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count) { throw 'Shared guard parse failed.' }
foreach($name in @('Assert-UnlinkedPath','Assert-OwnedControllers','Assert-SwitchPorts','Get-ProfileMutexName','Write-NewHostBytes','Write-NewHostJson','Write-RunState','Wait-OwnedJob','Invoke-OwnedGuest','Assert-NewRunDirectory')) {
    $definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $name)
    if($definition.Count -ne 1) { throw 'Expected one reviewed guard definition.' }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T215735Z-b4707e3f'
$helperRoot=Join-Path $buildRoot 'helper-v3';$helper=Join-Path $helperRoot 'clone-config-helper.exe'
$profile='H:\ad-sdk-lab\server2025';$statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml'
$operationMutex=$null;$mutexHeld=$false;$runState=$null
try {
    $operationMutex=[Threading.Mutex]::new($false,(Get-ProfileMutexName $profile))
    try { $mutexHeld=$operationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld=$true }
    if(-not $mutexHeld) { throw 'Another lab action owns the profile.' }
    foreach($path in @($helper,$statePath,$credentialPath)) { $null=Assert-UnlinkedPath $path }
    if((Get-FileHash -LiteralPath $helper).Hash -cne '9D2F0D3A3548E8CD719E741A46AB246B3E2AAF24430554F6EC1370DAD21C5D8F' -or
        (Get-FileHash -LiteralPath (Join-Path $helperRoot 'build.json')).Hash -cne 'AC7334366C218A2A708DCAAFDB9776A5557D5E293170482321AE789CF594D219' -or
        (Get-FileHash -LiteralPath (Join-Path $buildRoot 'build.json')).Hash -cne '8C1A3E99029AEADEDEE39904707E95B5C5C45599590A2BBF1EE0C61869E19579') { throw 'Frozen helper or source manifest differs.' }
    $stateHash=(Get-FileHash -LiteralPath $statePath).Hash
    $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Import-Module Hyper-V -ErrorAction Stop
    Assert-OwnedControllers
    $machine=@($state.machines | Where-Object role -ceq 'dc1')[0]
    $executionID='clone-config-reviewed-20261112T215735Z-b4707e3f-online-readiness-v2'
    $target='C:\ad-sdk-validation\'+$executionID
    $resultRoot=Assert-NewRunDirectory (Join-Path $buildRoot 'server2025-online-readiness-v2')
    [void][IO.Directory]::CreateDirectory($resultRoot)
    $runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'run-journal.json';$script:guestUncertain=$false
    $runState=[ordered]@{owner=$runOwner;execution_id=$executionID;phase='prepared';terminal=$false;guest_uncertain=$false;updated=$null;jobs=@();error=$null;completed=$false;source_commit='c72c7b0a4a785f177a70f26729b7d9ffff140a46';helper_sha256='9D2F0D3A3548E8CD719E741A46AB246B3E2AAF24430554F6EC1370DAD21C5D8F';staging_preserved=$true;lab_id=$state.id;vm_id=$machine.id}
    Write-RunState
    Write-NewHostBytes (Join-Path $resultRoot 'probe-clone-config-online.ps1') ([IO.File]::ReadAllBytes($PSCommandPath))
    Write-NewHostBytes (Join-Path $resultRoot 'shared-guards.ps1') ([IO.File]::ReadAllBytes($guardPath))
    Write-NewHostBytes (Join-Path $resultRoot 'build.json') ([IO.File]::ReadAllBytes((Join-Path $buildRoot 'build.json')))
    Write-NewHostBytes (Join-Path $resultRoot 'helper-v3-build.json') ([IO.File]::ReadAllBytes((Join-Path $helperRoot 'build.json')))
    $saved=Import-Clixml -LiteralPath $credentialPath;$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
    $binary=[Convert]::ToBase64String([IO.File]::ReadAllBytes($helper))
    $payload=Invoke-OwnedGuest -TimeoutSeconds 100 -Action 'native-online-readiness' -Arguments @($target,$executionID,$binary,$runState.helper_sha256) -Script {
        param($Directory,$Run,$Binary,$Hash)
        $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
        if($env:COMPUTERNAME -cne 'ADSDK25DC1' -or $Run -cne 'clone-config-reviewed-20261112T215735Z-b4707e3f-online-readiness-v2' -or
            $Directory -cne ('C:\ad-sdk-validation\'+$Run) -or $Hash -cne '9D2F0D3A3548E8CD719E741A46AB246B3E2AAF24430554F6EC1370DAD21C5D8F' -or (Test-Path -LiteralPath $Directory)) { throw 'Unexpected or existing guest fixture.' }
        for($cursor=$Directory;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked fixture ancestor.' } }
        # Independently confirm this ordinary fixed-drive scratch directory can
        # never equal the DSA directory, Windows NTDS directory, or a drive root.
        $output=Join-Path $Directory 'unsupported-output'
        $dsa=[IO.Path]::GetFullPath((Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'DSA Working Directory').'DSA Working Directory').TrimEnd('\')
        $ntds=[IO.Path]::GetFullPath((Join-Path $env:windir 'NTDS')).TrimEnd('\')
        if([string]::Equals($output,$dsa,[StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($output,$ntds,[StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals($output,[IO.Path]::GetPathRoot($output),[StringComparison]::OrdinalIgnoreCase) -or [IO.DriveInfo]::new('C:\').DriveType -ne [IO.DriveType]::Fixed) { throw 'Probe output is not independently proven unsupported.' }
        [void][IO.Directory]::CreateDirectory($output)
        [IO.File]::WriteAllText((Join-Path $Directory 'owner.txt'),$Run,[Text.UTF8Encoding]::new($false))
        $exe=Join-Path $Directory 'clone-config-helper.exe'
        [IO.File]::WriteAllBytes($exe,[Convert]::FromBase64String($Binary))
        if((Get-FileHash -LiteralPath $exe).Hash -cne $Hash) { throw 'Staged helper digest differs.' }
        $options=[ordered]@{Offline=$false;Directory=$output;Timeout=30000000000}
        $optionsPath=Join-Path $Directory 'options.json'
        [IO.File]::WriteAllText($optionsPath,($options|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
        $record=[ordered]@{run=$Run;computer=$env:COMPUTERNAME;os_version=[Environment]::OSVersion.Version.ToString();powershell=$PSVersionTable.PSVersion.ToString();helper_sha256=$Hash;dsa_directory=$dsa;windows_ntds=$ntds;output=$output;options=$options;pid=$null;started_utc=$null;completed=$false;process_uncertain=$true;exit_code=$null;stdout_base64=$null;stderr_base64=$null;output_files=@();error=$null}
        $recordPath=Join-Path $Directory 'observation.json'
        [IO.File]::WriteAllText($recordPath,($record|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
        $process=$null
        try {
            $stdout=Join-Path $Directory 'sdk.stdout.txt';$stderr=Join-Path $Directory 'sdk.stderr.txt'
            $process=Start-Process -FilePath $exe -ArgumentList ('-options "'+$optionsPath+'"') -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ErrorAction Stop
            $null=$process.Handle;$record.pid=$process.Id;$record.started_utc=$process.StartTime.ToUniversalTime().ToString('o')
            [IO.File]::WriteAllText($recordPath,($record|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
            $watch=[Diagnostics.Stopwatch]::StartNew();$exited=$false
            while($watch.Elapsed.TotalSeconds -lt 65) { if($process.WaitForExit(250)) { $exited=$true;break } }
            if(-not $exited) { throw 'Owned native process timed out; no retry or cleanup.' }
            $record.exit_code=$process.ExitCode
            if($null -eq $record.exit_code) { throw 'Native exit status unavailable.' }
            $record.completed=$true;$record.process_uncertain=$false
            foreach($path in @($stdout,$stderr)) { if((Get-Item -LiteralPath $path).Length -gt 2097152) { throw 'Native diagnostic exceeds capture bound.' } }
            $record.stdout_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($stdout));$record.stderr_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($stderr))
            $record.output_files=@(Get-ChildItem -LiteralPath $output -Force | Select-Object Name,Length,Attributes)
        } catch { $record.error=$_.Exception.Message }
        finally { [IO.File]::WriteAllText($recordPath,($record|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false));if($null -ne $process){$process.Dispose()} }
        $record | ConvertTo-Json -Depth 10 -Compress
    }
    Write-NewHostJson (Join-Path $resultRoot 'guest-return.json') ([ordered]@{payload=@($payload)})
    $values=@($payload|ConvertFrom-Json)
    if($values.Count -ne 1 -or $values[0].run -cne $executionID -or $values[0].helper_sha256 -cne $runState.helper_sha256 -or
        $values[0].completed -isnot [bool] -or -not $values[0].completed -or $values[0].process_uncertain -isnot [bool] -or $values[0].process_uncertain) { $script:guestUncertain=$true;throw 'Native probe completion is uncertain.' }
    $observation=$values[0]
    Write-NewHostJson (Join-Path $resultRoot 'observation.json') $observation
    if($observation.error) { throw $observation.error }
    $stdout=[Convert]::FromBase64String($observation.stdout_base64);$stderr=[Convert]::FromBase64String($observation.stderr_base64)
    Write-NewHostBytes (Join-Path $resultRoot 'sdk.stdout.json') $stdout
    Write-NewHostBytes (Join-Path $resultRoot 'sdk.stderr.txt') $stderr
    $sdk=[Text.Encoding]::UTF8.GetString($stdout)|ConvertFrom-Json
    if($sdk.protocol_version -ne 1 -or $sdk.operation -cne 'generate_config' -or $sdk.data.outcome -cne 'not_written' -or $sdk.data.checks_skipped -or
        -not $sdk.error_details.present -or $observation.exit_code -ne 1 -or @($observation.output_files).Count -ne 0) { throw 'Online probe violated expected no-publication outcome; retain all evidence.' }
    $runState.completed=$true
    $sdk|ConvertTo-Json -Depth 12
} catch { if($null -ne $runState){$runState.error=$_.Exception.Message};throw }
finally {
    try { if($null -ne $runState){$runState.terminal=$true;Write-RunState;Write-NewHostJson (Join-Path $resultRoot 'qualification.json') $runState} }
    finally { if($mutexHeld){$operationMutex.ReleaseMutex()};if($operationMutex){$operationMutex.Dispose()} }
}
