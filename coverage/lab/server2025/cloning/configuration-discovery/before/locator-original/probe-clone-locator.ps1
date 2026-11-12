#Requires -Version 5.1
param([ValidateSet('original','without-version','direct-original','direct-without-base','explicit-domain','without-force')][string]$Case='original')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$guardPath=Join-Path $PSScriptRoot 'run-clone-config-offline.ps1'
if((Get-FileHash -LiteralPath $guardPath).Hash -cne '116353985A315D63E60B16B3386B8E305B965F9D36FEA131D80A6B8F999C06BE') { throw 'Shared reviewed guards changed.' }
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($guardPath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count) { throw 'Shared guard parse failed.' }
foreach($name in @('Assert-UnlinkedPath','Assert-OwnedControllers','Assert-SwitchPorts','Get-ProfileMutexName','Write-NewHostBytes','Write-NewHostJson','Write-RunState','Wait-OwnedJob','Invoke-OwnedGuest','Assert-NewRunDirectory')) {
    $definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $name)
    if($definition.Count -ne 1) { throw 'Expected one shared guard.' }
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T211528Z-81823b4e'
$helperRoot=Join-Path $buildRoot 'locator-diagnostic-v1';$helper=Join-Path $helperRoot 'clone-locator-diagnostic.exe'
$profile='H:\ad-sdk-lab\server2025';$statePath=Join-Path $profile 'state.json';$credentialPath=Join-Path $profile 'credential.clixml'
$operationMutex=$null;$mutexHeld=$false;$runState=$null
try {
    $operationMutex=[Threading.Mutex]::new($false,(Get-ProfileMutexName $profile))
    try { $mutexHeld=$operationMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $mutexHeld=$true }
    if(-not $mutexHeld) { throw 'Another lab action owns the profile.' }
    foreach($path in @($helper,$statePath,$credentialPath)) { $null=Assert-UnlinkedPath $path }
    if((Get-FileHash -LiteralPath $helper).Hash -cne '2BEBF218DA1E7BA4248E9BD2CFFE2D1D9F8701A872CFE1F39F1D46EA52A81A83' -or
        (Get-FileHash -LiteralPath (Join-Path $helperRoot 'clone-locator-diagnostic.go')).Hash -cne 'ABA7313F82F314D011F499147CC674D9F9CB537894394C8B57618010A945229E') { throw 'Frozen diagnostic differs.' }
    $stateHash=(Get-FileHash -LiteralPath $statePath).Hash;$state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Import-Module Hyper-V -ErrorAction Stop
    Assert-OwnedControllers
    $machine=@($state.machines | Where-Object role -ceq 'dc1')[0]
    $executionID='clone-locator-diagnostic-v1-'+$Case;$target='C:\ad-sdk-validation\'+$executionID
    $resultRoot=Assert-NewRunDirectory (Join-Path $helperRoot $Case);[void][IO.Directory]::CreateDirectory($resultRoot)
    $runOwner=[guid]::NewGuid().ToString('N');$runStatePath=Join-Path $resultRoot 'run-journal.json';$script:guestUncertain=$false
    $runState=[ordered]@{owner=$runOwner;execution_id=$executionID;phase='prepared';terminal=$false;guest_uncertain=$false;updated=$null;jobs=@();error=$null;completed=$false;case=$Case;staging_preserved=$true}
    Write-RunState
    Write-NewHostBytes (Join-Path $resultRoot 'probe-clone-locator.ps1') ([IO.File]::ReadAllBytes($PSCommandPath))
    Write-NewHostBytes (Join-Path $resultRoot 'build.json') ([IO.File]::ReadAllBytes((Join-Path $helperRoot 'build.json')))
    $saved=Import-Clixml -LiteralPath $credentialPath;$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
    $binary=[Convert]::ToBase64String([IO.File]::ReadAllBytes($helper))
    $payload=Invoke-OwnedGuest -TimeoutSeconds 100 -Action 'locator' -Arguments @($target,$executionID,$binary,$Case) -Script {
        param($Directory,$Run,$Binary,$CaseName)
        $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
        $caseArguments=@{original='';'without-version'='-minimum 0';'direct-original'='-direct -flags 1075839121';'direct-without-base'='-direct -flags 1075839105';'explicit-domain'='-domain ad.sdk.test';'without-force'='-force=false'}
        if(-not $caseArguments.ContainsKey($CaseName) -or $env:COMPUTERNAME -cne 'ADSDK25DC1' -or $Run -cne ('clone-locator-diagnostic-v1-'+$CaseName) -or
            $Directory -cne ('C:\ad-sdk-validation\'+$Run) -or (Test-Path -LiteralPath $Directory)) { throw 'Unexpected or existing guest fixture.' }
        for($cursor=$Directory;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked fixture ancestor.' } }
        [void][IO.Directory]::CreateDirectory($Directory)
        [IO.File]::WriteAllText((Join-Path $Directory 'owner.txt'),$Run,[Text.UTF8Encoding]::new($false))
        $exe=Join-Path $Directory 'clone-locator-diagnostic.exe'
        [IO.File]::WriteAllBytes($exe,[Convert]::FromBase64String($Binary))
        if((Get-FileHash -LiteralPath $exe).Hash -cne '2BEBF218DA1E7BA4248E9BD2CFFE2D1D9F8701A872CFE1F39F1D46EA52A81A83') { throw 'Staged diagnostic differs.' }
        $record=[ordered]@{run=$Run;case=$CaseName;arguments=$caseArguments[$CaseName];pid=$null;started_utc=$null;completed=$false;process_uncertain=$true;exit_code=$null;stdout_base64=$null;stderr_base64=$null;error=$null}
        $recordPath=Join-Path $Directory 'observation.json'
        [IO.File]::WriteAllText($recordPath,($record|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
        $process=$null
        try {
            $stdout=Join-Path $Directory 'stdout.json';$stderr=Join-Path $Directory 'stderr.txt'
            $start=@{FilePath=$exe;WindowStyle='Hidden';PassThru=$true;RedirectStandardOutput=$stdout;RedirectStandardError=$stderr;ErrorAction='Stop'}
            if($record.arguments){$start.ArgumentList=$record.arguments}
            $process=Start-Process @start
            $null=$process.Handle;$record.pid=$process.Id;$record.started_utc=$process.StartTime.ToUniversalTime().ToString('o')
            [IO.File]::WriteAllText($recordPath,($record|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
            $watch=[Diagnostics.Stopwatch]::StartNew();$exited=$false
            while($watch.Elapsed.TotalSeconds -lt 65) { if($process.WaitForExit(250)) { $exited=$true;break } }
            if(-not $exited) { throw 'Owned locator process timed out; preserve without retry or cleanup.' }
            $record.exit_code=$process.ExitCode
            if($null -eq $record.exit_code) { throw 'Locator exit status unavailable.' }
            $record.completed=$true;$record.process_uncertain=$false
            foreach($path in @($stdout,$stderr)) { if((Get-Item -LiteralPath $path).Length -gt 2097152) { throw 'Diagnostic exceeds capture bound.' } }
            $record.stdout_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($stdout));$record.stderr_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($stderr))
        } catch { $record.error=$_.Exception.Message }
        finally { [IO.File]::WriteAllText($recordPath,($record|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false));if($null -ne $process){$process.Dispose()} }
        $record | ConvertTo-Json -Depth 8 -Compress
    }
    Write-NewHostJson (Join-Path $resultRoot 'guest-return.json') ([ordered]@{payload=@($payload)})
    $values=@($payload|ConvertFrom-Json)
    if($values.Count -ne 1 -or $values[0].run -cne $executionID -or $values[0].completed -isnot [bool] -or -not $values[0].completed -or
        $values[0].process_uncertain -isnot [bool] -or $values[0].process_uncertain) { $script:guestUncertain=$true;throw 'Locator process completion is uncertain.' }
    $observation=$values[0];Write-NewHostJson (Join-Path $resultRoot 'observation.json') $observation
    if($observation.error){throw $observation.error}
    $stdout=[Convert]::FromBase64String($observation.stdout_base64);$stderr=[Convert]::FromBase64String($observation.stderr_base64)
    Write-NewHostBytes (Join-Path $resultRoot 'stdout.json') $stdout;Write-NewHostBytes (Join-Path $resultRoot 'stderr.txt') $stderr
    $result=[Text.Encoding]::UTF8.GetString($stdout)|ConvertFrom-Json
    $result|ConvertTo-Json -Depth 10
    $runState.completed=$true
    if($result.native_status -eq 1004) { throw 'Reproduced locator ERROR_INVALID_FLAGS (1004).' }
    if($observation.exit_code -ne 0) { throw 'Locator returned another failure; inspect retained result.' }
} catch { if($null -ne $runState){$runState.error=$_.Exception.Message};throw }
finally {
    try { if($null -ne $runState){$runState.terminal=$true;Write-RunState;Write-NewHostJson (Join-Path $resultRoot 'qualification.json') $runState} }
    finally { if($mutexHeld){$operationMutex.ReleaseMutex()};if($operationMutex){$operationMutex.Dispose()} }
}
