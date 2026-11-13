#Requires -Version 5.1
# One public SDK call on an independently identified standalone workstation.
# Writes only new owned diagnostic files under this repository's tmp directory.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T215735Z-b4707e3f'
$helperRoot=Join-Path $buildRoot 'helper-v3';$exe=Join-Path $helperRoot 'clone-config-helper.exe'
$manifest=Join-Path $helperRoot 'build.json'
$expectedHelper='9D2F0D3A3548E8CD719E741A46AB246B3E2AAF24430554F6EC1370DAD21C5D8F'
if((Get-FileHash -LiteralPath $exe).Hash -cne $expectedHelper -or (Get-FileHash -LiteralPath $manifest).Hash -cne 'AC7334366C218A2A708DCAAFDB9776A5557D5E293170482321AE789CF594D219') { throw 'Frozen helper build changed.' }
$computer=Get-CimInstance -ClassName Win32_ComputerSystem -Property Name,DomainRole
$os=Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption,Version,BuildNumber,ProductType
if($computer.Name -cne 'SHOCONE' -or [int]$computer.DomainRole -ne 0 -or [int]$os.ProductType -ne 1) { throw 'Expected standalone workstation was not independently verified.' }
$run='clone-config-unsupported-host-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$root=Join-Path $PSScriptRoot $run
foreach($path in @($root,$exe)) {
    for($cursor=[IO.Path]::GetFullPath($path);$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked probe path.' }
    }
}
if(Test-Path -LiteralPath $root) { throw 'Existing probe retained.' }
[void][IO.Directory]::CreateDirectory($root)
$output=Join-Path $root 'output';[void][IO.Directory]::CreateDirectory($output)
$encoding=[Text.UTF8Encoding]::new($false)
function Save([string]$Name,$Value) { [IO.File]::WriteAllText((Join-Path $root $Name),($Value|ConvertTo-Json -Depth 12),$encoding) }
[IO.File]::WriteAllBytes((Join-Path $root 'probe.ps1'),[IO.File]::ReadAllBytes($PSCommandPath))
[IO.File]::WriteAllBytes((Join-Path $root 'helper-build.json'),[IO.File]::ReadAllBytes($manifest))
$options=[ordered]@{Offline=$false;Directory=$output;Timeout=10000000000};Save 'options.json' $options
$record=[ordered]@{schema_version=1;run=$run;source_commit='c72c7b0a4a785f177a70f26729b7d9ffff140a46';helper_sha256=$expectedHelper;host_script_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash;computer=$computer.Name;cim_domain_role=[int]$computer.DomainRole;os=$os.Caption;os_version=$os.Version;os_build=$os.BuildNumber;product_type=[int]$os.ProductType;powershell=$PSVersionTable.PSVersion.ToString();options=$options;pid=$null;started_utc=$null;terminal=$false;process_uncertain=$true;exit_code=$null;passed=$false;error=$null;output_files=@();artifacts=@();staging_preserved=$true}
Save 'qualification.json' $record
$process=$null
try {
    $stdout=Join-Path $root 'sdk.stdout.json';$stderr=Join-Path $root 'sdk.stderr.txt'
    $process=Start-Process -FilePath $exe -ArgumentList ('-options "'+(Join-Path $root 'options.json')+'"') -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null=$process.Handle;$record.pid=$process.Id;$record.started_utc=$process.StartTime.ToUniversalTime().ToString('o');Save 'qualification.json' $record
    $watch=[Diagnostics.Stopwatch]::StartNew();$ended=$false
    while($watch.Elapsed.TotalSeconds -lt 35) { if($process.WaitForExit(250)) { $ended=$true;break } }
    if(-not $ended) { throw 'Owned process completion is unknown; preserve without retry or cleanup.' }
    $record.exit_code=$process.ExitCode
    if($null -eq $record.exit_code) { throw 'Owned process exit status is unknown.' }
    $record.process_uncertain=$false
    foreach($path in @($stdout,$stderr)) { if((Get-Item -LiteralPath $path).Length -gt 2097152) { throw 'Diagnostic exceeds capture bound.' } }
    $result=Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json
    $record.output_files=@(Get-ChildItem -LiteralPath $output -Force | Select-Object Name,Length,Attributes)
    if($record.exit_code -ne 1 -or $result.protocol_version -ne 1 -or $result.operation -cne 'generate_config' -or
        $result.data.outcome -cne 'not_written' -or $result.data.checks_skipped -or $result.data.prerequisites.complete -or
        $result.data.prerequisites.role.machine_role -ne 0 -or -not $result.error_details.not_domain_controller -or
        $result.data.prerequisites.source_host -or $result.data.prerequisites.primary_controller -or $record.output_files.Count) { throw 'SDK did not preserve the expected unsupported-host outcome.' }
    $record.passed=$true
} catch { $record.error=$_.Exception.Message;throw }
finally {
    $record.terminal=$true;$record.finished_utc=[DateTime]::UtcNow.ToString('o')
    foreach($file in @(Get-ChildItem -LiteralPath $root -File | Where-Object Name -ne 'qualification.json')) { $record.artifacts+=@([ordered]@{name=$file.Name;bytes=$file.Length;sha256=(Get-FileHash -LiteralPath $file.FullName).Hash}) }
    Save 'qualification.json' $record
    if($null -ne $process) { $process.Dispose() }
}
[ordered]@{directory=$root;passed=$record.passed;domain_role=$record.cim_domain_role;outcome='not_written';error='not_domain_controller'}|ConvertTo-Json
