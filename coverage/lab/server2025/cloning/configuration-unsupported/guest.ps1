#Requires -Version 5.1
# One local SDK host-gate observation; no directory/configuration mutations.
param([Parameter(Mandatory)][string]$PayloadJson)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$Run='clone-config-unsupported-server2025-59346e9-v1'
$StageDirectory=Join-Path 'C:\ad-sdk-validation' $Run
$script:processUncertain=$false;$script:publicationUncertain=$false;$script:captureFailed=$false
function Assert-UnsupportedWire($Wire,$Process,[int]$OutputCount) {
    foreach($value in @($Wire.data.checks_skipped,$Wire.data.prerequisites.complete,$Wire.error_details.present,$Wire.error_details.not_domain_controller)) {
        if($value -isnot [bool]) { throw 'Untyped SDK outcome.' }
    }
    $source=$Wire.data.prerequisites.PSObject.Properties['source_host'];$primary=$Wire.data.prerequisites.PSObject.Properties['primary_controller']
    if(-not $Process.completed -or $Process.process_uncertain -or $null -ne $Process.error -or $Process.exit_code -ne 1 -or
        $Wire.protocol_version -ne 1 -or $Wire.operation -cne 'generate_config' -or $Wire.data.outcome -cne 'not_written' -or
        $Wire.data.checks_skipped -or $Wire.data.prerequisites.complete -or $Wire.data.prerequisites.role.machine_role -ne 2 -or
        -not $Wire.error_details.present -or -not $Wire.error_details.not_domain_controller -or
        ($null -ne $source -and $source.Value) -or ($null -ne $primary -and $primary.Value) -or $OutputCount -ne 0) { throw 'Expected unsupported standalone Server rejection was not observed.' }
}
function Assert-GuestIdentity($Computer,$OS) {
    if($Computer.Name -cne 'ADSDK25MEM' -or [int]$Computer.DomainRole -ne 2 -or $Computer.PartOfDomain -isnot [bool] -or $Computer.PartOfDomain -or
        [int]$OS.ProductType -ne 3 -or $OS.BuildNumber -cne '26100') { throw 'Expected unjoined Server 2025 member identity differs.' }
}
$payload=$PayloadJson|ConvertFrom-Json
$pins=[ordered]@{
    'clone-config-helper.exe'='09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957'
    'helper-v4-build.json'='362DE5A85947FFDE1DB6571617F5AA908037553661F899B6A32E4E22DF38E377'
    'build.json'='386ECB6700D11F28EBD4B4A9033392A9DAD03968AC0E5BE2E7AB60859E1F141F'
    'negative-process-support.ps1'='2208AD62F661E99400DDCB3BA53B396486D05D17E4C5AD1185D64A652338DC4D'
}
$decoded=@{}
foreach($name in $pins.Keys) {
    $bytes=[Convert]::FromBase64String($payload.$name)
    if($bytes.Length -gt 33554432) { throw 'Payload exceeds bound.' }
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { $digest=[BitConverter]::ToString($hasher.ComputeHash($bytes)).Replace('-','') } finally { $hasher.Dispose() }
    if($digest -cne $pins[$name]) { throw 'Pinned guest payload differs.' };$decoded[$name]=$bytes
}
# Import only reviewed primitives, never the support file entrypoint.
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString($decoded['negative-process-support.ps1']),[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'Process support parse failed.' }
foreach($name in @('Assert-StagePath','Bytes-Hash','Write-NewBytes','Write-NewJson','Error-Observation','Assert-CanRun','Wait-OwnedProcess','Start-OwnedProcess','Invoke-OwnedChild')) {
    $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    if($definitions.Count -ne 1) { throw 'Process primitive is missing or duplicated.' };. ([scriptblock]::Create($definitions[0].Extent.Text))
}
$null=Assert-StagePath $StageDirectory
if(Test-Path -LiteralPath $StageDirectory) { throw 'Existing guest staging is preserved; no replay.' }
$computer=Get-CimInstance Win32_ComputerSystem -Property Name,DomainRole,PartOfDomain -OperationTimeoutSec 10
$os=Get-CimInstance Win32_OperatingSystem -Property Caption,Version,BuildNumber,ProductType -OperationTimeoutSec 10
Assert-GuestIdentity $computer $os
[void][IO.Directory]::CreateDirectory($StageDirectory)
Write-NewBytes (Join-Path $StageDirectory 'owner.txt') ([Text.Encoding]::UTF8.GetBytes($Run))
foreach($name in $pins.Keys) { Write-NewBytes (Join-Path $StageDirectory $name) $decoded[$name] }
$output=Assert-StagePath (Join-Path $StageDirectory 'output');[void][IO.Directory]::CreateDirectory($output)
$options=[ordered]@{Offline=$false;Directory=$output;Timeout=10000000000}
Write-NewJson (Join-Path $StageDirectory 'options.json') $options
$summary=[ordered]@{schema_version=1;run=$Run;computer=$computer.Name;cim_domain_role=[int]$computer.DomainRole;part_of_domain=$computer.PartOfDomain;product_type=[int]$os.ProductType;os=$os.Caption;os_version=$os.Version;os_build=$os.BuildNumber;powershell=$PSVersionTable.PSVersion.ToString();source_commit='59346e9641feada4915a3313273ee2fc845bdbeb';helper_sha256=$pins['clone-config-helper.exe'];terminal=$false;passed=$false;child_invoked=$false;process=$null;process_uncertain=$false;capture_failed=$false;output_files=@();error=$null;staging_preserved=$true}
try {
    $summary.child_invoked=$true
    $summary.process=Invoke-OwnedChild (Join-Path $StageDirectory 'clone-config-helper.exe') ('-options "'+(Join-Path $StageDirectory 'options.json')+'"') (Join-Path $StageDirectory 'sdk') 35
    if($script:processUncertain -or $script:captureFailed) { throw 'Child completion or capture is uncertain.' }
    $wire=Get-Content -LiteralPath (Join-Path $StageDirectory 'sdk.stdout.txt') -Raw|ConvertFrom-Json
    $summary.output_files=@(Get-ChildItem -LiteralPath $output -Force|Select-Object Name,Length,Attributes)
    Assert-UnsupportedWire $wire $summary.process $summary.output_files.Count
    $summary.passed=$true
} catch { $summary.error=Error-Observation $_ }
finally {
    $summary.terminal=$true;$summary.process_uncertain=$script:processUncertain;$summary.capture_failed=$script:captureFailed
    Write-NewJson (Join-Path $StageDirectory 'summary.json') $summary
}
# Capture in the same completed remoting operation; no second guest dispatch.
$artifacts=@()
foreach($name in @('owner.txt','options.json','sdk.requested.json','sdk.started.json','sdk.finished.json','sdk.stdout.txt','sdk.stderr.txt','summary.json')) {
    $path=Assert-StagePath (Join-Path $StageDirectory $name)
    if(-not (Test-Path -LiteralPath $path)) { continue }
    if((Get-Item -LiteralPath $path).Length -gt 2097152) { throw 'Evidence exceeds capture bound.' }
    $bytes=[IO.File]::ReadAllBytes($path);$artifacts+=@([ordered]@{name=$name;sha256=(Bytes-Hash $bytes);bytes=$bytes.Length;base64=[Convert]::ToBase64String($bytes)})
}
[ordered]@{schema_version=1;run=$Run;summary=$summary;artifacts=$artifacts}|ConvertTo-Json -Depth 24 -Compress
