#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState,[Parameter(Mandatory)][PSCredential]$Credential,[Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
$lds=Get-Content -LiteralPath (Assert-LabPath (Join-Path $LabRoot 'lds-state.json')) -Raw | ConvertFrom-Json
$client=$LabState.machines | Where-Object role -eq dc2
$member=$LabState.machines | Where-Object role -eq member
foreach($machine in @($client,$member)){$null=Get-OwnedVM $machine $LabState}
if($lds.lab_id -ne $LabState.id -or $lds.client_id -ne $client.id -or $lds.member_id -ne $member.id -or $lds.phase -ne 'fixture-ready'){throw 'Complete ConfigureLDS before qualification.'}
$reader=Import-Clixml -LiteralPath (Assert-LabPath (Join-Path $LabRoot 'lds-reader.clixml'))
if($reader -isnot [PSCredential] -or $reader.UserName -cne $lds.reader.dn){throw 'LDS reader credential differs.'}
$runId='lds-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$resultRoot=Assert-LabPath (Join-Path $LabRoot "results\$runId")
$snapshot=Join-Path $resultRoot 'source';$harness=Join-Path $resultRoot 'harness'
$null=New-Item -ItemType Directory -Path $snapshot,$harness
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Copy-Item -LiteralPath (Join-Path $sourceRoot 'go.mod'),(Join-Path $sourceRoot 'go.sum') -Destination $snapshot
Get-ChildItem -LiteralPath $sourceRoot -Filter '*.go' -File | Copy-Item -Destination $snapshot
function Get-LDSSourceHashes {
    $hashes=[ordered]@{}
    foreach($file in (Get-ChildItem -LiteralPath $snapshot -File | Sort-Object Name)){$hashes[$file.Name]=(Get-FileHash -LiteralPath $file.FullName).Hash}
    return $hashes
}
$sourceHashes=Get-LDSSourceHashes
$harnessHashes=[ordered]@{}
foreach($name in @('lab.ps1','guest.ps1','test-lds.ps1','reference-lds.ps1','configure-lds.ps1','guest-configure-lds.ps1','guest-configure-lds-tls.ps1','guest-trust-lds-root.ps1','guest-seed-lds.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $harness
    $harnessHashes[$name]=(Get-FileHash -LiteralPath (Join-Path $harness $name)).Hash
}
$binary=Join-Path $resultRoot 'lds.test.exe'
$saved=@{}
foreach($name in @('GOOS','GOARCH','CGO_ENABLED','GOWORK','GOFLAGS')){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
Push-Location $snapshot
try {
    $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0';$env:GOWORK='off';$env:GOFLAGS=''
    $toolchain=(& go version | Out-String).Trim()
    & go test -mod=readonly -trimpath -c -o $binary . *> (Join-Path $resultRoot 'build.log')
    if($LASTEXITCODE -ne 0){throw "LDS test build failed; see $resultRoot\build.log"}
    if(($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-LDSSourceHashes) | ConvertTo-Json -Compress)){throw 'LDS source snapshot changed during build.'}
} finally {foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')};Pop-Location}
$hash=(Get-FileHash -LiteralPath $binary).Hash
$target="C:\ad-sdk-validation\$runId"
$session=$null;$failure=$null;$cleanupFailure=$null;$result=$null
try {
    $session=Wait-LabGuest $client $Credential
    Invoke-Command -Session $session -ArgumentList $target -ScriptBlock {
        param($Directory)
        $ErrorActionPreference='Stop'
        $root='C:\ad-sdk-validation'
        if((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Guest test root is a reparse point.'}
        if(-not ([IO.Path]::GetFullPath($Directory)).StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $Directory)){throw 'Unexpected/existing guest test directory.'}
        $null=New-Item -ItemType Directory -Path $Directory
    }
    Copy-Item -LiteralPath $binary -Destination "$target\lds.test.exe" -ToSession $session
    Write-LabLog "Running native LDS qualification on $($client.name)."
    $result=Invoke-Command -Session $session -FilePath (Join-Path $harness 'reference-lds.ps1') -ArgumentList "$target\lds.test.exe","$target\lds.json",($lds | ConvertTo-Json -Depth 12 -Compress),$reader,$hash | ConvertFrom-Json
    if($result.exit_code -eq 0){Copy-Item -LiteralPath "$target\lds.json" -Destination (Join-Path $resultRoot 'lds.json') -FromSession $session}
    if(-not $result.passed){throw "LDS qualification failed; see $resultRoot"}
} catch {$failure=$_}
finally {if($session){try{Remove-PSSession $session}catch{$cleanupFailure=$_}}}
foreach($name in $harnessHashes.Keys){if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -ne $harnessHashes[$name]){throw 'LDS harness changed during execution.'}}
$passed=$null -eq $failure -and $null -eq $cleanupFailure -and $result -and $result.passed
[ordered]@{schema_version=1;run=$runId;time=[DateTime]::UtcNow.ToString('o');passed=[bool]$passed;image=$LabState.image;lab_id=$LabState.id;fixture_id=$lds.id;source_sha256=$sourceHashes;harness_sha256=$harnessHashes;binary_sha256=$hash;toolchain=$toolchain;reference=$result;session_cleanup_failed=($null -ne $cleanupFailure)} | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $resultRoot 'lds-reference.json') -Encoding UTF8
if($failure -and $cleanupFailure){throw [AggregateException]::new('LDS qualification/session cleanup failed.',[Exception[]]@($failure.Exception,$cleanupFailure.Exception))}
if($failure){throw $failure};if($cleanupFailure){throw $cleanupFailure}
Write-LabLog "LDS qualification passed. Results: $resultRoot"
