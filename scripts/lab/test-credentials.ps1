#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState,[Parameter(Mandatory)][PSCredential]$Credential,[Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
if (-not $LabState.configured) {throw 'Configure the lab before testing.'}
$member=$LabState.machines | Where-Object role -eq 'member'
$dc=$LabState.machines | Where-Object role -eq 'dc1'
$replica=$LabState.machines | Where-Object role -eq 'dc2'
foreach ($machine in @($member,$dc,$replica)) {$null=Get-OwnedVM $machine $LabState}
$source="$($dc.name).$($LabState.domain)"; $destination="$($replica.name).$($LabState.domain)"
$runId='credentials-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$resultRoot=Assert-LabPath (Join-Path $LabRoot "results\$runId")
$snapshot=Join-Path $resultRoot 'source'; $harness=Join-Path $resultRoot 'harness'
$null=New-Item -ItemType Directory -Path $snapshot,$harness
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Copy-Item -LiteralPath (Join-Path $sourceRoot 'go.mod'),(Join-Path $sourceRoot 'go.sum') -Destination $snapshot
Get-ChildItem -LiteralPath $sourceRoot -Filter '*.go' -File | Copy-Item -Destination $snapshot
function Get-CredentialSourceHashes {
    $hashes=[ordered]@{}
    foreach($file in (Get-ChildItem -LiteralPath $snapshot -File | Sort-Object Name)) {$hashes[$file.Name]=(Get-FileHash -LiteralPath $file.FullName).Hash}
    return $hashes
}
$sourceHashes=Get-CredentialSourceHashes
$harnessHashes=[ordered]@{}
foreach($name in @('lab.ps1','guest.ps1','test-credentials.ps1','reference-credentials.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $harness
    $harnessHashes[$name]=(Get-FileHash -LiteralPath (Join-Path $harness $name)).Hash
}
$binary=Join-Path $resultRoot 'credentials.test.exe'
$saved=@{}
foreach($name in @('GOOS','GOARCH','CGO_ENABLED','GOWORK','GOFLAGS')) {$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
Push-Location $snapshot
try {
    $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0';$env:GOWORK='off';$env:GOFLAGS=''
    $toolchain=(& go version | Out-String).Trim()
    & go test -mod=readonly -trimpath -c -o $binary . *> (Join-Path $resultRoot 'build.log')
    if($LASTEXITCODE -ne 0) {throw "Credential test build failed; see $resultRoot\build.log"}
    if(($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-CredentialSourceHashes) | ConvertTo-Json -Compress)) {throw 'Credential source snapshot changed during build.'}
} finally {
    foreach($name in $saved.Keys) {[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
    Pop-Location
}
$hash=(Get-FileHash -LiteralPath $binary).Hash
$target="C:\ad-sdk-validation\$runId"
$session=$null; $failure=$null; $cleanupFailure=$null; $result=$null
try {
    $session=Wait-LabGuest $member $Credential
    Invoke-Command -Session $session -ArgumentList $target -ScriptBlock {
        param($Directory)
        $ErrorActionPreference='Stop'
        $root='C:\ad-sdk-validation'
        if((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Guest test root is a reparse point.'}
        if(-not ([IO.Path]::GetFullPath($Directory)).StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $Directory)) {throw 'Unexpected or existing guest test directory.'}
        $null=New-Item -ItemType Directory -Path $Directory
    }
    Copy-Item -LiteralPath $binary -Destination "$target\credentials.test.exe" -ToSession $session
    Write-LabLog "Running explicit credential qualification against $source."
    $result=Invoke-Command -Session $session -FilePath (Join-Path $harness 'reference-credentials.ps1') -ArgumentList "$target\credentials.test.exe","$target\credentials.json",$source,$destination,$runId,$hash | ConvertFrom-Json
    if($result.exit_code -eq 0) {Copy-Item -LiteralPath "$target\credentials.json" -Destination (Join-Path $resultRoot 'credentials.json') -FromSession $session}
    if(-not $result.passed) {throw "Explicit credential qualification failed; see $resultRoot"}
} catch {$failure=$_}
finally {
    if($session) {try {Remove-PSSession $session} catch {$cleanupFailure=$_}}
}
foreach($name in $harnessHashes.Keys) {
    if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -ne $harnessHashes[$name]) {throw 'Credential harness changed during execution.'}
}
$passed=$null -eq $failure -and $null -eq $cleanupFailure -and $result -and $result.passed
[ordered]@{
    schema_version=1;run=$runId;time=[DateTime]::UtcNow.ToString('o');passed=[bool]$passed;image=$LabState.image;lab_id=$LabState.id
    source_sha256=$sourceHashes;harness_sha256=$harnessHashes;binary_sha256=$hash;toolchain=$toolchain;reference=$result
    session_cleanup_failed=($null -ne $cleanupFailure)
} | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath (Join-Path $resultRoot 'credentials-reference.json') -Encoding UTF8
if($failure -and $cleanupFailure) {throw [AggregateException]::new('Credential qualification and session cleanup failed.',[Exception[]]@($failure.Exception,$cleanupFailure.Exception))}
if($failure) {throw $failure}
if($cleanupFailure) {throw $cleanupFailure}
Write-LabLog "Explicit credential qualification passed. Results: $resultRoot"
