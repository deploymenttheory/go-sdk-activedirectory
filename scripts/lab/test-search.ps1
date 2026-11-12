#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState,[Parameter(Mandatory)][PSCredential]$Credential,[Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
if (-not $LabState.configured) { throw 'Configure the lab before testing search.' }
$member=$LabState.machines | Where-Object role -eq 'member'
$dc=$LabState.machines | Where-Object role -eq 'dc1'
$replica=$LabState.machines | Where-Object role -eq 'dc2'
foreach ($machine in @($member,$dc,$replica)) { $null=Get-OwnedVM $machine $LabState }
$server="$($dc.name).$($LabState.domain)"; $destination="$($replica.name).$($LabState.domain)"
$runId='search-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$resultRoot=Assert-LabPath (Join-Path $LabRoot "results\$runId")
$snapshot=Join-Path $resultRoot 'source'; $harness=Join-Path $resultRoot 'harness'
$null=New-Item -ItemType Directory -Path $snapshot,$harness
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$sourceHashes=[ordered]@{}; $harnessHashes=[ordered]@{}; $binaryHash=$null; $toolchain=$null
$session=$null; $failure=$null; $sessionCleanupFailure=$null; $copyErrors=@(); $reference=$null; $phase='snapshot'
$dcSession=$null; $sourceDCEnvironment=$null; $dcSessionCleanupFailure=$null
$binary=Join-Path $resultRoot 'search.test.exe'
$target="C:\ad-sdk-validation\$runId"
function Get-SearchSourceHashes {
    $hashes=[ordered]@{}
    foreach ($file in (Get-ChildItem -LiteralPath $snapshot -File | Sort-Object Name)) { $hashes[$file.Name]=(Get-FileHash -LiteralPath $file.FullName).Hash }
    return $hashes
}
try {
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'go.mod'),(Join-Path $sourceRoot 'go.sum') -Destination $snapshot
    Get-ChildItem -LiteralPath $sourceRoot -Filter '*.go' -File | Copy-Item -Destination $snapshot
    $sourceHashes=Get-SearchSourceHashes
    foreach ($name in @('lab.ps1','guest.ps1','test-search.ps1','reference-search.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $harness
        $harnessHashes[$name]=(Get-FileHash -LiteralPath (Join-Path $harness $name)).Hash
    }
    $phase='build'
    $saved=@{}
    foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GOWORK','GOFLAGS')) { $saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
    Push-Location $snapshot
    try {
        $env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'; $env:GOWORK='off'; $env:GOFLAGS=''
        $toolchain=(& go version | Out-String).Trim()
        & go test -mod=readonly -trimpath -c -o $binary . *> (Join-Path $resultRoot 'build.log')
        if ($LASTEXITCODE -ne 0) { throw 'Search test build failed; inspect build.log.' }
    } finally {
        foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
        Pop-Location
    }
    if (($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-SearchSourceHashes) | ConvertTo-Json -Compress)) { throw 'Search source snapshot changed during build.' }
    $binaryHash=(Get-FileHash -LiteralPath $binary).Hash
    $phase='source-dc-environment'
    # PowerShell Direct targets the already ownership-checked source VM ID.
    # Its running OS is distinct from both the member and the source ISO.
    $dcSession=Wait-LabGuest $dc $Credential
    $sourceDCEnvironment=Invoke-Command -Session $dcSession -ArgumentList $dc.name -ScriptBlock {
        param($ExpectedName)
        $ErrorActionPreference='Stop'
        if ($env:COMPUTERNAME -ine $ExpectedName) { throw 'Source DC session returned an unexpected computer identity.' }
        $os=Get-CimInstance Win32_OperatingSystem
        $build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $module=Get-Module -ListAvailable -Name ActiveDirectory | Sort-Object Version -Descending | Select-Object -First 1
        [ordered]@{
            computer_name=$env:COMPUTERNAME;timestamp=[DateTime]::UtcNow.ToString('o')
            os_caption=$os.Caption;os_version=$os.Version;os_build=$os.BuildNumber;os_revision=$build.UBR
            os_full_build="$($os.BuildNumber).$($build.UBR)";architecture=$os.OSArchitecture
            powershell_version=$PSVersionTable.PSVersion.ToString()
            active_directory_module_version=$(if ($module) {$module.Version.ToString()} else {$null})
        }
    }
    $phase='guest-setup'
    $session=Wait-LabGuest $member $Credential
    Invoke-Command -Session $session -ArgumentList $target -ScriptBlock {
        param($Directory)
        $ErrorActionPreference='Stop'
        $root='C:\ad-sdk-validation'
        if ((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Guest search test root is a reparse point.' }
        if (-not ([IO.Path]::GetFullPath($Directory)).StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $Directory)) { throw 'Unexpected or existing guest search test directory.' }
        $null=New-Item -ItemType Directory -Path $Directory
    }
    Copy-Item -LiteralPath $binary -Destination "$target\search.test.exe" -ToSession $session
    $phase='search-qualification'
    Write-LabLog "Running search qualification against $server; cleanup is verified on $destination."
    Invoke-Command -Session $session -FilePath (Join-Path $harness 'reference-search.ps1') -ArgumentList "$target\search.test.exe","$target\search.json",$server,$binaryHash,$destination,$runId
} catch { $failure=$_ }
finally {
    if ($session) {
        # Pull every artifact that exists even when the guest harness throws.
        foreach ($name in @('search.json','search.json.reference.json','search.json.permission.json')) {
            try {
                $guestPath="$target\$name"
                $exists=Invoke-Command -Session $session -ArgumentList $guestPath -ScriptBlock { param($Path) Test-Path -LiteralPath $Path -PathType Leaf }
                if ($exists) { Copy-Item -LiteralPath $guestPath -Destination (Join-Path $resultRoot $name) -FromSession $session }
            } catch { $copyErrors+=@($_.Exception.GetType().FullName) }
        }
        try { Remove-PSSession $session } catch { $sessionCleanupFailure=$_ }
    }
    if ($dcSession) {
        try { Remove-PSSession $dcSession } catch { $dcSessionCleanupFailure=$_ }
    }
    foreach ($name in $harnessHashes.Keys) {
        try {
            if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -ne $harnessHashes[$name]) { throw 'Search harness changed during execution.' }
        } catch { if (-not $failure) { $failure=$_ } }
    }
    $referencePath=Join-Path $resultRoot 'search.json.reference.json'
    try {
        if (Test-Path -LiteralPath $referencePath) { $reference=Get-Content -LiteralPath $referencePath -Raw | ConvertFrom-Json }
    } catch { if (-not $failure) { $failure=$_ } }
    $passed=$null -eq $failure -and $null -eq $sessionCleanupFailure -and $null -eq $dcSessionCleanupFailure -and $sourceDCEnvironment -and $copyErrors.Count -eq 0 -and $reference -and $reference.PSObject.Properties['passed'] -and $reference.passed
    [ordered]@{
        schema_version=1;run=$runId;timestamp=[DateTime]::UtcNow.ToString('o');passed=[bool]$passed;image=$LabState.image;lab_id=$LabState.id
        source_sha256=$sourceHashes;harness_sha256=$harnessHashes;binary_sha256=$binaryHash;toolchain=$toolchain
        server=$server;destination=$destination;member_vm_id=$member.id;dc1_vm_id=$dc.id;dc2_vm_id=$replica.id
        source_dc_environment=$sourceDCEnvironment;member_reference=$reference
        failure_phase=$(if ($failure) {$phase} else {$null});failure_type=$(if ($failure) {$failure.Exception.GetType().FullName} else {$null})
        session_cleanup_failed=($null -ne $sessionCleanupFailure);dc_session_cleanup_failed=($null -ne $dcSessionCleanupFailure);artifact_copy_errors=$copyErrors
    } | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath (Join-Path $resultRoot 'search-reference.json') -Encoding UTF8
}
$failures=@()
foreach ($record in @($failure,$sessionCleanupFailure,$dcSessionCleanupFailure)) { if ($record) { $failures+=@($record.Exception) } }
if ($failures.Count -gt 1) { throw [AggregateException]::new('Search qualification and session cleanup failed.',[Exception[]]$failures) }
if ($failures.Count -eq 1) { throw $failures[0] }
if (-not $passed) { throw "Search qualification failed; see $resultRoot" }
Write-LabLog "Search qualification passed. Results: $resultRoot"
