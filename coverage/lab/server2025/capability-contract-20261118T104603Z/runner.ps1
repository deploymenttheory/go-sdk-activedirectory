[CmdletBinding()]
param(
    [string]$Repo = 'C:\Users\Dafydd\github\sdk\go-sdk-activedirectory',
    [string]$LabRoot = 'H:\ad-sdk-lab\server2025'
)
$ErrorActionPreference = 'Stop'
$runID = 'capability-contract-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$captureRoot = [IO.Path]::GetFullPath('H:\ad-sdk-lab\captures')
$runRoot = [IO.Path]::GetFullPath((Join-Path $captureRoot $runID))
if (-not $runRoot.StartsWith($captureRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Capture escaped its root.' }
if (Test-Path -LiteralPath $runRoot) { throw 'A fresh capture directory is required.' }
$null = New-Item -ItemType Directory -Path $runRoot
$session = $null
try {
    Set-Location -LiteralPath $Repo
    . (Join-Path $Repo 'scripts\lab\source-snapshot.ps1')
    $snapshot = Join-Path $runRoot 'source'
    $null = New-Item -ItemType Directory -Path $snapshot
    Copy-SDKSourceSnapshot -SourceRoot $Repo -SnapshotRoot $snapshot
    $sourceHashes = Get-SDKSnapshotHashes -Directory $snapshot
    $sourceHashes | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runRoot 'source-hashes.json') -Encoding utf8
    $binary = Join-Path $runRoot 'capability.test.exe'
    & go test -c -o $binary ./activedirectory/acceptance
    if ($LASTEXITCODE -ne 0) { throw 'Test binary compilation failed.' }
    $binaryHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    $state = Get-Content -LiteralPath (Join-Path $LabRoot 'state.json') -Raw | ConvertFrom-Json
    if (-not $state.configured -or $state.domain -ne 'ad.sdk.test') { throw 'Expected configured isolated AD lab.' }
    $member = $state.machines | Where-Object role -eq 'member'
    $dc = $state.machines | Where-Object role -eq 'dc1'
    $saved = Import-Clixml -LiteralPath (Join-Path $LabRoot 'credential.clixml')
    $credential = [PSCredential]::new("$($state.netbios)\Administrator", $saved.Password)
    $session = New-PSSession -VMId ([guid]$member.id) -Credential $credential
    $guestRoot = 'C:\adsdk-qualification\' + $runID
    Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
        param($directory)
        if (Test-Path -LiteralPath $directory) { throw 'Guest capture must be fresh.' }
        $null = New-Item -ItemType Directory -Path $directory
    }
    $guestBinary = Join-Path $guestRoot 'capability.test.exe'
    Copy-Item -LiteralPath $binary -Destination $guestBinary -ToSession $session
    $facts = Invoke-Command -Session $session -ArgumentList $guestRoot, $guestBinary, $binaryHash, "$($dc.name).$($state.domain)", $runID -ScriptBlock {
        param($directory, $executable, $expectedHash, $endpoint, $identity)
        $ErrorActionPreference = 'Stop'
        if ((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Guest executable hash mismatch.' }
        Import-Module ActiveDirectory -ErrorAction Stop
        $root = Get-ADRootDSE -Server $endpoint
        $domain = Get-ADDomain -Identity $root.defaultNamingContext -Server $endpoint
        if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'Directory identity mismatch.' }
        $controller = Get-ADDomainController -Identity $endpoint -Server $endpoint
        $env:ADSDK_CAPABILITY_ENDPOINT = $endpoint
        $env:ADSDK_CAPABILITY_RUN_ID = $identity
        $env:ADSDK_CAPABILITY_RESULT = Join-Path $directory 'result.json'
        try {
            $output = @(& $executable '-test.run' '^TestDirectoryCapabilitySweepLab$' '-test.v' '-test.timeout' '15m' 2>&1 | ForEach-Object { "$_" })
            $testExit = $LASTEXITCODE
            $output | Set-Content -LiteralPath (Join-Path $directory 'test-output.txt') -Encoding utf8
            if ($testExit -ne 0) { throw "Capability test failed with exit $testExit" }
        } finally {
            Remove-Item Env:ADSDK_CAPABILITY_ENDPOINT,Env:ADSDK_CAPABILITY_RUN_ID,Env:ADSDK_CAPABILITY_RESULT -ErrorAction SilentlyContinue
        }
        $result = Get-Content -LiteralPath (Join-Path $directory 'result.json') -Raw | ConvertFrom-Json
        $applicable = @($result.operations | Where-Object has_directory_prerequisite)
        if (-not $result.passed -or $applicable.Count -ne 12) { throw 'Incomplete capability sweep.' }
        foreach ($operation in $applicable) {
            if (-not $operation.passed -or $operation.unsupported_capability_error_kind -cne 'DirectoryCapabilityError') {
                throw "Imprecise refusal for $($operation.cmdlet)"
            }
        }
        [pscustomobject]@{
            run_id=$identity; endpoint=$endpoint; server_version=$controller.OperatingSystem
            server_build=$controller.OperatingSystemVersion; host_version=[Environment]::OSVersion.VersionString
            module_version=(Get-Module ActiveDirectory).Version.ToString(); binary_sha256=$expectedHash
            applicable_operations=$applicable.Count; all_refusals_typed=$true; directory_writes=$false
        }
    }
    foreach ($file in @('result.json','test-output.txt')) {
        Copy-Item -LiteralPath (Join-Path $guestRoot $file) -Destination (Join-Path $runRoot $file) -FromSession $session
    }
    $facts | Add-Member -NotePropertyName base_revision -NotePropertyValue ((& git rev-parse HEAD).Trim())
    $facts | Add-Member -NotePropertyName source_dirty -NotePropertyValue $true
    $facts | Add-Member -NotePropertyName go_version -NotePropertyValue ((& go version) -join '')
    $facts | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runRoot 'qualification.json') -Encoding utf8
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $runRoot 'runner.ps1')
    Write-Output "PASS: $runID; 12 precise capability refusals; no directory writes; artifacts=$runRoot"
} finally {
    if ($session) { Remove-PSSession $session }
}
