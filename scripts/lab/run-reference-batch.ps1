#Requires -Version 5.1
#Requires -RunAsAdministrator
# Runs the read-only reference collectors that have never been captured, inside
# the lab member guest, and brings the artifacts back. One elevated run.
#
#   reference-directory         : core + topology profiles (issues #16-#20, #78)
#   reference-optional-features : feature discovery and flag bits (issue #29)
#
# Both collectors are read-only: every directory call is a Get-AD* and no
# mutation gate is passed. The owned disposable ad.sdk.test domain is unchanged.
[CmdletBinding()]
param(
    [string]$Repo = 'C:\Users\Dafydd\github\sdk\go-sdk-activedirectory',
    [string]$LabRoot = 'H:\ad-sdk-lab\server2025',
    [string]$HostResultRoot = 'H:\ad-sdk-lab\captures'
)
$ErrorActionPreference = 'Stop'
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$runRoot = Join-Path $HostResultRoot "$stamp-reference"
$null = New-Item -ItemType Directory -Path $runRoot -Force
Start-Transcript -LiteralPath (Join-Path $runRoot 'driver.log') -Force | Out-Null
$session = $null
try {
    Set-Location -LiteralPath $Repo
    . (Join-Path $Repo 'scripts\lab\guest.ps1')
    $state = Get-Content -LiteralPath (Join-Path $LabRoot 'state.json') -Raw | ConvertFrom-Json
    if (-not $state.configured) { throw 'Lab is not configured; run lab.ps1 -Action Configure first.' }
    $saved = Import-Clixml -LiteralPath (Join-Path $LabRoot 'credential.clixml')
    $domainCred = [PSCredential]::new("$($state.netbios)\Administrator", $saved.Password)
    $member = $state.machines | Where-Object role -eq 'member'
    $dc1 = $state.machines | Where-Object role -eq 'dc1'
    $commit = (& git -C $Repo rev-parse HEAD).Trim()
    Write-Host "lab_id=$($state.id) domain=$($state.domain) member=$($member.name) dc1=$($dc1.name) commit=$commit"

    $session = Wait-LabGuest $member @($domainCred)
    Write-Host '--- guest session established ---'
    $guestDir = 'C:\adsdk-refcap'
    Invoke-Command -Session $session -ArgumentList $guestDir -ScriptBlock {
        param($dir)
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
        $null = New-Item -ItemType Directory -Path $dir
    }
    foreach ($file in @('directory-harness.ps1', 'reference-directory.ps1', 'reference-optional-features.ps1')) {
        $source = Join-Path (Join-Path $Repo 'scripts\lab') $file
        Copy-Item -LiteralPath $source -Destination (Join-Path $guestDir $file) -ToSession $session -Force
    }

    # Identity facts come from the directory itself, not from assumptions.
    $facts = Invoke-Command -Session $session -ArgumentList $dc1.name, $state.domain -ScriptBlock {
        param($dc, $domain)
        $env:ADPS_LoadDefaultDrive = '0'
        Import-Module ActiveDirectory -ErrorAction Stop
        $fqdn = "$dc.$domain"
        $root = Get-ADRootDSE -Server $fqdn
        $dom = Get-ADDomain -Identity $root.defaultNamingContext -Server $fqdn
        $config = Get-ADObject -Identity $root.configurationNamingContext -Server $fqdn -Properties objectGUID
        [pscustomobject]@{
            server          = $fqdn
            domain_dns      = $dom.DNSRoot
            domain_guid     = $dom.ObjectGUID.ToString()
            config_guid     = $config.ObjectGUID.ToString()
            client_computer = $env:COMPUTERNAME
            module          = (Get-Module ActiveDirectory).Version.ToString()
            trust_count     = @(Get-ADTrust -LDAPFilter '(objectClass=trustedDomain)' -Server $fqdn).Count
        }
    }
    $facts | Format-List | Out-String | Write-Host
    $facts | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $runRoot 'guest-facts.json') -Encoding UTF8

    # The harness validates this manifest strictly; every field is observed above.
    $fixtureId = "lab-$($state.id)"
    $manifestGuest = Join-Path $guestDir 'fixture.json'
    Invoke-Command -Session $session -ArgumentList $manifestGuest, $fixtureId, $facts, $state.server_version -ScriptBlock {
        param($path, $id, $f, $version)
        $manifest = [ordered]@{
            schema_version  = 1
            purpose         = 'go-sdk-activedirectory-isolated-lab'
            fixture_id      = $id
            domain_dns      = $f.domain_dns
            domain_guid     = $f.domain_guid
            server          = $f.server
            client_computer = $f.client_computer
            server_version  = $version
            trust_partners  = @()
        }
        $json = ($manifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine
        [IO.File]::WriteAllText($path, $json, [Text.UTF8Encoding]::new($false))
    }
    Write-Host "--- fixture manifest written: $manifestGuest (fixture_id=$fixtureId) ---"

    $summary = @()
    # Runs one guest collector and copies whatever it produced, whether or not
    # the collector itself succeeded.
    function Invoke-Capture([string]$Name, [string]$Script, [hashtable]$Parameters, [string]$GuestResult) {
        Write-Host "--- $Name ---"
        $record = [ordered]@{ name = $Name; script = $Script; outcome = 'not_run'; output = @() }
        try {
            $record.output = @(Invoke-Command -Session $session -ArgumentList $guestDir, $Script, $Parameters -ScriptBlock {
                    param($dir, $script, $splat)
                    & (Join-Path $dir $script) @splat 2>&1
                } | ForEach-Object { "$_" })
            $record.outcome = 'ran'
        }
        catch {
            $record.outcome = 'error'
            $record.output = @(($_ | Out-String))
        }
        $record.output | ForEach-Object { Write-Host "    $_" }
        $local = Join-Path $runRoot $Name
        try {
            if (Invoke-Command -Session $session -ArgumentList $GuestResult -ScriptBlock { param($p) Test-Path $p }) {
                $null = New-Item -ItemType Directory -Path $local -Force
                Copy-Item -Path (Join-Path $GuestResult '*') -Destination $local -FromSession $session -Recurse -Force
                Write-Host "    artifacts -> $local"
            }
            else { Write-Host '    no artifact directory produced' }
        }
        catch { Write-Host "    artifact copy failed: $($_.Exception.Message)" }
        return $record
    }

    foreach ($profileName in @('core', 'topology')) {
        $runId = "directory-$stamp-$profileName"
        $runDir = Join-Path $guestDir $runId
        # Assert-DirectoryRun requires the directory leaf to equal the run id and
        # an owner.json naming the same run and fixture.
        Invoke-Command -Session $session -ArgumentList $runDir, $runId, $fixtureId -ScriptBlock {
            param($dir, $id, $fixture)
            $null = New-Item -ItemType Directory -Path $dir -Force
            $owner = [ordered]@{ purpose = 'go-sdk-activedirectory-directory-run'; run_id = $id; fixture_id = $fixture }
            $json = ($owner | ConvertTo-Json -Depth 4) + [Environment]::NewLine
            [IO.File]::WriteAllText((Join-Path $dir 'owner.json'), $json, [Text.UTF8Encoding]::new($false))
        }
        $parameters = @{
            FixtureManifest = $manifestGuest
            RunDirectory    = $runDir
            RunID           = $runId
            SDKRevision     = $commit
            Profile         = $profileName
        }
        $summary += Invoke-Capture "directory-$profileName" 'reference-directory.ps1' $parameters $runDir
    }

    # SDK-side differential. TestDirectoryProjectionLab re-reads the reference
    # the core collector just produced, pins it by SHA-256, dials the same
    # endpoint natively and compares the SDK's own projection fact by fact. The
    # reference is read from the guest copy the collector wrote, so the hash is
    # computed over exactly the bytes the test consumes.
    $coreRunId = "directory-$stamp-core"
    $coreReference = Join-Path (Join-Path $guestDir $coreRunId) 'reference.json'
    $testBinaryLocal = Join-Path $runRoot 'adsdk-directory.test.exe'
    Write-Host '--- building the package test binary for the guest ---'
    & go test -c -o $testBinaryLocal . 2>&1 | ForEach-Object { Write-Host "    go: $_" }
    if (-not (Test-Path $testBinaryLocal)) {
        Write-Host '    test binary build failed; skipping the differential'
    }
    else {
        $testBinaryGuest = Join-Path $guestDir 'adsdk-directory.test.exe'
        Copy-Item -LiteralPath $testBinaryLocal -Destination $testBinaryGuest -ToSession $session -Force
        $differentialDir = Join-Path $guestDir 'differential'
        $resultGuest = Join-Path $differentialDir 'result.json'
        Write-Host '--- directory-differential ---'
        $record = [ordered]@{ name = 'directory-differential'; script = 'TestDirectoryProjectionLab'; outcome = 'not_run'; output = @() }
        try {
            $record.output = @(Invoke-Command -Session $session `
                    -ArgumentList $testBinaryGuest, $coreReference, $coreRunId, $resultGuest, $differentialDir `
                    -ScriptBlock {
                    param($exe, $reference, $runId, $result, $dir)
                    $null = New-Item -ItemType Directory -Path $dir -Force
                    $sha256 = [Security.Cryptography.SHA256]::Create()
                    try {
                        $digest = $sha256.ComputeHash([IO.File]::ReadAllBytes($reference))
                    }
                    finally { $sha256.Dispose() }
                    $env:ADSDK_DIRECTORY_REFERENCE = $reference
                    $env:ADSDK_DIRECTORY_REFERENCE_SHA256 = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant()
                    $env:ADSDK_DIRECTORY_RUN_ID = $runId
                    $env:ADSDK_DIRECTORY_RESULT = $result
                    try {
                        & $exe '-test.run' '^TestDirectoryProjectionLab$' '-test.v' 2>&1
                        "exit_code=$LASTEXITCODE"
                    }
                    finally {
                        Remove-Item Env:ADSDK_DIRECTORY_REFERENCE, Env:ADSDK_DIRECTORY_REFERENCE_SHA256, `
                            Env:ADSDK_DIRECTORY_RUN_ID, Env:ADSDK_DIRECTORY_RESULT -ErrorAction SilentlyContinue
                    }
                } | ForEach-Object { "$_" })
            $record.outcome = 'ran'
        }
        catch {
            $record.outcome = 'error'
            $record.output = @(($_ | Out-String))
        }
        $record.output | ForEach-Object { Write-Host "    $_" }
        $local = Join-Path $runRoot 'directory-differential'
        try {
            if (Invoke-Command -Session $session -ArgumentList $differentialDir -ScriptBlock { param($p) Test-Path $p }) {
                $null = New-Item -ItemType Directory -Path $local -Force
                Copy-Item -Path (Join-Path $differentialDir '*') -Destination $local -FromSession $session -Recurse -Force
                Write-Host "    artifacts -> $local"
            }
            else { Write-Host '    no differential artifact produced' }
        }
        catch { Write-Host "    artifact copy failed: $($_.Exception.Message)" }
        $summary += $record
    }

    $featureDir = Join-Path $guestDir 'optional-features'
    Invoke-Command -Session $session -ArgumentList $featureDir -ScriptBlock {
        param($dir)
        $null = New-Item -ItemType Directory -Path $dir -Force
    }
    $parameters = @{
        Server            = $facts.server
        ConfigurationGUID = $facts.config_guid
        OutputPath        = (Join-Path $featureDir 'reference.json')
    }
    $summary += Invoke-Capture 'optional-features' 'reference-optional-features.ps1' $parameters $featureDir

    $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runRoot 'summary.json') -Encoding UTF8
    Invoke-Command -Session $session -ArgumentList $guestDir -ScriptBlock {
        param($dir)
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    }
    Write-Host "--- REFERENCE BATCH DONE: $runRoot ---"
}
catch {
    Write-Host '--- DRIVER FAILED ---'
    Write-Host ($_ | Out-String)
    Write-Host ($_.ScriptStackTrace | Out-String)
}
finally {
    if ($session) { Remove-PSSession $session }
    Stop-Transcript | Out-Null
}
