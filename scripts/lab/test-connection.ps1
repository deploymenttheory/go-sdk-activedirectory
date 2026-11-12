#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)]$LabState, [Parameter(Mandatory)][PSCredential]$Credential, [Parameter(Mandatory)][string]$LabRoot)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')
if (-not $LabState.configured) { throw 'Configure the lab before testing.' }
$member = $LabState.machines | Where-Object role -eq 'member'
$dc = $LabState.machines | Where-Object role -eq 'dc1'
$null = Get-OwnedVM $member $LabState
$null = Get-OwnedVM $dc $LabState
$server = "$($dc.name).$($LabState.domain)"
$runId = 'connection-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$resultRoot = Join-Path $LabRoot "results\$runId"
$snapshot = Join-Path $resultRoot 'source'
$null = New-Item -ItemType Directory -Path $snapshot
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Copy-Item -LiteralPath (Join-Path $sourceRoot 'go.mod'), (Join-Path $sourceRoot 'go.sum') -Destination $snapshot
Get-ChildItem -LiteralPath $sourceRoot -Filter '*.go' -File | Copy-Item -Destination $snapshot
function Get-ConnectionSourceHashes {
    $hashes = [ordered]@{}
    foreach ($file in (Get-ChildItem -LiteralPath $snapshot -File | Sort-Object Name)) { $hashes[$file.Name] = (Get-FileHash -LiteralPath $file.FullName).Hash }
    return $hashes
}
$sourceHashes = Get-ConnectionSourceHashes
$binary = Join-Path $resultRoot 'connection.test.exe'
$saved = @{}
foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GOWORK','GOFLAGS')) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location $snapshot
try {
    $env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'; $env:GOWORK='off'; $env:GOFLAGS=''
    $goVersion = (& go version | Out-String).Trim()
    & go test -mod=readonly -trimpath -c -o $binary . *> (Join-Path $resultRoot 'build.log')
    if ($LASTEXITCODE -ne 0) { throw "Connection test build failed; see $resultRoot\build.log" }
    if (($sourceHashes | ConvertTo-Json -Compress) -cne ((Get-ConnectionSourceHashes) | ConvertTo-Json -Compress)) { throw 'Source snapshot changed during the build.' }
} finally {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    Pop-Location
}
$binaryHash = (Get-FileHash -LiteralPath $binary).Hash
$target = "C:\ad-sdk-validation\$runId"
$session = Wait-LabGuest $member $Credential
try {
    Invoke-Command -Session $session -ArgumentList $target -ScriptBlock {
        param($Directory)
        $ErrorActionPreference = 'Stop'
        $root = 'C:\ad-sdk-validation'
        if ((Test-Path -LiteralPath $root) -and ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Test root is a reparse point.' }
        if (-not ([IO.Path]::GetFullPath($Directory)).StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $Directory)) { throw 'Unexpected or existing guest test directory.' }
        $null = New-Item -ItemType Directory -Path $Directory
    }
    Copy-Item -LiteralPath $binary -Destination "$target\connection.test.exe" -ToSession $session
    Write-LabLog "Running native connection tests against $server on $($member.name)."
    $result = Invoke-Command -Session $session -ArgumentList $target, $server, $binaryHash -ScriptBlock {
        param($Directory, $Server, $ExpectedHash)
        $ErrorActionPreference = 'Stop'
        $executable = Join-Path $Directory 'connection.test.exe'
        if ((Get-FileHash -LiteralPath $executable).Hash -ne $ExpectedHash) { throw 'Guest binary hash mismatch.' }
        Import-Module ActiveDirectory
        $properties = @('configurationNamingContext','currentTime','defaultNamingContext','dnsHostName','domainControllerFunctionality','domainFunctionality','dsServiceName','forestFunctionality','highestCommittedUSN','isGlobalCatalogReady','isSynchronized','ldapServiceName','namingContexts','rootDomainNamingContext','schemaNamingContext','serverName','subschemaSubentry','supportedCapabilities','supportedControl','supportedLDAPPolicies','supportedLDAPVersion','supportedSASLMechanisms','supportedExtension')
        $before = Get-ADRootDSE -Server $Server -Properties $properties
        $oldServer = $env:ADSDK_LDAP_SERVER; $oldResult = $env:ADSDK_LDAP_RESULT
        try {
            $env:ADSDK_LDAP_SERVER=$Server; $env:ADSDK_LDAP_RESULT=Join-Path $Directory 'rootdse.json'
            $ErrorActionPreference = 'Continue'
            $output = @(& $executable '-test.v' '-test.count=1' 2>&1 | ForEach-Object { $_.ToString() })
            $exitCode = $LASTEXITCODE
        } finally { $env:ADSDK_LDAP_SERVER=$oldServer; $env:ADSDK_LDAP_RESULT=$oldResult; $ErrorActionPreference='Stop' }
        $build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $proof = [ordered]@{passed=($exitCode -eq 0);exit_code=$exitCode;output=$output;binary_sha256=$ExpectedHash;server=$Server;build="$($build.CurrentBuild).$($build.UBR)";architecture=$env:PROCESSOR_ARCHITECTURE;powershell=$PSVersionTable.PSVersion.ToString();ad_module=(Get-Module ActiveDirectory).Version.ToString();matched_properties=@();comparison_error=$null}
        if ($exitCode -eq 0) {
            try {
                $after = Get-ADRootDSE -Server $Server -Properties $properties
                $native = Get-Content -LiteralPath (Join-Path $Directory 'rootdse.json') -Raw | ConvertFrom-Json
                foreach ($name in $properties) {
                    if ($name -in @('currentTime','highestCommittedUSN')) { continue }
                    $encoded = @($native.selected_attributes.($name.ToLowerInvariant()))
                    $actual = @($encoded | ForEach-Object { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)) } | Sort-Object)
                    $expected = @($after.$name | ForEach-Object { ([string]$_) } | Sort-Object)
                    if (($actual -join "`n") -cne ($expected -join "`n")) { throw "RootDSE differs for $name" }
                    $proof.matched_properties += $name
                }
                $usn = [UInt64][Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($native.attributes.highestcommittedusn[0]))
                if ($usn -lt [UInt64]$before.highestCommittedUSN -or $usn -gt [UInt64]$after.highestCommittedUSN) { throw 'USN is outside the before/after reference interval.' }
            } catch { $proof.passed=$false; $proof.comparison_error=$_.Exception.Message }
        }
        $proof | ConvertTo-Json -Depth 8
    } | ConvertFrom-Json
    [ordered]@{schema_version=1;run=$runId;time=[DateTime]::UtcNow.ToString('o');passed=$result.passed;image=$LabState.image;lab_id=$LabState.id;source_sha256=$sourceHashes;toolchain=$goVersion;guest=$result;scope='Current-identity signed/sealed LDAP RootDSE, selected/wildcard reads, repeat open/read/close, invalid endpoint, and PowerShell property comparison. Authentication-denial and broader version qualification remain separate.'} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $resultRoot 'connection-reference.json') -Encoding UTF8
    if ($result.exit_code -eq 0) { Copy-Item -LiteralPath "$target\rootdse.json" -Destination (Join-Path $resultRoot 'rootdse.json') -FromSession $session }
    if (-not $result.passed) { throw "Connection qualification failed; see $resultRoot" }
    Write-LabLog "Connection tests passed. Results: $resultRoot"
} finally {
    # Retain the uniquely named guest artifact directory for diagnosis. No AD
    # objects or accounts are created by this read-only qualification.
    if ($session) { Remove-PSSession $session }
}
