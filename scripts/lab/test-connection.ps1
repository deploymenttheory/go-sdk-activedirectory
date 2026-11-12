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
$harnessRoot = Join-Path $resultRoot 'harness'
$null = New-Item -ItemType Directory -Path $harnessRoot
$harnessHashes = [ordered]@{}
foreach ($name in @('lab.ps1','guest.ps1','test-connection.ps1','test-connection-denial.ps1')) {
    $path = Join-Path $PSScriptRoot $name
    Copy-Item -LiteralPath $path -Destination $harnessRoot
    $harnessHashes[$name] = (Get-FileHash -LiteralPath (Join-Path $harnessRoot $name)).Hash
}
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
        function Convert-RootDSEReferenceValue([string]$Name, $Value) {
            if ($Name -in @('domainControllerFunctionality','domainFunctionality','forestFunctionality')) { return ([int]$Value).ToString([Globalization.CultureInfo]::InvariantCulture) }
            if ($Name -in @('supportedCapabilities','supportedControl','supportedExtension')) {
                if ($Value -is [string]) { return $Value }
                # ADObjectIdentifier.Value is the OID; ToString adds DisplayName.
                $oid = $Value.PSObject.Properties['Value']
                if ($null -eq $oid) { throw 'Unexpected RootDSE OID projection type.' }
                return [string]$oid.Value
            }
            if ($Name -in @('isGlobalCatalogReady','isSynchronized')) { return ([string]$Value).ToUpperInvariant() }
            return [string]$Value
        }
        $properties = @('configurationNamingContext','currentTime','defaultNamingContext','dnsHostName','domainControllerFunctionality','domainFunctionality','dsServiceName','forestFunctionality','highestCommittedUSN','isGlobalCatalogReady','isSynchronized','ldapServiceName','namingContexts','rootDomainNamingContext','schemaNamingContext','serverName','subschemaSubentry','supportedCapabilities','supportedControl','supportedLDAPPolicies','supportedLDAPVersion','supportedSASLMechanisms','supportedExtension')
        $before = Get-ADRootDSE -Server $Server -Properties $properties
        $oldServer = $env:ADSDK_LDAP_SERVER; $oldResult = $env:ADSDK_LDAP_RESULT; $oldTimeout = $env:ADSDK_LDAP_TIMEOUT_HOST
        try {
            $env:ADSDK_LDAP_SERVER=$Server; $env:ADSDK_LDAP_RESULT=Join-Path $Directory 'rootdse.json'
            $env:ADSDK_LDAP_TIMEOUT_HOST='10.77.23.254'
            $ErrorActionPreference = 'Continue'
            $output = @(& $executable '-test.v' '-test.count=1' 2>&1 | ForEach-Object { $_.ToString() })
            $exitCode = $LASTEXITCODE
        } finally { $env:ADSDK_LDAP_SERVER=$oldServer; $env:ADSDK_LDAP_RESULT=$oldResult; $env:ADSDK_LDAP_TIMEOUT_HOST=$oldTimeout; $ErrorActionPreference='Stop' }
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
                    $expected = @($after.$name | ForEach-Object { Convert-RootDSEReferenceValue $name $_ } | Sort-Object)
                    if (($actual -join "`n") -cne ($expected -join "`n")) { throw "RootDSE differs for $name" }
                    $proof.matched_properties += $name
                }
                $usn = [UInt64][Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($native.attributes.highestcommittedusn[0]))
                if ($usn -lt [UInt64]$before.highestCommittedUSN -or $usn -gt [UInt64]$after.highestCommittedUSN) { throw 'USN is outside the before/after reference interval.' }
                $beforeTime = ([DateTimeOffset]([DateTime]$before.currentTime).ToUniversalTime()).ToUnixTimeSeconds()
                $afterTime = ([DateTimeOffset]([DateTime]$after.currentTime).ToUniversalTime()).ToUnixTimeSeconds()
                if ($native.current_time_unix -lt $beforeTime -or $native.current_time_unix -gt $afterTime) { throw 'Current time is outside the before/after reference interval.' }
            } catch { $proof.passed=$false; $proof.comparison_error=$_.Exception.Message }
        }
        $proof | ConvertTo-Json -Depth 8
    } | ConvertFrom-Json
    $denial = $null
    if ($result.passed) { $denial = & (Join-Path $harnessRoot 'test-connection-denial.ps1') -Member $member -AdminSession $session -Server $server -Executable "$target\connection.test.exe" -ExpectedHash $binaryHash -LabId $LabState.id }
    $passed = $result.passed -and $denial -and $denial.passed
    foreach ($name in $harnessHashes.Keys) { if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -ne $harnessHashes[$name]) { throw 'Connection harness changed during execution.' } }
    [ordered]@{schema_version=1;run=$runId;time=[DateTime]::UtcNow.ToString('o');passed=[bool]$passed;image=$LabState.image;lab_id=$LabState.id;source_sha256=$sourceHashes;harness_sha256=$harnessHashes;toolchain=$goVersion;guest=$result;authentication_denial=$denial;scope='Current-identity signed/sealed LDAP RootDSE, selected/wildcard reads, repeat open/read/close, invalid endpoint, bounded wait on an unused private address, untrusted local identity denial with cleanup, and PowerShell property comparison. Broader version qualification remains separate.'} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $resultRoot 'connection-reference.json') -Encoding UTF8
    if ($result.exit_code -eq 0) { Copy-Item -LiteralPath "$target\rootdse.json" -Destination (Join-Path $resultRoot 'rootdse.json') -FromSession $session }
    if (-not $passed) { throw "Connection qualification failed; see $resultRoot" }
    Write-LabLog "Connection tests passed. Results: $resultRoot"
} finally {
    # Retain the uniquely named guest artifact directory for diagnosis. The
    # denial helper owns cleanup of its uniquely marked local fixture account.
    if ($session) { Remove-PSSession $session }
}
