#Requires -Version 5.1
# Offline only: fake the external AD cmdlet boundary; never import AD or connect.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ArtifactRoot)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$global:optionalFeatureOffline=@{}
$root=[IO.Path]::GetFullPath($ArtifactRoot)
if (-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Use an existing offline artifact directory.'}
$run=Join-Path $root ('optional-feature-reference-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $run
$global:optionalFeatureOffline.configurationGUID=[guid]'11111111-2222-3333-4455-66778899aabb'
$global:optionalFeatureOffline.featureGUID=[guid]'766ddcd8-acd0-445e-f3b9-a7f9b6744f2a'
$global:optionalFeatureOffline.configDN='CN=Configuration,DC=example,DC=test'
$global:optionalFeatureOffline.featureDN='CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,'+$global:optionalFeatureOffline.configDN
$global:optionalFeatureOffline.rawFeature=[pscustomobject]@{DistinguishedName=$global:optionalFeatureOffline.featureDN;ObjectGUID=$global:optionalFeatureOffline.featureGUID;'msDS-OptionalFeatureGUID'=$global:optionalFeatureOffline.featureGUID.ToByteArray();'msDS-OptionalFeatureFlags'=1;'msDS-RequiredForestBehaviorVersion'=4;'msDS-EnabledFeatureBL'=@('CN=Partitions,'+$global:optionalFeatureOffline.configDN)}
$global:optionalFeatureOffline.calls=0
function Assert-Endpoint($Server) {if ($Server -cne 'dc.example.test') {throw 'Unpinned endpoint.'};$global:optionalFeatureOffline.calls++}
function Import-Module {param($Name,$ErrorAction) if ($Name -cne 'ActiveDirectory' -or $env:ADPS_LoadDefaultDrive -cne '0') {throw 'Implicit AD drive was permitted.'}}
function Get-Module {param($Name) return [pscustomobject]@{Version=[version]'1.0.1.0'}}
function Get-CimInstance {param($ClassName) return [pscustomobject]@{Caption='Offline fixture';Version='0';BuildNumber='0'}}
function Get-ADRootDSE {param($Server,$ErrorAction) Assert-Endpoint $Server;return [pscustomobject]@{configurationNamingContext=$global:optionalFeatureOffline.configDN;domainControllerFunctionality=10;forestFunctionality=10}}
function Get-ADObject {param($Identity,$Server,$Properties,$ErrorAction) Assert-Endpoint $Server;if ($Identity -ceq $global:optionalFeatureOffline.configDN) {return [pscustomobject]@{ObjectGUID=$global:optionalFeatureOffline.configurationGUID}};if ($Identity -ceq $global:optionalFeatureOffline.featureDN) {return $global:optionalFeatureOffline.rawFeature};throw 'Unexpected identity.'}
function Get-ADOptionalFeature {param($Filter,$Server,$ErrorAction) Assert-Endpoint $Server;if ($Filter -cne '*') {throw 'Unexpected filter.'};return [pscustomobject]@{ObjectGUID=$global:optionalFeatureOffline.featureGUID;FeatureGUID=$global:optionalFeatureOffline.featureGUID;DistinguishedName=$global:optionalFeatureOffline.featureDN;IsDisableable=$false}}
$native=[ordered]@{Complete=$true;LimitReached=$false;Observation=[ordered]@{Source=[ordered]@{Host='dc.example.test';Port=389};RootDSE=[ordered]@{ConfigurationNamingContext=$global:optionalFeatureOffline.configDN}};Features=@([ordered]@{DistinguishedName=$global:optionalFeatureOffline.featureDN;FeatureGUID=$global:optionalFeatureOffline.featureGUID.ToString('D');Flags=1;Disablable=$false;RequiredForestLevel=4;RequiredDomainLevel=$null;EnabledScopes=@('CN=Partitions,'+$global:optionalFeatureOffline.configDN);EnabledScopesState=2})}
$checks=0
foreach ($mode in @('positive','wrong-guid','wrong-flags','wrong-level','wrong-scope','wrong-endpoint','incomplete','ranged','duplicate','missing-to-zero')) {
    $value=$native | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    switch ($mode) {
        'wrong-guid' {$value.Features[0].FeatureGUID=$global:optionalFeatureOffline.configurationGUID.ToString('D')}
        'wrong-flags' {$value.Features[0].Flags=5}
        'wrong-level' {$value.Features[0].RequiredForestLevel=3}
        'wrong-scope' {$value.Features[0].EnabledScopes=@('CN=other')}
        'wrong-endpoint' {$value.Observation.Source.Host='foreign.example.test'}
        'incomplete' {$value.Complete=$false}
        'ranged' {$value.Features[0].EnabledScopesState=3}
        'duplicate' {$value.Features+=@($value.Features[0])}
        'missing-to-zero' {$value.Features[0].RequiredDomainLevel=0}
    }
    $inputPath=Join-Path $run ($mode+'-native.json');$outputPath=Join-Path $run ($mode+'-reference.json')
    [IO.File]::WriteAllText($inputPath,($value | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    $failed=$false
    try {& (Join-Path $PSScriptRoot 'reference-optional-features.ps1') -Server 'dc.example.test' -ConfigurationGUID $global:optionalFeatureOffline.configurationGUID -OutputPath $outputPath -NativeJSON $inputPath | Out-Null} catch {$failed=$true}
    $artifact=Get-Content -LiteralPath $outputPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $checks++
    if ($mode -eq 'positive') {if ($failed -or -not $artifact.passed -or -not $artifact.comparison_passed) {throw ('Positive offline differential failed: '+($artifact | ConvertTo-Json -Depth 8 -Compress))}}
    elseif (-not $failed -or $artifact.passed -or $artifact.comparison_passed) {throw ('Accepted invalid differential: '+$mode)}
}
if ($global:optionalFeatureOffline.calls -ne 40) {throw 'Unexpected external read count.'}
Write-Output "Optional-feature reference offline checks passed: $checks; retained $run"
