#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][guid]$ConfigurationGUID,
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$NativeJSON
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'directory-harness.ps1')
if ($Server -notmatch '\A[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?\z' -or $ConfigurationGUID -eq [guid]::Empty) {throw 'Explicit endpoint and provisioned configuration GUID are required.'}
$destination=Assert-DirectoryPlainPath $OutputPath $false
if (Test-Path -LiteralPath $destination) {throw 'Reference output already exists.'}
function Get-OptionalProperty($Object,[string]$Name) {
    $names=$Object.PSObject.Properties['PropertyNames']
    if ($names -and $Name -notin @($names.Value)) {return $null}
    $property=$Object.PSObject.Properties[$Name];if ($property) {return $property.Value};return $null
}
function ConvertTo-OptionalGUID($Value) {
    if ($null -eq $Value) {return $null}
    if ($Value -is [Array]) {
        if (@($Value).Count -ne 16 -or @($Value | Where-Object {$_ -isnot [byte]}).Count) {throw 'Invalid binary feature GUID.'}
        return ([guid]::new([byte[]]$Value)).ToString('D')
    }
    return ([guid]$Value).ToString('D')
}
$artifact=[ordered]@{schema_version=1;purpose='go-sdk-activedirectory-optional-feature-reference';server=$Server;configuration_guid=$ConfigurationGUID.ToString('D');started=[DateTime]::UtcNow.ToString('o');finished=$null;passed=$false;full_ticket_complete=$false;features=@();comparison_performed=$false;comparison_passed=$false;failure_type=$null;failure_id=$null;failure_line=$null;environment=$null}
$old=$env:ADPS_LoadDefaultDrive;$failure=$null
try {
    $env:ADPS_LoadDefaultDrive='0';Import-Module ActiveDirectory -ErrorAction Stop
    $root=Get-ADRootDSE -Server $Server -ErrorAction Stop
    $config=Get-ADObject -Identity $root.configurationNamingContext -Server $Server -Properties objectGUID -ErrorAction Stop
    if ($config.ObjectGUID -ne $ConfigurationGUID) {throw 'Configuration identity differs from the pinned fixture.'}
    $properties=@('msDS-OptionalFeatureGUID','msDS-OptionalFeatureFlags','msDS-RequiredForestBehaviorVersion','msDS-RequiredDomainBehaviorVersion','msDS-EnabledFeatureBL')
    $features=@(Get-ADOptionalFeature -Filter '*' -Server $Server -ErrorAction Stop)
    if (-not $features.Count) {throw 'Positive optional feature fixture is required.'}
    foreach ($feature in $features) {
        $raw=Get-ADObject -Identity $feature.DistinguishedName -Server $Server -Properties $properties -ErrorAction Stop
        if ($raw.ObjectGUID -ne $feature.ObjectGUID) {throw 'Cmdlet and raw feature identities differ.'}
        $guid=ConvertTo-OptionalGUID (Get-OptionalProperty $raw 'msDS-OptionalFeatureGUID')
        if ($guid -ine $feature.FeatureGUID.ToString()) {throw 'Cmdlet and raw feature GUIDs differ.'}
        $flags=ConvertTo-DirectoryMask (Get-OptionalProperty $raw 'msDS-OptionalFeatureFlags')
        $disablable=$null;if ($null -ne $flags) {$disablable=($flags -band 4) -ne 0}
        if ($null -ne $disablable -and $disablable -ne $feature.IsDisableable) {throw 'Cmdlet disablability differs from documented flag bits.'}
        $enabled=Get-OptionalProperty $raw 'msDS-EnabledFeatureBL'
        $artifact.features+=@([ordered]@{DistinguishedName=$raw.DistinguishedName;FeatureGUID=$guid;Flags=$flags;Disablable=$disablable;RequiredForestLevel=Get-OptionalProperty $raw 'msDS-RequiredForestBehaviorVersion';RequiredDomainLevel=Get-OptionalProperty $raw 'msDS-RequiredDomainBehaviorVersion';EnabledScopes=if ($null -eq $enabled) {$null} else {@($enabled)}})
    }
    $os=Get-CimInstance Win32_OperatingSystem
    $artifact.environment=[ordered]@{computer=[Environment]::MachineName;os=$os.Caption;version=$os.Version;build=$os.BuildNumber;powershell=$PSVersionTable.PSVersion.ToString();module=(Get-Module ActiveDirectory).Version.ToString();directory_controller_functionality=$root.domainControllerFunctionality;forest_functionality=$root.forestFunctionality}
    if ($NativeJSON) {
        $native=Get-Content -LiteralPath (Assert-DirectoryPlainPath $NativeJSON) -Raw -Encoding UTF8 | ConvertFrom-Json
        $endpoint=$Server.Split(':');$port=389;if ($endpoint.Count -eq 2) {$port=[int]$endpoint[1]}
        if ($native.Observation.Source.Host -ine $endpoint[0] -or $native.Observation.Source.Port -ne $port -or $native.Observation.RootDSE.ConfigurationNamingContext -ine $root.configurationNamingContext) {throw 'Native and reference endpoints/configurations differ.'}
        if ($native.Complete -ne $true -or $native.LimitReached -ne $false -or @($native.Features).Count -ne $artifact.features.Count) {throw 'Native collection was incomplete or selected a different feature set.'}
        $artifact.comparison_performed=$true
        foreach ($expected in $artifact.features) {
            $actual=@($native.Features | Where-Object {$_.FeatureGUID -ieq $expected.FeatureGUID})
            if ($actual.Count -ne 1) {throw 'Missing or duplicate native feature GUID.'}
            foreach ($name in @('DistinguishedName','Flags','Disablable','RequiredForestLevel','RequiredDomainLevel')) {if ($null -eq $expected[$name]) {if ($null -ne $actual[0].$name) {throw 'Missing property became a value.'}} elseif ([string]$actual[0].$name -ine [string]$expected[$name]) {throw 'Native/reference feature scalar differs.'}}
            if ($actual[0].EnabledScopesState -eq 3) {throw 'Ranged native enabled scopes are incomplete.'}
            if ($null -eq $expected.EnabledScopes) {if ($actual[0].EnabledScopesState -ne 1) {throw 'Unreturned enabled scopes must remain unknown.'}} else {
                if ($actual[0].EnabledScopesState -ne 2 -or (Compare-Object @($expected.EnabledScopes | Sort-Object) @($actual[0].EnabledScopes | Sort-Object))) {throw 'Native/reference enabled scopes differ.'}
            }
        }
        $artifact.comparison_passed=$true
    }
    $artifact.passed=$true
} catch {$failure=$_;$artifact.failure_type=$_.Exception.GetType().FullName;$artifact.failure_id=$_.FullyQualifiedErrorId;$artifact.failure_line=$_.InvocationInfo.ScriptLineNumber} finally {
    $env:ADPS_LoadDefaultDrive=$old;$artifact.finished=[DateTime]::UtcNow.ToString('o');Write-DirectoryNewJSON $destination $artifact
}
if ($failure) {throw 'Optional-feature reference failed; inspect the retained artifact.'}
Write-Output 'Read-only optional-feature reference captured; full ticket qualification is incomplete.'
