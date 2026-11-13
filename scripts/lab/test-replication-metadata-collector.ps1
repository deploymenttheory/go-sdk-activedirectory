# Local contract test. Mock AD cmdlets prevent all directory/network activity.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$collector = Join-Path $PSScriptRoot 'collect-replication-metadata.ps1'
$directory = Join-Path ([IO.Path]::GetTempPath()) ('ad-sdk-metadata-collector-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($directory) | Out-Null
$metadataCollectorMode = 'attributes'
function Import-Module { param($Name, $ErrorAction) if ($Name -ne 'ActiveDirectory') { throw 'Unexpected module.' } }
function Get-Module { param($Name) return [pscustomobject]@{ Version = [version]'1.0.0.0' } }
function Get-ADReplicationAttributeMetadata {
    param($Server, $Object, $Properties, [switch]$ShowAllLinkedValues, [switch]$IncludeDeletedObjects, $ErrorAction)
    if ($metadataCollectorMode -eq 'failure') { throw 'Injected reference denial' }
    if ($metadataCollectorMode -eq 'unavailable') { return }
    $row = [ordered]@{
        AttributeName = 'description'; IsLinkValue = $false; Version = 4
        LastOriginatingChangeDirectoryServerInvocationId = [guid]'00112233-4455-6677-8899-aabbccddeeff'
        LastOriginatingChangeUsn = [long]'9007199254740993'; LocalChangeUsn = [long]'9007199254740995'
        LastOriginatingChangeDirectoryServerIdentity = 'CN=NTDS Settings,CN=DC1'
        LastOriginatingChangeTime = [datetime]::FromFileTimeUtc([long]'133800000001234567')
    }
    if ($metadataCollectorMode -eq 'malformed') { $row.Remove('Version') }
    [pscustomobject]$row
    if ($ShowAllLinkedValues) {
        $row.AttributeName = 'member'; $row.IsLinkValue = $true
        $row.AttributeValue = 'CN=Member,DC=ad,DC=sdk,DC=test'
        $row.FirstOriginatingCreateTime = [datetime]::FromFileTimeUtc([long]'133800000001234560')
        $row.LastOriginatingDeleteTime = [datetime]::FromFileTimeUtc([long]'133800000001234568')
        [pscustomobject]$row
    }
}
function Get-ADReplicationUpToDatenessVectorTable {
    param($Target, $Scope, $Partition, $ErrorAction)
    [pscustomobject]@{
        PartnerInvocationId = [guid]'00112233-4455-6677-8899-aabbccddeeff'
        UsnFilter = [long]'9007199254740993'
        LastReplicationSuccess = [datetime]::FromFileTimeUtc([long]'133800000001234567')
        Partner = 'CN=NTDS Settings,CN=DC1'
    }
}
function Assert-Local([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
try {
    $common = @{ Server = 'dc1.ad.sdk.test'; ServerVersion = 'fixture test version'; RunID = 'local-test'; FixtureID = 'mock-only'; Phase = 'unit' }
    $attributes = Join-Path $directory 'attributes.json'
    & $collector @common -ObjectDN 'CN=Group' -IncludeLinkedValues -IncludeDeletedObjects -OutputPath $attributes
    $ref = Get-Content -LiteralPath $attributes -Raw | ConvertFrom-Json
    Assert-Local ($ref.Stamps.Count -eq 2) 'Attribute/link distinction lost.'
    Assert-Local ($ref.Stamps[0].OriginatingUSN -ceq '9007199254740993') 'USN precision lost.'
    Assert-Local ($ref.Stamps[0].ChangedTicks -ceq '133800000001234567') 'FILETIME precision lost.'
    Assert-Local ($ref.Stamps[1].Link -and $ref.Stamps[1].DeletedTicks -ceq '133800000001234568') 'Link deletion stamp lost.'
    Assert-Local ($ref.IdentitySID -ne '' -and $ref.ModuleVersion -eq '1.0.0.0') 'Identity/version missing.'
    $rejected = $false
    try { & $collector @common -ObjectDN 'CN=Group' -OutputPath $attributes } catch { $rejected = $true }
    Assert-Local $rejected 'Existing artifact was overwritten.'

    $vectors = Join-Path $directory 'vectors.json'
    & $collector @common -PartitionDN 'DC=ad,DC=sdk,DC=test' -OutputPath $vectors
    $ref = Get-Content -LiteralPath $vectors -Raw | ConvertFrom-Json
    Assert-Local ($ref.Kind -eq 'vectors' -and $ref.Cursors.Count -eq 1 -and $ref.Cursors[0].HighestUSN -ceq '9007199254740993') 'Vector mapping failed.'

    $metadataCollectorMode = 'failure'
    $failure = Join-Path $directory 'failure.json'
    & $collector @common -ObjectDN 'CN=Denied' -ExpectedOutcome failure -ExpectedLDAPCodes 50 -OutputPath $failure
    $ref = Get-Content -LiteralPath $failure -Raw | ConvertFrom-Json
    Assert-Local ($null -ne $ref.ReferenceError -and $ref.ExpectedLDAPCodes[0] -eq 50) 'Reference failure was not retained.'

    $metadataCollectorMode = 'unavailable'
    $unavailable = Join-Path $directory 'unavailable.json'
    & $collector @common -ObjectDN 'CN=Hidden' -ExpectedOutcome unavailable -OutputPath $unavailable
    $ref = Get-Content -LiteralPath $unavailable -Raw | ConvertFrom-Json
    Assert-Local ($ref.Stamps.Count -eq 0 -and $null -eq $ref.ReferenceError) 'Omitted reference conflated with native error.'

    $metadataCollectorMode = 'malformed'
    $malformed = Join-Path $directory 'malformed.json'
    $rejected = $false
    try { & $collector @common -ObjectDN 'CN=Group' -OutputPath $malformed } catch { $rejected = $true }
    Assert-Local ($rejected -and -not (Test-Path -LiteralPath $malformed)) 'Malformed reference accepted.'
    'Replication metadata collector contract checks passed (mock AD commands only).'
} finally {
    # This unique directory contains only the local test's known output files.
    foreach ($name in @('attributes.json', 'vectors.json', 'failure.json', 'unavailable.json', 'malformed.json')) {
        $path = Join-Path $directory $name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    Remove-Item -LiteralPath $directory
}
