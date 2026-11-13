# Read-only reference collector for an externally prepared, isolated fixture.
# It neither provisions objects nor triggers replication nor launches the SDK.
[CmdletBinding(DefaultParameterSetName = 'Attributes')]
param(
    [Parameter(Mandatory)][string]$Server,
    [ValidateRange(1, 65535)][int]$Port = 389,
    [Parameter(Mandatory)][string]$ServerVersion,
    [Parameter(Mandatory)][string]$RunID,
    [Parameter(Mandatory)][string]$FixtureID,
    [Parameter(Mandatory)][string]$Phase,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory, ParameterSetName = 'Attributes')][string]$ObjectDN,
    [Parameter(ParameterSetName = 'Attributes')][string[]]$Properties = @('*'),
    [Parameter(ParameterSetName = 'Attributes')][switch]$IncludeLinkedValues,
    [Parameter(ParameterSetName = 'Attributes')][switch]$IncludeDeletedObjects,
    [Parameter(Mandatory, ParameterSetName = 'Vectors')][string]$PartitionDN,
    [ValidateSet('success', 'failure', 'unavailable')][string]$ExpectedOutcome = 'success',
    [int[]]$ExpectedLDAPCodes = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ServerVersion) -or [string]::IsNullOrWhiteSpace($RunID) -or [string]::IsNullOrWhiteSpace($FixtureID) -or [string]::IsNullOrWhiteSpace($Phase)) {
    throw 'The fixture inventory version, run ID, fixture ID, and phase are required.'
}
if ($ExpectedOutcome -eq 'failure' -and $ExpectedLDAPCodes.Count -eq 0) { throw 'Failure cases require expected native LDAP codes.' }
if ($Server -notmatch '^[A-Za-z0-9.-]+$' -or $Server -notmatch '\.') { throw 'Server must be an explicit FQDN or IPv4 address.' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Output must be a fresh artifact.' }
Import-Module ActiveDirectory -ErrorAction Stop

function Required-Value($Row, [string]$Name) {
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { throw "Reference result omitted required field $Name." }
    return $property.Value
}
function Optional-Text($Row, [string]$Name) {
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value -or [string]$property.Value -eq '') { return $null }
    return ([string]$property.Value).ToLowerInvariant()
}
function Filetime-Text($Row, [string]$Name, [bool]$Required) {
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "Reference result omitted timestamp field $Name." }
    if ($null -eq $property.Value) { if ($Required) { throw "Required timestamp $Name was null." }; return '0' }
    return ([datetime]$property.Value).ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
}

$target = $Server
if ($Port -ne 389) { $target = "${Server}:$Port" }
$kind = if ($PSCmdlet.ParameterSetName -eq 'Attributes') { 'attributes' } else { 'vectors' }
$rows = @()
$referenceError = $null
try {
    if ($kind -eq 'attributes') {
        $rows = @(Get-ADReplicationAttributeMetadata -Server $target -Object $ObjectDN -Properties $Properties -ShowAllLinkedValues:$IncludeLinkedValues -IncludeDeletedObjects:$IncludeDeletedObjects -ErrorAction Stop)
    } else {
        $rows = @(Get-ADReplicationUpToDatenessVectorTable -Target $target -Scope Server -Partition $PartitionDN -ErrorAction Stop)
    }
} catch {
    # Only the native reference operation can satisfy an expected failure.
    # Conversion, missing properties, and artifact errors remain hard failures.
    $referenceError = [ordered]@{ Type = $_.Exception.GetType().FullName; ID = $_.FullyQualifiedErrorId }
}
if ($ExpectedOutcome -eq 'failure' -and $null -eq $referenceError) { throw 'Expected reference failure, but the reference operation succeeded.' }
if ($ExpectedOutcome -ne 'failure' -and $null -ne $referenceError) { throw "Unexpected reference failure: $($referenceError.ID)" }
if ($ExpectedOutcome -eq 'unavailable' -and $rows.Count -ne 0) { throw 'Expected an omitted/empty reference collection.' }
if ($ExpectedOutcome -eq 'success' -and $rows.Count -eq 0) { throw 'Successful qualification requires at least one observed metadata row.' }

$stamps = @()
$cursors = @()
foreach ($row in $rows) {
    if ($kind -eq 'attributes') {
        $link = [bool](Required-Value $row 'IsLinkValue')
        $value = $null; $created = ''; $deleted = ''
        if ($link) {
            $value = Optional-Text $row 'AttributeValue'
            $created = Filetime-Text $row 'FirstOriginatingCreateTime' $false
            $deleted = Filetime-Text $row 'LastOriginatingDeleteTime' $false
        }
        $stamps += [ordered]@{
            AttributeName = ([string](Required-Value $row 'AttributeName')).ToLowerInvariant()
            Link = $link; ValueDN = $value
            Version = [uint32](Required-Value $row 'Version')
            InvocationID = ([guid](Required-Value $row 'LastOriginatingChangeDirectoryServerInvocationId')).ToString('D')
            OriginatingUSN = ([long](Required-Value $row 'LastOriginatingChangeUsn')).ToString([Globalization.CultureInfo]::InvariantCulture)
            LocalUSN = ([long](Required-Value $row 'LocalChangeUsn')).ToString([Globalization.CultureInfo]::InvariantCulture)
            OriginatingServerDN = Optional-Text $row 'LastOriginatingChangeDirectoryServerIdentity'
            ChangedTicks = Filetime-Text $row 'LastOriginatingChangeTime' $true
            CreatedTicks = $created; DeletedTicks = $deleted
        }
    } else {
        $cursors += [ordered]@{
            InvocationID = ([guid](Required-Value $row 'PartnerInvocationId')).ToString('D')
            HighestUSN = ([long](Required-Value $row 'UsnFilter')).ToString([Globalization.CultureInfo]::InvariantCulture)
            LastSuccessTicks = Filetime-Text $row 'LastReplicationSuccess' $false
            SourceServerDN = Optional-Text $row 'Partner'
        }
    }
}
$artifact = [ordered]@{
    SchemaVersion = 1; RunID = $RunID; FixtureID = $FixtureID; Phase = $Phase
    Server = $Server; Port = $Port; ServerVersion = $ServerVersion
    ServerVersionSource = 'caller-supplied fixture inventory'
    ModuleVersion = (Get-Module ActiveDirectory).Version.ToString()
    CollectorOS = [Environment]::OSVersion.VersionString
    IdentitySID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    CollectedUTC = [datetime]::UtcNow.ToString('o')
    Kind = $kind; ObjectDN = $ObjectDN; PartitionDN = $PartitionDN
    Properties = @($Properties); IncludeLinkedValues = [bool]$IncludeLinkedValues
    IncludeDeletedObjects = [bool]$IncludeDeletedObjects
    ExpectedOutcome = $ExpectedOutcome; ExpectedLDAPCodes = @($ExpectedLDAPCodes)
    ReferenceError = $referenceError; Stamps = @($stamps); Cursors = @($cursors)
}
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(($artifact | ConvertTo-Json -Depth 12))
$stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
