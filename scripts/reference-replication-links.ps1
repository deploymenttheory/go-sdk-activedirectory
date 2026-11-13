[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$IdentityDN,
    [Parameter(Mandatory)][ValidateSet('Connection','SiteLink','SiteLinkBridge')][string]$Kind,
    [string]$SDKResultPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Read-only: consume existing explicitly selected objects. No fixture creation,
# topology writes, KCC execution, remote shell or endpoint discovery occurs here.
function Convert-RawProperty {
    param($Object, [string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    $encoded = [Collections.Generic.List[string]]::new()
    if ($null -eq $property -or $null -eq $property.Value) {
        return [ordered]@{ Returned = $false; Values = @() }
    }
    $value = $property.Value
    if ($value -is [byte[]]) {
        $encoded.Add([Convert]::ToBase64String($value))
    } else {
        foreach ($item in $value) {
            if ($item -is [byte[]]) { $encoded.Add([Convert]::ToBase64String($item)); continue }
            if ($item -is [Guid]) { $encoded.Add([Convert]::ToBase64String($item.ToByteArray())); continue }
            if ($item -is [bool]) { $text = $item.ToString().ToUpperInvariant() }
            else { $text = [Convert]::ToString($item, [Globalization.CultureInfo]::InvariantCulture) }
            $encoded.Add([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)))
        }
    }
    return [ordered]@{ Returned = $true; Values = @($encoded.ToArray()) }
}
function Sort-ReferenceDNs {
    param([string[]]$Values)
    $copy = [string[]]@($Values)
    [Array]::Sort($copy, [StringComparer]::OrdinalIgnoreCase)
    return ,$copy
}
$report = [ordered]@{
    schema = 1; started_utc = [DateTime]::UtcNow.ToString('o'); server = $Server
    identity_dn = $IdentityDN; kind = $Kind; ps_version = $PSVersionTable.PSVersion.ToString()
    module_version = $null; server_os = $null; server_os_version = $null
    cmdlet = $null; raw = [ordered]@{}; sdk_compared = $false
    differences = @(); errors = @(); passed = $false
}
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $report.module_version = (Get-Module ActiveDirectory).Version.ToString()
    $root = Get-ADRootDSE -Server $Server
    # AD LDS need not have an AD DS computer-account reference.
    $dsa = Get-ADObject -Server $Server -Identity $root.dsServiceName -Properties distinguishedName
    $dsaDN = [string]$dsa.DistinguishedName
    $serverDN = $dsaDN.Substring($dsaDN.IndexOf(',') + 1)
    $serverObject = Get-ADObject -Server $Server -Identity $serverDN -Properties serverReference
    if ($serverObject.serverReference) {
        $computer = Get-ADObject -Server $Server -Identity $serverObject.serverReference -Properties operatingSystem,operatingSystemVersion
        $report.server_os = $computer.operatingSystem
        $report.server_os_version = $computer.operatingSystemVersion
    }
    $properties = @('objectGUID','name','description')
    $referenceAttribute = $null
    switch ($Kind) {
        'Connection' {
            $report.cmdlet = Get-ADReplicationConnection -Server $Server -Identity $IdentityDN -Properties *
            $properties += @('fromServer','transportType','enabledConnection','options','schedule')
            $memberName = 'Connection'
        }
        'SiteLink' {
            $report.cmdlet = Get-ADReplicationSiteLink -Server $Server -Identity $IdentityDN -Properties *
            $properties += @('cost','replInterval','options','schedule'); $referenceAttribute = 'siteList'; $memberName = 'Link'
        }
        'SiteLinkBridge' {
            $report.cmdlet = Get-ADReplicationSiteLinkBridge -Server $Server -Identity $IdentityDN -Properties *
            $referenceAttribute = 'siteLinkList'; $memberName = 'Bridge'
        }
    }
    $requested = @($properties)
    if ($referenceAttribute) { $requested += $referenceAttribute }
    $object = Get-ADObject -Server $Server -Identity $IdentityDN -Properties $requested
    foreach ($property in $properties) { $report.raw[$property] = Convert-RawProperty $object $property }
    if ($referenceAttribute) {
        $report.raw[$referenceAttribute] = Convert-RawProperty $object $referenceAttribute
    }
    if ($SDKResultPath) {
        $sdk = Get-Content -LiteralPath $SDKResultPath -Raw | ConvertFrom-Json
        $attributes = $sdk.$memberName.Raw.Attributes
        $differences = [Collections.Generic.List[string]]::new()
        foreach ($property in $properties) {
            $actual = $attributes.PSObject.Properties[$property]
            $expected = $report.raw[$property]
            if (($null -ne $actual) -ne $expected.Returned) { $differences.Add("$property return state"); continue }
            if ($null -eq $actual) { continue }
            $left = [string[]]@($actual.Value); $right = [string[]]@($expected.Values)
            [Array]::Sort($left, [StringComparer]::Ordinal); [Array]::Sort($right, [StringComparer]::Ordinal)
            if (($left -join '|') -cne ($right -join '|')) { $differences.Add("$property raw values") }
        }
        if ($referenceAttribute) {
            if ($Kind -eq 'SiteLink') { $references = $sdk.Sites } else { $references = $sdk.SiteLinks }
            if (-not $references.Complete -or $null -ne $references.Error) { $differences.Add('SDK references incomplete') }
            $referenceReturned = $report.raw[$referenceAttribute].Returned
            if ($references.AttributeReturned -ne $referenceReturned) { $differences.Add('reference return state') }
            $expectedDNs = @($object.$referenceAttribute | ForEach-Object { [string]$_ })
            $actualDNs = @($references.References | ForEach-Object { [string]$_.DistinguishedName })
            $left = Sort-ReferenceDNs $actualDNs; $right = Sort-ReferenceDNs $expectedDNs
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals(($left -join '|'), ($right -join '|'))) { $differences.Add('reference DNs') }
        }
        $report.sdk_compared = $true
        $report.differences = @($differences.ToArray())
    }
    $report.passed = $report.differences.Count -eq 0
} catch { $report.errors = @($_.Exception.ToString()) }
$report['completed_utc'] = [DateTime]::UtcNow.ToString('o')
$report | ConvertTo-Json -Depth 12
if (-not $report.passed) { throw 'Replication link reference collection/comparison failed; inspect the emitted report.' }
