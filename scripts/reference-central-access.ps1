[CmdletBinding(DefaultParameterSetName='Collect')]
param(
    [Parameter(Mandatory,ParameterSetName='Collect')][string]$Server,
    [Parameter(Mandatory,ParameterSetName='Collect')][string]$IdentityDN,
    [Parameter(Mandatory,ParameterSetName='Collect')][ValidateSet('Rule','Policy')][string]$Kind,
    [Parameter(ParameterSetName='Collect')][string]$SDKResultPath,
    [Parameter(Mandatory,ParameterSetName='SelfTest')][switch]$SelfTest
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Collection is opt-in and read-only. No fixture creation, AD writes, remote
# shell, policy deployment or discovery of a different endpoint occurs here.
function Convert-ReferenceValues {
    param($Value)
    $encoded = [Collections.Generic.List[string]]::new()
    if ($null -eq $Value) { return ,$encoded.ToArray() }
    if ($Value -is [byte[]]) { $items = ,$Value } else { $items = @($Value) }
    foreach ($item in $items) {
        if ($item -is [byte[]]) { $bytes = $item }
        elseif ($item -is [Guid]) { $bytes = $item.ToByteArray() }
        elseif ($item -is [Security.Principal.SecurityIdentifier]) {
            $bytes = [byte[]]::new($item.BinaryLength); $item.GetBinaryForm($bytes,0)
        } else { $bytes = [Text.Encoding]::UTF8.GetBytes([Convert]::ToString($item,[Globalization.CultureInfo]::InvariantCulture)) }
        $encoded.Add([Convert]::ToBase64String($bytes))
    }
    return ,$encoded.ToArray()
}
function Get-ReferenceProperty {
    param($Object,[string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return ,$property.Value
}
function Test-ReferenceValues {
    param([string[]]$Left,[string[]]$Right)
    $a = [string[]]@($Left); $b = [string[]]@($Right)
    [Array]::Sort($a,[StringComparer]::Ordinal); [Array]::Sort($b,[StringComparer]::Ordinal)
    return ($a.Count -eq $b.Count -and ($a -join '|') -ceq ($b -join '|'))
}
if ($SelfTest) {
    $bytes = [byte[]](0,1,128,255)
    if (-not (Test-ReferenceValues (Convert-ReferenceValues $bytes) @('AAGA/w=='))) { throw 'Binary values were flattened.' }
    if (-not (Test-ReferenceValues (Convert-ReferenceValues (Get-ReferenceProperty ([pscustomobject]@{ value=$bytes }) 'value')) @('AAGA/w=='))) { throw 'Property access flattened binary values.' }
    $guid = [Guid]'00112233-4455-6677-8899-aabbccddeeff'
    if (-not (Test-ReferenceValues (Convert-ReferenceValues $guid) @([Convert]::ToBase64String($guid.ToByteArray())))) { throw 'GUID byte order changed.' }
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-17-1-2-3-4')
    if (([Convert]::FromBase64String((Convert-ReferenceValues $sid)[0])).Length -ne 24) { throw 'SID representation changed.' }
    if (-not (Test-ReferenceValues @('Yg==','YQ==') @('YQ==','Yg==')) -or (Test-ReferenceValues @('YQ==') @('yQ=='))) { throw 'Raw comparison lost ordinal semantics.' }
    if ((Convert-ReferenceValues $null).Count -ne 0) { throw 'Null was converted to a value.' }
    'Central-access reference helper checks passed; no directory calls made.'
    return
}
$report = [ordered]@{
    schema = 1; started_utc = [DateTime]::UtcNow.ToString('o'); server = $Server
    identity_dn = $IdentityDN; kind = $Kind; ps_version = $PSVersionTable.PSVersion.ToString()
    module_version = $null; assembly_file_version = $null; server_os = $null; server_os_version = $null
    cmdlet = $null; raw_base64 = [ordered]@{}; empty_or_omitted = @(); sdk_compared = $false
    comparison_scope = 'Returned values only; the reference module cannot distinguish an omitted attribute from an exposed empty collection.'
    differences = @(); errors = @(); passed = $false
}
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $report.module_version = (Get-Module ActiveDirectory).Version.ToString()
    $assembly = [Microsoft.ActiveDirectory.Management.ADObject].Assembly.Location
    $report.assembly_file_version = [Diagnostics.FileVersionInfo]::GetVersionInfo($assembly).FileVersion
    $root = Get-ADRootDSE -Server $Server
    $dsa = Get-ADObject -Server $Server -Identity $root.dsServiceName -Properties distinguishedName
    $dsaDN = [string]$dsa.DistinguishedName
    $serverObject = Get-ADObject -Server $Server -Identity $dsaDN.Substring($dsaDN.IndexOf(',')+1) -Properties serverReference
    $computer = Get-ADObject -Server $Server -Identity $serverObject.serverReference -Properties operatingSystem,operatingSystemVersion
    $report.server_os = $computer.operatingSystem; $report.server_os_version = $computer.operatingSystemVersion
    $properties = @('objectGUID','name','description')
    if ($Kind -eq 'Rule') {
        $report.cmdlet = Get-ADCentralAccessRule -Server $Server -Identity $IdentityDN -Properties * |
            Select-Object DistinguishedName,ObjectGUID,Name,Description,CurrentACL,ProposedACL,PreviousACL,ResourceCondition,MemberOf,ProtectedFromAccidentalDeletion
        $properties += @('msAuthz-EffectiveSecurityPolicy','msAuthz-ProposedSecurityPolicy','msAuthz-LastEffectiveSecurityPolicy','msAuthz-ResourceCondition')
        $referenceAttribute = 'msAuthz-MemberRulesInCentralAccessPolicyBL'; $memberName = 'Rule'; $referenceName = 'Policies'
    } else {
        $report.cmdlet = Get-ADCentralAccessPolicy -Server $Server -Identity $IdentityDN -Properties * |
            Select-Object DistinguishedName,ObjectGUID,Name,Description,PolicyID,Members,ProtectedFromAccidentalDeletion
        $properties += 'msAuthz-CentralAccessPolicyID'
        $referenceAttribute = 'msAuthz-MemberRulesInCentralAccessPolicy'; $memberName = 'Policy'; $referenceName = 'Members'
    }
    $object = Get-ADObject -Server $Server -Identity $IdentityDN -Properties ($properties + $referenceAttribute)
    foreach ($property in ($properties + $referenceAttribute)) {
        $values = Convert-ReferenceValues (Get-ReferenceProperty $object $property)
        $report.raw_base64[$property] = @($values)
        if ($values.Count -eq 0) { $report.empty_or_omitted += $property }
    }
    if ($SDKResultPath) {
        $sdk = Get-Content -LiteralPath $SDKResultPath -Raw | ConvertFrom-Json
        $differences = [Collections.Generic.List[string]]::new()
        if (-not $sdk.Observation.Complete) { $differences.Add('SDK object observation incomplete') }
        $attributes = $sdk.$memberName.Raw.Attributes
        foreach ($property in $properties) {
            $actual = Get-ReferenceProperty $attributes $property
            if (-not (Test-ReferenceValues @($actual | Where-Object { $null -ne $_ }) $report.raw_base64[$property])) { $differences.Add("$property raw values") }
        }
        $references = $sdk.$referenceName
        if (-not $references.Complete -or $null -ne $references.Error) { $differences.Add('SDK references incomplete') }
        # Require byte-equivalent DN values here. Semantically equivalent but
        # differently rendered DNs are retained as differences for review.
        $actualDNs = @($references.References | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$_.DistinguishedName)) })
        if (-not (Test-ReferenceValues $actualDNs $report.raw_base64[$referenceAttribute])) { $differences.Add('reference DN values') }
        $report.sdk_compared = $true; $report.differences = @($differences.ToArray())
    }
    $report.passed = $report.differences.Count -eq 0
} catch { $report.errors = @($_.Exception.ToString()) }
$report['completed_utc'] = [DateTime]::UtcNow.ToString('o')
$report | ConvertTo-Json -Depth 14
if (-not $report.passed) { throw 'Central-access collection/comparison failed; inspect the emitted report.' }
