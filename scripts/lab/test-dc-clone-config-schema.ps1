# Offline XML qualification. Loads the retained Microsoft schema; no AD module,
# directory calls, VM operations, registry access, or clone-file publication.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SdkBinary,
    [string]$SchemaEvidence
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $SchemaEvidence) { $SchemaEvidence = Join-Path $PSScriptRoot '../../docs/research/dc-cloning-evidence/server2025-readonly.json' }
$evidence = Get-Content -LiteralPath $SchemaEvidence -Raw | ConvertFrom-Json
$schemaFile = @($evidence.observation.files | Where-Object { $_.path -match 'DCCloneConfigSchema\.xsd$' })
if ($schemaFile.Count -ne 1) { throw 'Exactly one captured Microsoft schema is required.' }
$schemaReader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new([string]$schemaFile[0].text))
try { $schema = [System.Xml.Schema.XmlSchema]::Read($schemaReader, $null) } finally { $schemaReader.Dispose() }
$cases = @(
    @{ Name = 'default'; Args = @() },
    @{ Name = 'name-site'; Args = @('-computer-name','CLONE-1','-site','East & <West>') },
    @{ Name = 'v4-dynamic'; Args = @('-ipv4-dns','192.0.2.10,192.0.2.11') },
    @{ Name = 'v4-static'; Args = @('-static','-ipv4-address','192.0.2.20','-ipv4-mask','255.255.255.0','-ipv4-gateway','192.0.2.1','-ipv4-dns','192.0.2.10') },
    @{ Name = 'v6-dynamic'; Args = @('-ipv6-dns','2001:db8::10') },
    @{ Name = 'v6-static'; Args = @('-static','-ipv6-dns','2001:db8::10') },
    @{ Name = 'dual-dynamic'; Args = @('-ipv4-dns','192.0.2.10','-ipv6-dns','2001:db8::10') },
    @{ Name = 'dual-static'; Args = @('-static','-ipv4-address','192.0.2.20','-ipv4-mask','255.255.255.0','-ipv4-dns','192.0.2.10','-ipv6-dns','2001:db8::10') },
    @{ Name = 'four-resolvers'; Args = @('-ipv4-dns','192.0.2.10,192.0.2.11,192.0.2.12,192.0.2.13') }
)
foreach ($case in $cases) {
    $arguments = @('-encode-only') + $case.Args
    $text = (& $SdkBinary @arguments | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "SDK encoding failed: $($case.Name)" }
    $document = [System.Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    $document.LoadXml($text)
    [void]$document.Schemas.Add($schema)
    $document.Validate($null)
    if ($document.DocumentElement.NamespaceURI -ne 'uri:microsoft.com:schemas:DCCloneConfig') { throw 'Root namespace differs.' }
    foreach ($element in $document.DocumentElement.SelectNodes('.//*')) {
        if ($element.NamespaceURI -ne '') { throw 'Descendant is incorrectly namespace-qualified.' }
    }
    Write-Output "PASS $($case.Name)"
}
Write-Output "Validated $($cases.Count) SDK cases against retained Microsoft XSD; no reference cmdlet was invoked."
