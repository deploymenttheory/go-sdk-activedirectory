# Run only when the lab owner assigns a profile for reference qualification.
# This script invokes the real AD cmdlet in explicit Offline mode in unique,
# owned directories. Module initialization is part of the observed reference.
# It never writes NTDS locations, changes groups, or performs VM lifecycle work.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SdkBinary,
    [Parameter(Mandatory)][string]$ArtifactDirectory,
    [string]$SchemaEvidence
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $SchemaEvidence) { $SchemaEvidence = Join-Path $PSScriptRoot '../../docs/research/dc-cloning-evidence/server2025-readonly.json' }
$SdkBinary = (Resolve-Path -LiteralPath $SdkBinary).Path
$runDirectory = Join-Path ([System.IO.Path]::GetFullPath($ArtifactDirectory)) ('clone-config-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($runDirectory)
$savedDefaultDrive = $env:ADPS_LoadDefaultDrive
try {
    $env:ADPS_LoadDefaultDrive = '0'
    Import-Module ActiveDirectory -ErrorAction Stop
    $command = Get-Command New-ADDCCloneConfigFile -ErrorAction Stop
    if (-not $command.Parameters.ContainsKey('Offline')) { throw 'Reference has no explicit Offline mode.' }
    $schemaObservation = Get-Content -LiteralPath $SchemaEvidence -Raw | ConvertFrom-Json
    $schemaFile = @($schemaObservation.observation.files | Where-Object { $_.path -match 'DCCloneConfigSchema\.xsd$' })
    if ($schemaFile.Count -ne 1) { throw 'Exactly one captured schema is required.' }
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new([string]$schemaFile[0].text))
    try { $schema = [System.Xml.Schema.XmlSchema]::Read($reader, $null) } finally { $reader.Dispose() }

    function Read-Configuration([string]$Path) {
        $document = [System.Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($Path)
        [void]$document.Schemas.Add($schema)
        $document.Validate($null)
        return $document
    }
    function Project-Element([System.Xml.XmlElement]$Element) {
        $children = @($Element.ChildNodes | Where-Object { $_ -is [System.Xml.XmlElement] } | ForEach-Object { Project-Element $_ })
        $value = ''
        if ($children.Count -eq 0) { $value = $Element.InnerText }
        return [ordered]@{ name = $Element.LocalName; namespace = $Element.NamespaceURI; value = $value; children = $children }
    }

    $cases = @(
        @{ Name = 'default'; Sdk = @(); Reference = @{} },
        @{ Name = 'name-site'; Sdk = @('-computer-name','CLONE-1','-site','Default-First-Site-Name'); Reference = @{ CloneComputerName = 'CLONE-1'; SiteName = 'Default-First-Site-Name' } },
        @{ Name = 'v4-dynamic'; Sdk = @('-ipv4-dns','192.0.2.10,192.0.2.11'); Reference = @{ IPv4DNSResolver = @('192.0.2.10','192.0.2.11') } },
        @{ Name = 'v4-static'; Sdk = @('-static','-ipv4-address','192.0.2.20','-ipv4-mask','255.255.255.0','-ipv4-gateway','192.0.2.1','-ipv4-dns','192.0.2.10'); Reference = @{ Static = $true; IPv4Address = '192.0.2.20'; IPv4SubnetMask = '255.255.255.0'; IPv4DefaultGateway = '192.0.2.1'; IPv4DNSResolver = @('192.0.2.10') } },
        @{ Name = 'v6-dynamic'; Sdk = @('-ipv6-dns','2001:db8::10'); Reference = @{ IPv6DNSResolver = @('2001:db8::10') } },
        @{ Name = 'v6-static'; Sdk = @('-static','-ipv6-dns','2001:db8::10'); Reference = @{ Static = $true; IPv6DNSResolver = @('2001:db8::10') } },
        @{ Name = 'dual-dynamic'; Sdk = @('-ipv4-dns','192.0.2.10','-ipv6-dns','2001:db8::10'); Reference = @{ IPv4DNSResolver = @('192.0.2.10'); IPv6DNSResolver = @('2001:db8::10') } },
        @{ Name = 'dual-static'; Sdk = @('-static','-ipv4-address','192.0.2.20','-ipv4-mask','255.255.255.0','-ipv4-dns','192.0.2.10','-ipv6-dns','2001:db8::10'); Reference = @{ Static = $true; IPv4Address = '192.0.2.20'; IPv4SubnetMask = '255.255.255.0'; IPv4DNSResolver = @('192.0.2.10'); IPv6DNSResolver = @('2001:db8::10') } },
        @{ Name = 'four-resolvers'; Sdk = @('-ipv4-dns','192.0.2.10,192.0.2.11,192.0.2.12,192.0.2.13'); Reference = @{ IPv4DNSResolver = @('192.0.2.10','192.0.2.11','192.0.2.12','192.0.2.13') } },
        @{ Name = 'overwrite'; Sdk = @('-computer-name','CLONE-2'); Reference = @{ CloneComputerName = 'CLONE-2' } }
    )
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($case in $cases) {
        $caseDirectory = Join-Path $runDirectory $case.Name
        $sdkDirectory = Join-Path $caseDirectory 'sdk'
        $referenceDirectory = Join-Path $caseDirectory 'reference'
        [void][System.IO.Directory]::CreateDirectory($sdkDirectory)
        [void][System.IO.Directory]::CreateDirectory($referenceDirectory)
        $sdkPath = Join-Path $sdkDirectory 'DCCloneConfig.xml'
        $referencePath = Join-Path $referenceDirectory 'DCCloneConfig.xml'
        if ($case.Name -eq 'overwrite') {
            [System.IO.File]::WriteAllText($sdkPath, 'prior owned fixture')
            [System.IO.File]::WriteAllText($referencePath, 'prior owned fixture')
        }
        $entry = [ordered]@{ name = $case.Name; sdk_arguments = $case.Sdk; reference_arguments = $case.Reference; passed = $false; error = $null; sdk_sha256 = $null; reference_sha256 = $null }
        try {
            $arguments = @('-offline','-directory',$sdkDirectory) + $case.Sdk
            $output = (& $SdkBinary @arguments 2> (Join-Path $caseDirectory 'sdk.stderr.txt') | Out-String)
            $exitCode = $LASTEXITCODE
            [System.IO.File]::WriteAllText((Join-Path $caseDirectory 'sdk.json'), $output)
            if ($exitCode -ne 0) { throw "SDK exited $exitCode" }
            $sdkResult = $output | ConvertFrom-Json
            if (-not $sdkResult.checks_skipped -or $sdkResult.prerequisites.complete -or $sdkResult.outcome -ne 'written') { throw 'SDK did not report explicit offline publication.' }
            $referenceArguments = @{ Offline = $true; Path = $referenceDirectory; ErrorAction = 'Stop' }
            foreach ($key in $case.Reference.Keys) { $referenceArguments[$key] = $case.Reference[$key] }
            New-ADDCCloneConfigFile @referenceArguments *> (Join-Path $caseDirectory 'reference.streams.txt')
            $sdkDocument = Read-Configuration $sdkPath
            $referenceDocument = Read-Configuration $referencePath
            $sdkProjection = Project-Element $sdkDocument.DocumentElement | ConvertTo-Json -Depth 20 -Compress
            $referenceProjection = Project-Element $referenceDocument.DocumentElement | ConvertTo-Json -Depth 20 -Compress
            if (-not [string]::Equals($sdkProjection, $referenceProjection, [System.StringComparison]::Ordinal)) { throw 'Schema-valid XML projections differ.' }
            $entry.passed = $true
        } catch { $entry.error = $_.ToString() }
        if (Test-Path -LiteralPath $sdkPath -PathType Leaf) { $entry.sdk_sha256 = (Get-FileHash -LiteralPath $sdkPath -Algorithm SHA256).Hash }
        if (Test-Path -LiteralPath $referencePath -PathType Leaf) { $entry.reference_sha256 = (Get-FileHash -LiteralPath $referencePath -Algorithm SHA256).Hash }
        $results.Add($entry)
    }
    $assemblyPath = $command.ImplementingType.Assembly.Location
    $record = [ordered]@{
        collected_utc = [DateTime]::UtcNow.ToString('o'); computer = $env:COMPUTERNAME
        os_version = [Environment]::OSVersion.Version.ToString(); powershell = $PSVersionTable.PSVersion.ToString()
        module_version = $command.Module.Version.ToString(); assembly_version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($assemblyPath).FileVersion
        assembly_sha256 = (Get-FileHash -LiteralPath $assemblyPath -Algorithm SHA256).Hash
        sdk_sha256 = (Get-FileHash -LiteralPath $SdkBinary -Algorithm SHA256).Hash
        schema_evidence_sha256 = (Get-FileHash -LiteralPath $SchemaEvidence -Algorithm SHA256).Hash
        mode = 'explicit offline only'; cases = @($results.ToArray())
    }
    $record | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $runDirectory 'summary.json') -Encoding UTF8
    Write-Output $runDirectory
    if (@($results | Where-Object { -not $_.passed }).Count -ne 0) { throw 'One or more offline reference cases failed; inspect summary.json.' }
} finally {
    $env:ADPS_LoadDefaultDrive = $savedDefaultDrive
}
