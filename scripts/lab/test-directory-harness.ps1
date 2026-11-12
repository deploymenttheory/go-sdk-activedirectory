#Requires -Version 5.1
# Offline tests only: AD cmdlets and trust process execution are mocked below.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'directory-harness.ps1')
foreach ($name in @('directory-harness.ps1','reference-directory.ps1','test-directory.ps1')) {
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count) {throw "Syntax error in $name."}
    if ($name -eq 'reference-directory.ps1') {
        foreach ($functionName in @('Get-DirectoryReferenceValue','Set-DirectoryReferenceFacts')) {
            $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName},$true)
            if (-not $definition) {throw 'Reference helper missing.'}
            . ([scriptblock]::Create($definition.Extent.Text))
        }
    }
}
function Assert-Test([bool]$Condition,[string]$Message) {if (-not $Condition) {throw $Message}}
function Assert-Rejected([scriptblock]$Action,[string]$Message) {$caught=$false;try{& $Action}catch{$caught=$true};Assert-Test $caught $Message}
$temporaryRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$scratch=[IO.Path]::GetFullPath((Join-Path $temporaryRoot ('ad-sdk-directory-tests-'+[guid]::NewGuid().ToString('N'))))
if (-not $scratch.StartsWith($temporaryRoot.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected scratch path.'}
$null=New-Item -ItemType Directory -Path $scratch
try {
    $fixture=[pscustomobject]@{schema_version=1;purpose='go-sdk-activedirectory-isolated-lab';fixture_id='offline-test';domain_dns='ad.sdk.test';domain_guid='11111111-1111-1111-1111-111111111111';server='dc1.ad.sdk.test';client_computer='SDKTEST';server_version='2025';trust_partners=@()}
    $manifest=Join-Path $scratch 'fixture.json'
    Write-DirectoryNewJSON $manifest $fixture
    $parsed=Read-DirectoryFixture $manifest
    Assert-Test ($parsed.domain_dns -eq 'ad.sdk.test') 'Fixture parsing changed identity.'
    Assert-Rejected {Write-DirectoryNewJSON $manifest @{changed=$true}} 'Existing artifact was overwritten.'
    Assert-Test ((Read-DirectoryFixture $manifest).domain_dns -eq 'ad.sdk.test') 'Overwrite rejection changed the existing artifact.'
    $bad=Join-Path $scratch 'bad-fixture.json';$fixture | Add-Member NoteProperty password 'synthetic-private-value'
    Write-DirectoryNewJSON $bad $fixture
    Assert-Rejected {Read-DirectoryFixture $bad} 'Manifest accepted an arbitrary secret payload.'
    $fixture.PSObject.Properties.Remove('password')
    foreach ($field in @('fixture_id','client_computer')) {
        $original=$fixture.$field;$fixture.$field=$original+"`n"
        $invalid=Join-Path $scratch ($field+'-newline.json');Write-DirectoryNewJSON $invalid $fixture
        Assert-Rejected {Read-DirectoryFixture $invalid} 'Fixture identifier accepted a trailing newline.'
        $fixture.$field=$original
    }
    foreach ($name in @('ad.sdk.test /Reset','ad.sdk.test:389','ad.sdk.test"',('ad.sdk.test'+"`n"),'short')) {Assert-Rejected {Assert-DirectoryDNSName $name} 'Invalid target syntax was accepted.'}
    $run=New-DirectoryRun $scratch $fixture.fixture_id ('a'*64)
    $null=Assert-DirectoryRun $run.Path $run.ID $fixture.fixture_id
    Assert-Rejected {Assert-DirectoryRun $run.Path $run.ID 'different-fixture'} 'Foreign artifact owner was accepted.'
    Assert-Rejected {Assert-DirectoryRun $run.Path 'different-run' $fixture.fixture_id} 'Foreign run identity was accepted.'
    Assert-Rejected {ConvertTo-DirectoryHashMap ([pscustomobject]@{'../go.mod'=('a'*64)}) 'source'} 'Prepared snapshot accepted path traversal.'
    $sourceHashes=ConvertTo-DirectoryHashMap ([pscustomobject]@{'go.mod'=('a'*64);'go.sum'=('b'*64)}) 'source'
    Assert-Test ($sourceHashes.Count -eq 2) 'Prepared module hash map changed.'
    $facts=[ordered]@{}
    Add-DirectoryFact $facts 'empty' @();Add-DirectoryFact $facts 'names' @('B','a');Add-DirectoryFact $facts 'guid.binary' 'AbC='
    Assert-Test ($facts.empty.Count -eq 0 -and ($facts.names -join ',') -ceq 'a,b' -and $facts['guid.binary'][0] -ceq 'AbC=') 'Fact normalization lost arrays or binary case.'
    Assert-Test ((ConvertTo-DirectoryMask -2147483640) -eq 2147483656) 'Signed bitmask was not preserved.'
    foreach ($direction in 1,2,3) {
        $pairs=@(Get-DirectoryTrustPairs $direction 'ad.sdk.test' 'partner.test')
        $expected=if ($direction -eq 1) {'partner.test>ad.sdk.test'} elseif ($direction -eq 2) {'ad.sdk.test>partner.test'} else {'ad.sdk.test>partner.test,partner.test>ad.sdk.test'}
        Assert-Test ((@($pairs | ForEach-Object {$_ -join '>'}) -join ',') -ceq $expected) 'Trust direction mapping changed.'
    }
    Assert-Rejected {Get-DirectoryTrustPairs 0 'ad.sdk.test' 'partner.test'} 'Disabled trust passed a positive gate.'
    Assert-Rejected {Get-DirectoryTrustPairs 3 'ad.sdk.test' 'ad.sdk.test'} 'Self trust passed a positive gate.'
    Assert-Test ((ConvertTo-DirectoryProcessArgument 'C:\path with spaces\') -ceq '"C:\path with spaces\\"') 'Trailing-backslash command-line quoting failed.'
    Assert-Test ((ConvertTo-DirectoryProcessArgument 'a"b') -ceq '"a\"b"') 'Quote escaping failed.'
    $processScript=Join-Path $scratch 'arguments.ps1'
    Write-DirectoryNewText $processScript 'param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Values); ConvertTo-Json -InputObject @($Values) -Compress'
    $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments=@('a b','C:\trailing\','a"b','$(literal-not-executed)')
    $execution=Invoke-DirectoryProcess $powershell (@('-NoProfile','-NonInteractive','-File',$processScript)+$arguments) $scratch 15 @{PSModulePath=$null}
    Assert-Test ($execution.ExitCode -eq 0 -and -not $execution.TimedOut) 'Owned process failed.'
    $actual=ConvertFrom-Json -InputObject $execution.Stdout
    Assert-Test ($actual.Count -eq $arguments.Count) 'Process argument count changed.'
    for ($index=0;$index -lt $arguments.Count;$index++) {Assert-Test ([string]$actual[$index] -ceq $arguments[$index]) 'Process argument round trip changed a value.'}
    $sleepScript=Join-Path $scratch 'sleep.ps1';Write-DirectoryNewText $sleepScript 'Start-Sleep -Seconds 10'
    $execution=Invoke-DirectoryProcess $powershell @('-NoProfile','-NonInteractive','-File',$sleepScript) $scratch 1 @{PSModulePath=$null}
    Assert-Test ($execution.TimedOut -and $null -eq $execution.ExitCode) 'Process timeout was reported as success.'

    function Test-TrustInvocation {
        $capture=[Collections.Generic.List[object]]::new()
        function Invoke-DirectoryProcess($Executable,$Arguments,$WorkingDirectory,$TimeoutSeconds,$Environment) {
            $capture.Add([pscustomobject]@{arguments=$Arguments;timeout=$TimeoutSeconds})
            return [pscustomobject]@{ExitCode=0;TimedOut=$false;Stdout='synthetic-secret';Stderr='synthetic-secret'}
        }
        $receipt=Invoke-DirectoryTrustVerification $processScript $scratch 'partner.test' 'ad.sdk.test' 'partner.test'
        Assert-Test (($capture[0].arguments -join '|') -ceq 'trust|ad.sdk.test|/Domain:partner.test|/Verify' -and $capture[0].timeout -eq 60) 'Verification invoked an unexpected or mutable command.'
        Assert-Test (($receipt | ConvertTo-Json -Compress) -notmatch 'synthetic-secret') 'Raw process output leaked into verification evidence.'
    }
    Test-TrustInvocation

    function Test-ReferenceCollector {
        $domainDN='DC=ad,DC=sdk,DC=test';$config='CN=Configuration,'+$domainDN;$site='CN=Site,CN=Sites,'+$config
        $serverDN='CN=DC1,CN=Servers,'+$site;$dsaDN='CN=NTDS Settings,'+$serverDN;$trustDN='CN=partner.test,CN=System,'+$domainDN
        $sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3')
        function Get-CimInstance($ClassName) {
            if ($ClassName -eq 'Win32_ComputerSystem') {return [pscustomobject]@{Name='SDKTEST'}}
            return [pscustomobject]@{Caption='Synthetic OS';Version='10.0';BuildNumber='123';OSArchitecture='64-bit'}
        }
        function Get-Module($Name) {return [pscustomobject]@{Version=[version]'1.0'}}
        function Get-ADRootDSE($Server) {Assert-Test ($Server -eq $fixture.server) 'Unexpected reference server.';return [pscustomobject]@{dnsHostName=$Server;defaultNamingContext=$domainDN}}
        function Get-ADDomain($Identity,$Server) {
            Assert-Test ($Server -eq $fixture.server -and $Identity -eq $domainDN) 'Domain endpoint/identity changed.'
            return [pscustomobject]@{ObjectGUID=[guid]$fixture.domain_guid;DistinguishedName=$domainDN;DNSRoot=$fixture.domain_dns;DomainSID=$sid;Forest='ad.sdk.test';DomainMode=7;Name='ad';NetBIOSName='AD';ReplicaDirectoryServers=@($fixture.server);ChildDomains=@();SystemsContainer='CN=System,'+$domainDN}
        }
        function Get-ADForest($Identity,$Server) {return [pscustomobject]@{Name='ad.sdk.test';ForestMode=7;Domains=@('ad.sdk.test');GlobalCatalogs=@($fixture.server);Sites=@('Site')}}
        function Get-ADDomainController($Filter,$Server) {
            Assert-Test ($Filter -ceq '*' -and $Server -eq $fixture.server) 'Controller query scope changed.'
            return [pscustomobject]@{ServerObjectDN=$serverDN;NTDSSettingsObjectDN=$dsaDN;ComputerObjectDN='CN=DC1,'+$domainDN;HostName=$fixture.server;Site='Site';Enabled=$true;IsGlobalCatalog=$true;IsReadOnly=$false;OperatingSystem='Synthetic';OperatingSystemVersion='10.0';OperatingSystemServicePack=$null;Partitions=@($domainDN,$config);OperationMasterRoles=@('PDCEmulator');InvocationId=[guid]'33333333-3333-3333-3333-333333333333'}
        }
        function Get-ADTrust($LDAPFilter,$Server) {Assert-Test ($LDAPFilter -ceq '(objectClass=trustedDomain)' -and $Server -eq $fixture.server) 'Trust LDAP query changed.';return [pscustomobject]@{DistinguishedName=$trustDN;ObjectGUID=[guid]'44444444-4444-4444-4444-444444444444'}}
        function Get-ADObject($Identity,$Server,$Properties) {
            Assert-Test ($Server -eq $fixture.server -and @($Properties | Where-Object {$_ -eq '*' -or $_ -like 'trustAuth*'}).Count -eq 0) 'Reference collector requested unrestricted/secret properties.'
            if ($Identity -eq $serverDN) {return [pscustomobject]@{ObjectGUID=[guid]'22222222-2222-2222-2222-222222222222'}}
            if ($Identity -eq $dsaDN) {return [pscustomobject]@{ObjectGUID=[guid]'55555555-5555-5555-5555-555555555555';'msDS-Behavior-Version'=10}}
            if ($Identity -eq $trustDN) {return [pscustomobject]@{ObjectGUID=[guid]'44444444-4444-4444-4444-444444444444';trustPartner='partner.test';flatName='PARTNER';securityIdentifier=$sid;trustDirection=3;trustType=2;trustAttributes=-2147483640}}
            throw 'Unexpected reference object read.'
        }
        function Invoke-DirectoryTrustVerification {throw 'Core profile must not execute trust verification.'}
        $reference=[ordered]@{}
        Set-DirectoryReferenceFacts $fixture 'core' '' $scratch $reference
        Assert-Test ($reference.facts['domain/guid.binary'][0] -ceq [Convert]::ToBase64String(([guid]$fixture.domain_guid).ToByteArray())) 'Domain GUID conversion failed.'
        Assert-Test ($reference.facts[('trust:'+$trustDN.ToLowerInvariant()+'/attributes.schema')][0] -ceq '2147483656') 'Reference mask lost unknown bits.'
        Assert-Test ($reference.facts['forest/domains'].Count -eq 1 -and $reference.facts['forest/upn_suffixes'].Count -eq 0) 'Reference array cardinality changed.'
        Assert-Test ($reference.trust_verification.Count -eq 0) 'Core profile claimed trust verification.'
        Assert-Rejected {Set-DirectoryReferenceFacts $fixture 'topology' '' $scratch ([ordered]@{})} 'Missing RODC/multidomain fixture passed.'
        $original=$fixture.domain_guid;$fixture.domain_guid='99999999-9999-9999-9999-999999999999'
        # The mocked live domain uses a fixed original GUID for this check.
        function Get-ADDomain {return [pscustomobject]@{ObjectGUID=[guid]'11111111-1111-1111-1111-111111111111';DNSRoot='ad.sdk.test'}}
        Assert-Rejected {Set-DirectoryReferenceFacts $fixture 'core' '' $scratch ([ordered]@{})} 'Wrong provisioned domain GUID passed.'
        $fixture.domain_guid=$original
        $output=Join-Path $scratch 'facts.json';Write-DirectoryNewJSON $output $reference
        $bytes=[IO.File]::ReadAllBytes($output);Assert-Test (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) 'Reference JSON contains a BOM.'
    }
    Test-ReferenceCollector

    # A deliberately invalid prepared binary must fail before either the
    # collector or test executable can run. No directory module is imported.
    $bundle=New-DirectoryRun $scratch $fixture.fixture_id ('b'*64)
    $bundleSource=Join-Path $bundle.Path 'source';$bundleHarness=Join-Path $bundle.Path 'harness'
    $null=New-Item -ItemType Directory -Path $bundleSource,$bundleHarness
    Write-DirectoryNewJSON (Join-Path $bundle.Path 'fixture.json') $fixture
    $hashes=[ordered]@{}
    foreach ($name in @('go.mod','go.sum')) {Write-DirectoryNewText (Join-Path $bundleSource $name) 'synthetic';$hashes[$name]=(Get-FileHash -LiteralPath (Join-Path $bundleSource $name)).Hash}
    $harnessHashes=[ordered]@{}
    foreach ($name in @('directory-harness.ps1','reference-directory.ps1','test-directory.ps1')) {Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $bundleHarness;$harnessHashes[$name]=(Get-FileHash -LiteralPath (Join-Path $bundleHarness $name)).Hash}
    Write-DirectoryNewText (Join-Path $bundle.Path 'directory.test.exe') 'not an executable'
    Write-DirectoryNewJSON (Join-Path $bundle.Path 'preparation.json') ([ordered]@{schema_version=1;prepared=$true;run_id=$bundle.ID;fixture_id=$fixture.fixture_id;profile='core';trust_partner='';architecture='amd64';source_revision=('a'*40);source_sha256=$hashes;harness_sha256=$harnessHashes;binary_sha256=('0'*64);toolchain='synthetic';supplied_fixture_sha256=('b'*64);fixture_snapshot_sha256=(Get-FileHash -LiteralPath (Join-Path $bundle.Path 'fixture.json')).Hash})
    $execution=Invoke-DirectoryProcess $powershell @('-NoProfile','-NonInteractive','-File',(Join-Path $bundleHarness 'test-directory.ps1'),'-PreparedRun',$bundle.Path) $scratch 20 @{PSModulePath=$null}
    Assert-Test ($execution.ExitCode -ne 0 -and -not $execution.TimedOut) 'Tampered prepared binary was accepted.'
    if (-not (Test-Path -LiteralPath (Join-Path $bundle.Path 'manifest.json'))) {throw ('Prepared run did not reach its checked failure: '+$execution.Stderr)}
    $failedRun=Get-Content -LiteralPath (Join-Path $bundle.Path 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Test (-not $failedRun.passed -and $failedRun.failure_phase -eq 'prepared-input-check' -and -not $failedRun.full_ticket_complete) 'Prepared input failure artifact was not retained.'
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $bundle.Path 'reference.json'))) 'Tampered bundle reached directory reference collection.'
    Assert-Rejected {& (Join-Path $PSScriptRoot 'test-directory.ps1') -PreparedRun $bundle.Path} 'Failed prepared run was reused.'
    Write-Output 'Directory harness offline checks passed; no AD server or trust verification was contacted.'
} finally {
    # Delete only this test's freshly created tree, with each target checked.
    $prefix=$scratch.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
    foreach ($file in @(Get-ChildItem -LiteralPath $scratch -File -Recurse)) {
        if (-not ([IO.Path]::GetFullPath($file.FullName)).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {throw 'Scratch cleanup target escaped its owned root.'}
        Remove-Item -LiteralPath $file.FullName
    }
    foreach ($directory in @(Get-ChildItem -LiteralPath $scratch -Directory -Recurse | Sort-Object {$_.FullName.Length} -Descending)) {
        if (-not ([IO.Path]::GetFullPath($directory.FullName)).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {throw 'Scratch cleanup target escaped its owned root.'}
        Remove-Item -LiteralPath $directory.FullName
    }
    if (([IO.Path]::GetFullPath($scratch)).StartsWith($temporaryRoot.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {Remove-Item -LiteralPath $scratch}
}
