#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureManifest,
    [Parameter(Mandatory)][string]$RunDirectory,
    [Parameter(Mandatory)][string]$RunID,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SDKRevision,
    [ValidateSet('core','trust','topology','extended')][string]$Profile='core',
    [string]$TrustPartner
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'directory-harness.ps1')
$Profile=$Profile.ToLowerInvariant()

function Get-DirectoryReferenceValue($Object,[string]$Name) {
    $property=$Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Set-DirectoryReferenceFacts($Fixture,[string]$Profile,[string]$TrustPartner,[string]$WorkingDirectory,[System.Collections.IDictionary]$Reference) {
    $facts=[ordered]@{};$Reference['facts']=$facts;$Reference['trust_verification']=@()
    $source=$Fixture.server
    $computer=Get-CimInstance Win32_ComputerSystem
    if ($computer.Name -ine $Fixture.client_computer) { throw 'Reference collector is running on the wrong fixture computer.' }
    $root=Get-ADRootDSE -Server $source
    if ($root.dnsHostName -ine $source -or -not $root.defaultNamingContext) { throw 'Reference RootDSE did not identify the pinned AD DS endpoint.' }
    Add-DirectoryFact $facts 'connected/server_dn' (Get-DirectoryReferenceValue $root 'serverName')
    Add-DirectoryFact $facts 'connected/gc_ready' (Get-DirectoryReferenceValue $root 'isGlobalCatalogReady')
    $domain=Get-ADDomain -Identity $root.defaultNamingContext -Server $source
    if ($domain.DNSRoot -ine $Fixture.domain_dns -or $domain.ObjectGUID -ne [guid]$Fixture.domain_guid) { throw 'Source domain does not match the provisioned fixture identity.' }
    $forest=Get-ADForest -Identity $domain.Forest -Server $source
    $controllers=@(Get-ADDomainController -Filter '*' -Server $source)
    if (-not $controllers.Count) { throw 'A positive controller fixture is required.' }
    Add-DirectoryFact $facts 'domain/dn' $domain.DistinguishedName
    Add-DirectoryFact $facts 'domain/guid.binary' (ConvertTo-DirectoryBinary $domain.ObjectGUID)
    Add-DirectoryFact $facts 'domain/sid.binary' (ConvertTo-DirectoryBinary $domain.DomainSID)
    foreach ($pair in @(@('name','Name'),@('dns_root','DNSRoot'),@('netbios','NetBIOSName'),@('forest','Forest'),@('managed_by','ManagedBy'),@('allowed_suffixes','AllowedDNSSuffixes'),@('subrefs','SubordinateReferences'),@('pdc','PDCEmulator'),@('rid','RIDMaster'),@('infrastructure','InfrastructureMaster'),@('parent','ParentDomain'),@('children','ChildDomains'),@('writable','ReplicaDirectoryServers'),@('read_only','ReadOnlyReplicaDirectoryServers'))) {
        Add-DirectoryFact $facts ('domain/'+$pair[0]) (Get-DirectoryReferenceValue $domain $pair[1])
    }
    Add-DirectoryFact $facts 'domain/level' ([int]$domain.DomainMode)
    $containers=[ordered]@{AA312825768811D1ADED00C04FD8D5CD='ComputersContainer';A9D1CA15768811D1ADED00C04FD8D5CD='UsersContainer';A361B2FFFFD211D1AA4B00C04FD7D83A='DomainControllersContainer';'18E2EA80684F11D2B9AA00C04F79F805'='DeletedObjectsContainer';'22B70C67D56E4EFB91E9300FCA3DC1AA'='ForeignSecurityPrincipalsContainer';AB8153B7768811D1ADED00C04FD8D5CD='LostAndFoundContainer';'6227F0AF1FC2410D8E3BB10615BB5B0F'='QuotasContainer';AB1D30F3768811D1ADED00C04FD8D5CD='SystemsContainer'}
    foreach ($id in $containers.Keys) { Add-DirectoryFact $facts ('domain/container/'+$id) (Get-DirectoryReferenceValue $domain $containers[$id]) }
    foreach ($pair in @(@('name','Name'),@('upn_suffixes','UPNSuffixes'),@('spn_suffixes','SPNSuffixes'),@('schema','SchemaMaster'),@('naming','DomainNamingMaster'),@('domains','Domains'),@('applications','ApplicationPartitions'),@('external','CrossForestReferences'),@('sites','Sites'),@('gcs','GlobalCatalogs'))) {
        Add-DirectoryFact $facts ('forest/'+$pair[0]) (Get-DirectoryReferenceValue $forest $pair[1])
    }
    Add-DirectoryFact $facts 'forest/level' ([int]$forest.ForestMode)
    foreach ($dc in $controllers) {
        $prefix='dc:'+$dc.ServerObjectDN+'/'
        foreach ($pair in @(@('server_dn','ServerObjectDN'),@('dsa_dn','NTDSSettingsObjectDN'),@('computer_dn','ComputerObjectDN'),@('host','HostName'),@('site','Site'),@('enabled','Enabled'),@('gc','IsGlobalCatalog'),@('read_only','IsReadOnly'),@('os','OperatingSystem'),@('os_version','OperatingSystemVersion'),@('service_pack','OperatingSystemServicePack'),@('partitions','Partitions'),@('roles','OperationMasterRoles'))) {
            Add-DirectoryFact $facts ($prefix+$pair[0]) (Get-DirectoryReferenceValue $dc $pair[1])
        }
        Add-DirectoryFact $facts ($prefix+'roles_known') $true
        $serverObject=Get-ADObject -Identity $dc.ServerObjectDN -Server $source -Properties objectGUID
        $dsa=Get-ADObject -Identity $dc.NTDSSettingsObjectDN -Server $source -Properties objectGUID,invocationId,'msDS-Behavior-Version'
        Add-DirectoryFact $facts ($prefix+'server_guid.binary') (ConvertTo-DirectoryBinary $serverObject.ObjectGUID)
        Add-DirectoryFact $facts ($prefix+'dsa_guid.binary') (ConvertTo-DirectoryBinary $dsa.ObjectGUID)
        Add-DirectoryFact $facts ($prefix+'invocation.binary') (ConvertTo-DirectoryBinary $dc.InvocationId)
        Add-DirectoryFact $facts ($prefix+'generation.schema') (Get-DirectoryReferenceValue $dsa 'msDS-Behavior-Version')
    }
    if ($Profile -in @('topology','extended')) {
        if (-not @($controllers | Where-Object IsReadOnly).Count -or -not @($controllers | Where-Object IsGlobalCatalog).Count -or -not @($controllers | Where-Object {-not $_.IsGlobalCatalog}).Count -or @($forest.Domains).Count -lt 2) { throw 'Topology profile requires an RODC, GC/non-GC controllers and multiple domains.' }
    }
    $trusts=@(Get-ADTrust -LDAPFilter '(objectClass=trustedDomain)' -Server $source)
    $selected=$null
    foreach ($trust in $trusts) {
        # Explicit allowlist only; trust authentication material is never read.
        $raw=Get-ADObject -Identity $trust.DistinguishedName -Server $source -Properties objectGUID,trustPartner,flatName,securityIdentifier,trustDirection,trustType,trustAttributes,'msDS-SupportedEncryptionTypes'
        if ($raw.ObjectGUID -ne $trust.ObjectGUID) { throw 'Trust cmdlet and LDAP object identities differ.' }
        $prefix='trust:'+$trust.DistinguishedName+'/'
        Add-DirectoryFact $facts ($prefix+'dn') $trust.DistinguishedName
        Add-DirectoryFact $facts ($prefix+'guid.binary') (ConvertTo-DirectoryBinary $trust.ObjectGUID)
        Add-DirectoryFact $facts ($prefix+'sid.binary') (ConvertTo-DirectoryBinary (Get-DirectoryReferenceValue $raw 'securityIdentifier'))
        Add-DirectoryFact $facts ($prefix+'partner') (Get-DirectoryReferenceValue $raw 'trustPartner')
        Add-DirectoryFact $facts ($prefix+'flat_name') (Get-DirectoryReferenceValue $raw 'flatName')
        foreach ($pair in @(@('direction.schema','trustDirection'),@('type.schema','trustType'),@('attributes.schema','trustAttributes'),@('encryption.schema','msDS-SupportedEncryptionTypes'))) { Add-DirectoryFact $facts ($prefix+$pair[0]) (ConvertTo-DirectoryMask (Get-DirectoryReferenceValue $raw $pair[1])) }
        if ($TrustPartner -and (Get-DirectoryReferenceValue $raw 'trustPartner') -ieq $TrustPartner) { if ($selected) {throw 'Ambiguous positive trust fixture.'};$selected=$raw }
    }
    if ($Profile -in @('trust','extended')) {
        if (-not $TrustPartner -or -not $selected -or [uint32]$selected.trustType -ne 2 -or ((ConvertTo-DirectoryMask $selected.trustAttributes) -band 32)) { throw 'Trust profile requires a named external AD trust.' }
        $partner=@($Fixture.trust_partners | Where-Object {$_.dns_name -ieq $TrustPartner})
        if ($partner.Count -ne 1) { throw 'Trust partner is not in the owned fixture manifest.' }
        $partnerRoot=Get-ADRootDSE -Server $partner[0].server
        if ($partnerRoot.dnsHostName -ine $partner[0].server -or -not $partnerRoot.defaultNamingContext) { throw 'Trust partner endpoint mismatch.' }
        $partnerDomain=Get-ADDomain -Identity $partnerRoot.defaultNamingContext -Server $partner[0].server
        if ($partnerDomain.DNSRoot -ine $partner[0].dns_name -or $partnerDomain.ObjectGUID -ne [guid]$partner[0].domain_guid) { throw 'Trust partner does not match its provisioned domain identity.' }
        $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Trust verification requires an elevated fixture session.' }
        $netdom=Join-Path $env:SystemRoot 'System32\netdom.exe'
        $pairs=@(Get-DirectoryTrustPairs ([uint32]$selected.trustDirection) $domain.DNSRoot $TrustPartner)
        foreach ($pair in $pairs) {
            $verification=Invoke-DirectoryTrustVerification $netdom $WorkingDirectory $TrustPartner $pair[0] $pair[1]
            $Reference['trust_verification']+=@($verification)
            if ($verification.timed_out -or $null -eq $verification.exit_code -or $verification.exit_code -ne 0) { throw 'Actual trust secure-channel verification failed.' }
        }
    } elseif ($TrustPartner) { throw 'TrustPartner requires the trust or extended profile.' }
    $os=Get-CimInstance Win32_OperatingSystem
    $module=Get-Module ActiveDirectory
    $Reference['collector_environment']=[ordered]@{computer_name=$computer.Name;os_caption=$os.Caption;os_version=$os.Version;os_build=$os.BuildNumber;architecture=$os.OSArchitecture;module_version=$module.Version.ToString();powershell_version=$PSVersionTable.PSVersion.ToString()}
    $Reference['source_directory_os']=@($controllers | Where-Object {$_.HostName -ieq $source} | ForEach-Object {[ordered]@{host=$_.HostName;os=$_.OperatingSystem;version=$_.OperatingSystemVersion}})
}

$fixture=Read-DirectoryFixture $FixtureManifest
$run=Assert-DirectoryRun $RunDirectory $RunID $fixture.fixture_id
$reference=[ordered]@{schema_version=1;fixture_id=$fixture.fixture_id;run_id=$RunID;profile=$Profile;server=$fixture.server;sdk_revision=$SDKRevision;server_version_label=$fixture.server_version;server_os_independently_verified=$false;fixture_sha256=(Get-FileHash -LiteralPath $FixtureManifest -Algorithm SHA256).Hash;collector_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;timestamp=[DateTime]::UtcNow.ToString('o');facts=[ordered]@{};trust_verification=@();passed=$false;full_ticket_complete=$false;failure_type=$null}
$failure=$null
try {
    Import-Module ActiveDirectory
    Set-DirectoryReferenceFacts $fixture $Profile $TrustPartner $run $reference
    $reference.passed=$true
} catch { $failure=$_;$reference.failure_type=$_.Exception.GetType().FullName }
finally { $null=Assert-DirectoryRun $run $RunID $fixture.fixture_id;Write-DirectoryNewJSON (Join-Path $run 'reference.json') $reference }
if ($failure) { throw 'Directory reference collection failed; inspect the redacted reference artifact.' }
