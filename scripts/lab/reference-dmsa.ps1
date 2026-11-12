#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('start-unlinked','complete-started','undo-started','undo-completed','reset-started','reset-completed','reset-unlinked')][string]$Scenario,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$ExpectedDomainSID,
    [Parameter(Mandatory)][guid]$LabId,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$ResultPath,
    [switch]$AllowMigration,
    [switch]$AllowAcceleratedLabTransition
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Both switches must be explicit. This exploratory runner never claims full
# evidence and never invokes a guessed Undo/Reset compensation after failure.
if(-not $AllowMigration -or -not $AllowAcceleratedLabTransition) {throw 'Explicit AllowMigration and AllowAcceleratedLabTransition are required for this disposable reference runner.'}
if($Source -eq $Destination) {throw 'Two different writable Server 2025 DCs are required.'}
. (Join-Path $PSScriptRoot 'dmsa-capture.ps1')
Import-Module ActiveDirectory
$domain=Get-ADDomain -Server $Source
$remoteDomain=Get-ADDomain -Server $Destination
if($domain.DNSRoot -ne 'ad.sdk.test' -or $domain.DomainSID.Value -ne $ExpectedDomainSID -or $remoteDomain.DomainSID.Value -ne $ExpectedDomainSID) {throw 'The explicitly owned disposable domain does not match.'}
$os=Get-CimInstance Win32_OperatingSystem
if($os.Caption -notmatch 'Windows Server 2025' -or -not (Test-ComputerSecureChannel)) {throw 'Run this reference on an owned Server 2025 member with a healthy secure channel.'}
$clientPolicy=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name DelegatedMSAEnabled
if($clientPolicy.DelegatedMSAEnabled -ne 1) {throw 'Client dMSA policy has not been enabled by provisioning.'}
$keySets=@()
foreach($server in @($Source,$Destination)) {
    $dc=Get-ADDomainController -Identity $server -Server $server
    if($dc.IsReadOnly -or $dc.OperatingSystem -notmatch 'Windows Server 2025') {throw 'Reference endpoint must be a writable Server 2025 DC.'}
    $root=Get-ADRootDSE -Server $server
    $schemaNames=@('msDS-DelegatedManagedServiceAccount','msDS-DelegatedMSAState','msDS-SupersededServiceAccountState','msDS-ManagedAccountPrecededByLink','msDS-ManagedAccountPrecededByLinkBL','msDS-SupersededManagedAccountLink','msDS-SupersededManagedAccountLinkBL')
    foreach($name in $schemaNames) {
        if(@(Get-ADObject -LDAPFilter "(lDAPDisplayName=$name)" -SearchBase $root.schemaNamingContext -Server $server).Count -ne 1) {throw 'Required dMSA schema is missing.'}
    }
    $keyBase="CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($root.configurationNamingContext)"
    $ready=@(Get-ADObject -LDAPFilter '(objectClass=msKds-ProvRootKey)' -SearchBase $keyBase -Server $server -Properties 'msKds-CreateTime','msKds-UseStartTime' | Where-Object {
        [DateTime]::FromFileTimeUtc([long]$_.'msKds-CreateTime').AddHours(10) -le [DateTime]::UtcNow -and
        [DateTime]::FromFileTimeUtc([long]$_.'msKds-UseStartTime') -le [DateTime]::UtcNow
    } | ForEach-Object {$_.ObjectGUID.ToString()})
    $keySets+=,@($ready)
}
if(@($keySets[0] | Where-Object {$_ -in $keySets[1]}).Count -eq 0) {throw 'No matching effective KDS key aged at least ten hours was observed on both DCs.'}
if(-not (Get-Command New-ADServiceAccount).Parameters.ContainsKey('CreateDelegatedServiceAccount')) {throw 'The installed module lacks dMSA creation support.'}
$resultRoot=[IO.Path]::GetFullPath($ResultPath)
if(Test-Path -LiteralPath $resultRoot) {throw 'Use a new result directory for each run.'}
$parent=[IO.Path]::GetDirectoryName($resultRoot)
while($parent) {
    if((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Result path contains a reparse point.'}
    $parent=[IO.Path]::GetDirectoryName($parent)
}
$null=New-Item -ItemType Directory -Path $resultRoot
$runId=[guid]::NewGuid().ToString('N');$suffix=$runId.Substring(0,10)
$marker="ad-sdk-dmsa:$($LabId.ToString()):$runId"
$ouDN="OU=ADSDK-DMSA-$suffix,$($domain.DistinguishedName)"
$legacyName="sdkl$suffix";$dmsaName="sdkd$suffix"
$ledger=@(
    [pscustomobject]@{role='legacy';guid='';sid='';dn="CN=$legacyName,$ouDN";class='user';marker=$marker},
    [pscustomobject]@{role='dmsa';guid='';sid='';dn="CN=$dmsaName,$ouDN";class='msDS-DelegatedManagedServiceAccount';marker=$marker},
    [pscustomobject]@{role='ou';guid='';sid='';dn=$ouDN;class='organizationalUnit';marker=$marker}
)
$null=Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $resultRoot 'runner.ps1')
$null=Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'dmsa-capture.ps1') -Destination (Join-Path $resultRoot 'capture.ps1')
$artifactOf={param($name) [ordered]@{path=$name;sha256=(Get-FileHash -LiteralPath (Join-Path $resultRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()}}
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$module=Get-Module ActiveDirectory
$assembly=(Get-Command Start-ADServiceAccountMigration).ImplementingType.Assembly.Location
$forest=Get-ADForest -Server $Source
$environment=[ordered]@{run_id=$runId;lab_id=$LabId.ToString();domain_sid=$ExpectedDomainSID;os_build="$($build.CurrentBuild).$($build.UBR)";architecture=$env:PROCESSOR_ARCHITECTURE;powershell=$PSVersionTable.PSVersion.ToString();module_version=$module.Version.ToString();module_file_version=(Get-Item -LiteralPath $assembly).VersionInfo.FileVersion;module_sha256=(Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash.ToLowerInvariant();schema_version=[int](Get-ADObject -Identity $root.schemaNamingContext -Server $Source -Properties objectVersion).objectVersion;domain_level=$domain.DomainMode.ToString();forest_level=$forest.ForestMode.ToString();servers=@($Source,$Destination);observed_at=[DateTime]::UtcNow.ToString('o')}
$emptyArtifact=[ordered]@{path='';sha256=''}
$case=[ordered]@{id=$Scenario;family='minimal';command=($Scenario.Split('-')[0]+'-ADServiceAccountMigration');outcome='not_run';errors=@();before=$emptyArtifact;after=$emptyArtifact;replicated=$emptyArtifact;recovery_target=$emptyArtifact;recovered=$emptyArtifact;cleanup=@();effects=@();recovery_effects=@();service=@();credentials=@();unresolved=@('Accelerated lab observation; documented rollout waiting guidance was not exercised.','Service/credential probes and reviewed side effects are not implemented in this initial runner.','Recovery has not been inferred or attempted; the command under test may itself be Undo or Reset.')}
$run=[ordered]@{schema_version=1;run_id=$runId;lab_id=$LabId.ToString();domain_sid=$ExpectedDomainSID;provenance=[ordered]@{source_commit=$SourceCommit;runner=(& $artifactOf 'runner.ps1');capture=(& $artifactOf 'capture.ps1');environment=(Write-DmsaArtifact $resultRoot 'environment.json' $environment)};cases=@($case);unresolved=@('Initial minimal transition capture only; populated, permission, partial-failure and independent service/credential scenarios remain missing.')}
$connection=$null;$remoteConnection=$null;$created=$false;$targets=@();$failure=$null
try {
    $connection=New-DmsaLdapConnection $Source;$remoteConnection=New-DmsaLdapConnection $Destination
    $created=$true
    $ou=New-ADOrganizationalUnit -Name "ADSDK-DMSA-$suffix" -Path $domain.DistinguishedName -Description $marker -ProtectedFromAccidentalDeletion:$false -Server $Source -PassThru
    $ledger[2].guid=$ou.ObjectGUID.ToString()
    $password=ConvertTo-SecureString ('Aa9!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $legacy=New-ADUser -Name $legacyName -SamAccountName $legacyName -Path $ouDN -Description $marker -Enabled:$true -AccountPassword $password -ChangePasswordAtLogon:$false -Server $Source -PassThru
    $ledger[0].guid=$legacy.ObjectGUID.ToString();$ledger[0].sid=$legacy.SID.Value
    $member=Get-ADComputer -Identity $env:COMPUTERNAME -Server $Source
    $dmsa=New-ADServiceAccount -Name $dmsaName -SamAccountName $dmsaName -Path $ouDN -Description $marker -DNSHostName "$dmsaName.$($domain.DNSRoot)" -CreateDelegatedServiceAccount -KerberosEncryptionType AES256 -PrincipalsAllowedToRetrieveManagedPassword $member -Server $Source -PassThru
    $ledger[1].guid=$dmsa.ObjectGUID.ToString();$ledger[1].sid=$dmsa.SID.Value
    $targets=@($ledger[0],$ledger[1],$ledger[2])
    $null=Write-DmsaArtifact $resultRoot 'owned-fixtures.json' @($ledger)
    $baseline=Get-DmsaCapture $connection $Source $runId $Scenario 'recovery_target' $targets
    $case.recovery_target=Write-DmsaArtifact $resultRoot 'recovery-target.json' $baseline
    if($baseline.errors.Count) {throw 'Independent baseline capture failed; refusing migration.'}
    $parameters=@{Identity=[guid]$ledger[1].guid;SupersededAccount=$ledger[0].dn;Server=$Source;ErrorAction='Stop'}
    if($Scenario -ne 'start-unlinked' -and $Scenario -ne 'reset-unlinked') {Start-ADServiceAccountMigration @parameters}
    if($Scenario -in @('undo-completed','reset-completed')) {Complete-ADServiceAccountMigration @parameters}
    $before=Get-DmsaCapture $connection $Source $runId $Scenario 'before' $targets
    $case.before=Write-DmsaArtifact $resultRoot 'before.json' $before
    if($before.errors.Count) {throw 'Independent pre-operation capture failed; refusing migration.'}
    try {& $case.command @parameters;$case.outcome='success'} catch {$case.outcome='error';$case.errors=@(Get-DmsaError $_)}
    $case.after=Write-DmsaArtifact $resultRoot 'after.json' (Get-DmsaCapture $connection $Source $runId $Scenario 'after' $targets)
    foreach($item in @($ledger[2],$ledger[0],$ledger[1])) {Sync-ADObject -Object ([guid]$item.guid) -Source $Source -Destination $Destination}
    $case.replicated=Write-DmsaArtifact $resultRoot 'replicated.json' (Get-DmsaCapture $remoteConnection $Destination $runId $Scenario 'replicated' $targets)
} catch {$failure=$_;$case.unresolved+=@('Fixture preparation or capture failed.');$case.errors+=@(Get-DmsaError $_)}
finally {
    if($created) {
        try {Remove-DmsaOwnedFixtures $ledger $marker $Source} catch {$case.unresolved+=@('Owned fixture cleanup failed.');$case.errors+=@(Get-DmsaError $_)}
        if($targets.Count -eq 3 -and $connection -and $remoteConnection) {
            foreach($endpoint in @(@($Source,$connection),@($Destination,$remoteConnection))) {
                $server=$endpoint[0];$channel=$endpoint[1];$point=$null;$deadline=[DateTime]::UtcNow.AddMinutes(3)
                do {
                    $point=Get-DmsaCapture $channel $server $runId $Scenario 'cleanup' $targets
                    if(@($point.objects | Where-Object status -ne 'absent').Count -eq 0 -and $point.errors.Count -eq 0) {break}
                    Start-Sleep -Seconds 2
                } while([DateTime]::UtcNow -lt $deadline)
                $name=if($server -eq $Source){'cleanup-source.json'}else{'cleanup-destination.json'}
                $case.cleanup+=@(Write-DmsaArtifact $resultRoot $name $point)
            }
        }
    }
    if($connection){$connection.Dispose()};if($remoteConnection){$remoteConnection.Dispose()}
    $null=Write-DmsaArtifact $resultRoot 'run.json' $run
}
if($failure) {throw 'DMSA exploratory fixture failed; inspect retained nonsecret evidence.'}
Write-Output 'Observation captured; evidence remains incomplete. Cleanup does not establish recovery.'
