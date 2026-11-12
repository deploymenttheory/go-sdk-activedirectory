#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$ExpectedHash,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$RunId
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Search test binary hash mismatch.' }
$domain=Get-ADDomain -Server $Server
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'Search fixtures require the isolated lab domain.' }
if ((Get-ADDomain -Server $Destination).DNSRoot -ne $domain.DNSRoot) { throw 'Search cleanup controllers must share the isolated domain.' }
$nonce=[guid]::NewGuid().ToString('N')
$name='ADSDK-Search-'+$nonce
$base="OU=$name,$($domain.DistinguishedName)"
$marker='ad-sdk-search:'+$nonce
$created=$false; $ouGuid=$null; $failure=$null; $cleanupFailure=$null; $reference=@(); $native=$null; $output=@(); $exitCode=$null
$clean=$false; $cleanupControllers=@(); $phase='fixture-creation'
$saved=@{}
foreach ($key in @('ADSDK_SEARCH_SERVER','ADSDK_SEARCH_BASE','ADSDK_SEARCH_RESULT')) { $saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process') }
function Remove-SearchFixtures([string]$Source,[string]$DomainDN,[string]$OUName,[string]$GUID,[string]$Marker) {
    $ErrorActionPreference='Stop'
    $owned=@(Get-ADOrganizationalUnit -LDAPFilter "(ou=$OUName)" -SearchBase $DomainDN -SearchScope OneLevel -Properties description -Server $Source)
    if (-not $owned.Count) { return }
    if ($owned.Count -ne 1 -or $owned[0].Description -cne $Marker -or ($GUID -and $owned[0].ObjectGUID.ToString() -ne $GUID)) { throw 'Search OU ownership mismatch; refusing cleanup.' }
    $children=@(Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $owned[0].DistinguishedName -SearchScope Subtree -Properties description -Server $Source | Sort-Object @{Expression={$_.DistinguishedName.Length};Descending=$true})
    foreach ($child in $children) {
        if ($child.Description -cne $Marker -or $child.Name -notmatch '^ADSDK-(Search-[0-6]|Nested)$') { throw 'Unexpected search fixture child; refusing cleanup.' }
    }
    $cleanupErrors=[Collections.Generic.List[Exception]]::new()
    foreach ($child in $children) {
        try { Remove-ADObject -Identity $child.ObjectGUID -Server $Source -Confirm:$false } catch { $cleanupErrors.Add($_.Exception) }
    }
    # Nonrecursive removal refuses unexpected or surviving children.
    try { Remove-ADOrganizationalUnit -Identity $owned[0].ObjectGUID -Server $Source -Confirm:$false } catch { $cleanupErrors.Add($_.Exception) }
    if ($cleanupErrors.Count) { throw [AggregateException]::new('Search fixture cleanup failed.',$cleanupErrors.ToArray()) }
}
try {
    $created=$true
    $ou=New-ADOrganizationalUnit -Name $name -Path $domain.DistinguishedName -Description $marker -ProtectedFromAccidentalDeletion:$false -Server $Server -PassThru
    $ouGuid=$ou.ObjectGUID
    foreach ($index in 0..6) { New-ADObject -Type container -Name "ADSDK-Search-$index" -Path $base -Description $marker -Server $Server }
    New-ADObject -Type container -Name 'ADSDK-Nested' -Path "CN=ADSDK-Search-0,$base" -Description $marker -Server $Server
    # Put the owned fixture on both controllers so absence after cleanup is
    # meaningful even when background replication has not yet run.
    Sync-ADObject -Object $ouGuid -Source $Server -Destination $Destination
    foreach ($object in @(Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $base -SearchScope Subtree -Server $Server | Sort-Object @{Expression={$_.DistinguishedName.Length}})) {
        Sync-ADObject -Object $object.ObjectGUID -Source $Server -Destination $Destination
    }
    $phase='reference'
    $objects=@(Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $base -SearchScope OneLevel -Properties objectGUID,description,displayName -ResultPageSize 2 -Server $Server)
    if ($objects.Count -ne 7) { throw 'Reference fixture count is not seven.' }
    $reference=@($objects | Sort-Object DistinguishedName | ForEach-Object { [ordered]@{dn=$_.DistinguishedName;guid_base64=[Convert]::ToBase64String($_.ObjectGUID.ToByteArray());description=$_.Description;display_name=$_.displayName} })
    $env:ADSDK_SEARCH_SERVER=$Server; $env:ADSDK_SEARCH_BASE=$base; $env:ADSDK_SEARCH_RESULT=$ResultPath
    $phase='native-search'
    try {
        $ErrorActionPreference='Continue'
        $output=@(& $Executable -test.run '^TestSearchLab$' -test.v -test.count=1 -test.timeout=90s 2>&1 | ForEach-Object { "$_" })
        $exitCode=$LASTEXITCODE
    } finally { $ErrorActionPreference='Stop' }
    if ($exitCode -ne 0) { throw 'Native search qualification failed.' }
    $phase='differential-comparison'
    $native=Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    if (-not $native.passed -or $native.objects.Count -ne $reference.Count) { throw 'Native search artifact failed or has the wrong count.' }
    $rows=@($native.objects | Sort-Object DistinguishedName)
    for ($index=0; $index -lt $reference.Count; $index++) {
        if ($rows[$index].DistinguishedName -ine $reference[$index].dn -or $rows[$index].Attributes.objectguid[0] -cne $reference[$index].guid_base64) { throw 'Get-ADObject and native DN/GUID projections differ.' }
        $description=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($rows[$index].Attributes.description[0]))
        if ($description -cne $reference[$index].description) { throw 'Get-ADObject and native descriptions differ.' }
    }
    $subtree=@(Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $base -SearchScope Subtree -ResultPageSize 2 -Server $Server)
    $limited=@(Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $base -SearchScope OneLevel -ResultPageSize 2 -ResultSetSize 3 -Server $Server)
    if ($subtree.Count -ne $native.subtree_count -or $limited.Count -ne $native.limited_count) { throw 'Get-ADObject and native scope/limit counts differ.' }
} catch { $failure=$_ }
finally {
    foreach ($key in $saved.Keys) { [Environment]::SetEnvironmentVariable($key,$saved[$key],'Process') }
    if ($created) {
        $cleanupErrors=[Collections.Generic.List[Exception]]::new()
        try { Remove-SearchFixtures $Server $domain.DistinguishedName $name $ouGuid $marker } catch { $cleanupErrors.Add($_.Exception) }
        try {
            $deadline=[DateTime]::UtcNow.AddMinutes(3)
            do {
                $cleanupControllers=@()
                $queryFailed=$false
                foreach ($controller in @($Server,$Destination)) {
                    try {
                        $remaining=@(Get-ADObject -LDAPFilter "(description=$marker)" -SearchBase $domain.DistinguishedName -Server $controller)
                        $cleanupControllers+=@([ordered]@{server=$controller;remaining=$remaining.Count;query_failed=$false})
                    } catch {
                        $queryFailed=$true; $cleanupErrors.Add($_.Exception)
                        $cleanupControllers+=@([ordered]@{server=$controller;remaining=$null;query_failed=$true})
                    }
                }
                if ($queryFailed) { break }
                if (@($cleanupControllers | Where-Object remaining -ne 0).Count -eq 0) { $clean=$true; break }
                if ($cleanupErrors.Count) { break }
                Start-Sleep -Seconds 3
            } while ([DateTime]::UtcNow -lt $deadline)
            if (-not $clean) { throw 'Search fixture cleanup was not confirmed on both controllers.' }
        } catch { $cleanupErrors.Add($_.Exception) }
        if ($cleanupErrors.Count) {
            try { throw [AggregateException]::new('Search cleanup or verification failed.',$cleanupErrors.ToArray()) } catch { $cleanupFailure=$_ }
        }
    }
}
$os=Get-CimInstance Win32_OperatingSystem
$module=Get-Module ActiveDirectory
[ordered]@{
    schema_version=1;run=$RunId;passed=($null -eq $failure -and $null -eq $cleanupFailure -and $clean); server=$Server; destination=$Destination; timestamp=[DateTime]::UtcNow.ToString('o')
    os_caption=$os.Caption; os_version=$os.Version; os_build=$os.BuildNumber; module_version=$module.Version.ToString(); powershell_version=$PSVersionTable.PSVersion.ToString()
    binary_sha256=$ExpectedHash; reference=$reference; native_exit_code=$exitCode; output=$output; fixture_cleanup_passed=$clean; cleanup_on_both_controllers=$cleanupControllers
    failure_phase=$(if ($failure) {$phase} else {$null}); failure_type=$(if ($failure) {$failure.Exception.GetType().FullName} else {$null}); cleanup_failure_type=$(if ($cleanupFailure) {$cleanupFailure.Exception.GetType().FullName} else {$null})
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath ($ResultPath+'.reference.json') -Encoding UTF8
if ($failure -and $cleanupFailure) { throw [AggregateException]::new('Search qualification and cleanup failed.',[Exception[]]@($failure.Exception,$cleanupFailure.Exception)) }
if ($failure) { throw $failure }
if ($cleanupFailure) { throw $cleanupFailure }
