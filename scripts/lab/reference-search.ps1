#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$ExpectedHash
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Search test binary hash mismatch.' }
$domain=Get-ADDomain -Server $Server
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'Search fixtures require the isolated lab domain.' }
$nonce=[guid]::NewGuid().ToString('N')
$name='ADSDK-Search-'+$nonce
$base="OU=$name,$($domain.DistinguishedName)"
$marker='ad-sdk-search:'+$nonce
$created=$false; $ouGuid=$null; $failure=$null; $cleanupFailure=$null; $reference=@(); $native=$null; $output=@(); $exitCode=$null
$saved=@{}
foreach ($key in @('ADSDK_SEARCH_SERVER','ADSDK_SEARCH_BASE','ADSDK_SEARCH_RESULT')) { $saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process') }
try {
    $created=$true
    $ou=New-ADOrganizationalUnit -Name $name -Path $domain.DistinguishedName -Description $marker -ProtectedFromAccidentalDeletion:$false -Server $Server -PassThru
    $ouGuid=$ou.ObjectGUID
    foreach ($index in 0..6) { New-ADObject -Type container -Name "ADSDK-Search-$index" -Path $base -Description $marker -Server $Server }
    New-ADObject -Type container -Name 'ADSDK-Nested' -Path "CN=ADSDK-Search-0,$base" -Description $marker -Server $Server
    $objects=@(Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $base -SearchScope OneLevel -Properties objectGUID,description,displayName -ResultPageSize 2 -Server $Server)
    if ($objects.Count -ne 7) { throw 'Reference fixture count is not seven.' }
    $reference=@($objects | Sort-Object DistinguishedName | ForEach-Object { [ordered]@{dn=$_.DistinguishedName;guid_base64=[Convert]::ToBase64String($_.ObjectGUID.ToByteArray());description=$_.Description;display_name=$_.displayName} })
    $env:ADSDK_SEARCH_SERVER=$Server; $env:ADSDK_SEARCH_BASE=$base; $env:ADSDK_SEARCH_RESULT=$ResultPath
    $output=@(& $Executable -test.run '^TestSearchLab$' -test.v -test.count=1 -test.timeout=90s 2>&1 | ForEach-Object { "$_" })
    $exitCode=$LASTEXITCODE
    if ($exitCode -ne 0) { throw 'Native search qualification failed.' }
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
        try {
            $owned=@(Get-ADOrganizationalUnit -LDAPFilter "(ou=$name)" -SearchBase $domain.DistinguishedName -SearchScope OneLevel -Properties description -Server $Server)
            if ($owned.Count) {
                if ($owned.Count -ne 1 -or $owned[0].Description -cne $marker -or ($ouGuid -and $owned[0].ObjectGUID -ne $ouGuid)) { throw 'Search OU ownership mismatch; refusing cleanup.' }
                $children=@(Get-ADObject -LDAPFilter '(objectClass=container)' -SearchBase $base -SearchScope Subtree -Properties description -Server $Server | Sort-Object @{Expression={$_.DistinguishedName.Length};Descending=$true})
                foreach ($child in $children) {
                    if ($child.Description -cne $marker -or $child.Name -notmatch '^ADSDK-(Search-[0-6]|Nested)$') { throw 'Unexpected search fixture child; refusing cleanup.' }
                    Remove-ADObject -Identity $child.ObjectGUID -Server $Server -Confirm:$false
                }
                # Nonrecursive removal refuses unexpected children.
                Remove-ADOrganizationalUnit -Identity $owned[0].ObjectGUID -Server $Server -Confirm:$false
            }
        } catch { $cleanupFailure=$_ }
    }
}
$os=Get-CimInstance Win32_OperatingSystem
$module=Get-Module ActiveDirectory
[ordered]@{
    passed=($null -eq $failure -and $null -eq $cleanupFailure); server=$Server; timestamp=[DateTime]::UtcNow.ToString('o')
    os_caption=$os.Caption; os_version=$os.Version; os_build=$os.BuildNumber; module_version=$module.Version.ToString(); powershell_version=$PSVersionTable.PSVersion.ToString()
    binary_sha256=$ExpectedHash; reference=$reference; native_exit_code=$exitCode; output=$output; fixture_cleanup_passed=($null -eq $cleanupFailure)
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath ($ResultPath+'.reference.json') -Encoding UTF8
if ($failure -and $cleanupFailure) { throw [AggregateException]::new('Search qualification and cleanup failed.',[Exception[]]@($failure.Exception,$cleanupFailure.Exception)) }
if ($failure) { throw $failure }
if ($cleanupFailure) { throw $cleanupFailure }
