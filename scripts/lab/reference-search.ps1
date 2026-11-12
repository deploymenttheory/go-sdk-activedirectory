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
Add-Type -AssemblyName System.DirectoryServices
if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Search test binary hash mismatch.' }
$domain=Get-ADDomain -Server $Server
if ($domain.DNSRoot -ne 'ad.sdk.test') { throw 'Search fixtures require the isolated lab domain.' }
if ((Get-ADDomain -Server $Destination).DNSRoot -ne $domain.DNSRoot) { throw 'Search cleanup controllers must share the isolated domain.' }
$nonce=[guid]::NewGuid().ToString('N')
$name='ADSDK-Search-'+$nonce
$base="OU=$name,$($domain.DistinguishedName)"
$marker='ad-sdk-search:'+$nonce
$username='adsrch'+$nonce.Substring(0,12)
$permission=[ordered]@{passed=$false;user_guid=$null;phase='not-started';reference=@();ace=$null;output=@();native_exit_code=$null}
$created=$false; $ouGuid=$null; $failure=$null; $cleanupFailure=$null; $reference=@(); $native=$null; $output=@(); $exitCode=$null
$clean=$false; $cleanupControllers=@(); $phase='fixture-creation'
$saved=@{}
foreach ($key in @('ADSDK_SEARCH_SERVER','ADSDK_SEARCH_BASE','ADSDK_SEARCH_RESULT')) { $saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process') }
function Remove-SearchFixtures([string]$Source,[string]$DomainDN,[string]$OUName,[string]$GUID,[string]$Marker,[string]$UserName,[string]$UserGUID) {
    $ErrorActionPreference='Stop'
    $owned=@(Get-ADOrganizationalUnit -LDAPFilter "(ou=$OUName)" -SearchBase $DomainDN -SearchScope OneLevel -Properties description -Server $Source)
    if (-not $owned.Count) { return }
    if ($owned.Count -ne 1 -or $owned[0].Description -cne $Marker -or ($GUID -and $owned[0].ObjectGUID.ToString() -ne $GUID)) { throw 'Search OU ownership mismatch; refusing cleanup.' }
    $children=@(Get-ADObject -LDAPFilter '(objectClass=*)' -SearchBase $owned[0].DistinguishedName -SearchScope Subtree -Properties description -Server $Source | Where-Object DistinguishedName -ine $owned[0].DistinguishedName | Sort-Object @{Expression={$_.DistinguishedName.Length};Descending=$true})
    foreach ($child in $children) {
        $container=$child.ObjectClass -eq 'container' -and $child.Name -cmatch '^ADSDK-(Search-[0-6]|Nested)$'
        $user=$child.ObjectClass -eq 'user' -and $UserName -and $child.Name -ceq $UserName -and $child.DistinguishedName -ieq "CN=$UserName,$($owned[0].DistinguishedName)" -and (-not $UserGUID -or $child.ObjectGUID.ToString() -eq $UserGUID)
        if ($child.Description -cne $Marker -or (-not $container -and -not $user)) { throw 'Unexpected search fixture child; refusing cleanup.' }
    }
    $cleanupErrors=[Collections.Generic.List[Exception]]::new()
    foreach ($child in $children) {
        try { Remove-ADObject -Identity $child.ObjectGUID -Server $Source -Confirm:$false } catch { $cleanupErrors.Add($_.Exception) }
    }
    # Nonrecursive removal refuses unexpected or surviving children.
    try { Remove-ADOrganizationalUnit -Identity $owned[0].ObjectGUID -Server $Source -Confirm:$false } catch { $cleanupErrors.Add($_.Exception) }
    if ($cleanupErrors.Count) { throw [AggregateException]::new('Search fixture cleanup failed.',$cleanupErrors.ToArray()) }
}
function New-SearchDescriptionRule([Security.Principal.SecurityIdentifier]$SID,[guid]$AttributeGUID) {
    if ($AttributeGUID -eq [guid]::Empty) { throw 'Description schema GUID is empty.' }
    return [DirectoryServices.ActiveDirectoryAccessRule]::new($SID,[DirectoryServices.ActiveDirectoryRights]::ReadProperty,[Security.AccessControl.AccessControlType]::Deny,$AttributeGUID,[DirectoryServices.ActiveDirectorySecurityInheritance]::None)
}
function Assert-SearchDescriptionRule($Rule,[string]$SID,[guid]$AttributeGUID) {
    if ($Rule.IdentityReference.Value -cne $SID -or $Rule.ActiveDirectoryRights -ne [DirectoryServices.ActiveDirectoryRights]::ReadProperty -or $Rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Deny -or $Rule.ObjectType -ne $AttributeGUID -or $Rule.InheritanceType -ne [DirectoryServices.ActiveDirectorySecurityInheritance]::None -or $Rule.IsInherited -or $Rule.InheritedObjectType -ne [guid]::Empty -or $Rule.ObjectFlags -ne [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) {
        throw 'Description deny ACE does not have the exact owned user/property scope.'
    }
}
function Compare-SearchPermissionProjection($Native,$Reference,[string]$Marker,[string]$UserName,[string]$Source) {
    if (-not $Native.passed -or -not $Native.native_allocations_released -or $Native.username -cne $UserName -or $Native.server -ine $Source -or $Native.rows.Count -ne 3 -or $Reference.Count -ne 2) { throw 'Permission artifact identity, count or cleanup mismatch.' }
    foreach ($case in @('hidden','visible','unloaded')) {
        $rows=@($Native.rows | Where-Object case -ceq $case)
        $referenceCase=if ($case -eq 'unloaded') {'hidden'} else {$case}
        $references=@($Reference | Where-Object case -ceq $referenceCase)
        if ($rows.Count -ne 1 -or $references.Count -ne 1) { throw 'Permission projection has a missing or duplicated case.' }
        $row=$rows[0]; $expected=$references[0]
        if ($row.object.DistinguishedName -ine $expected.dn -or @($row.object.Attributes.objectguid).Count -ne 1 -or $row.object.Attributes.objectguid[0] -cne $expected.guid_base64) { throw 'Ordinary identity DN/GUID differs between WinLDAP and Get-ADObject.' }
        $description=$row.object.Attributes.PSObject.Properties['description']
        if ($case -eq 'visible') {
            if ($row.description_state -ne 2 -or -not $description -or @($description.Value).Count -ne 1 -or [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($description.Value[0])) -cne $Marker -or $expected.description -cne $Marker) { throw 'Ordinary identity visible description control failed.' }
        } else {
            $state=if ($case -eq 'hidden') {1} else {0}
            if ($row.description_state -ne $state -or $description -or $null -ne $expected.description) { throw 'Hidden/unloaded description projection differs.' }
        }
    }
}
function Protect-SearchPermissionOutput([string]$Text,[byte[]]$PasswordBytes) {
    if (-not $PasswordBytes.Length -or $Text.Contains([Text.Encoding]::UTF8.GetString($PasswordBytes)) -or $Text.Contains([Convert]::ToBase64String($PasswordBytes))) { throw 'Credential material detected in native output; output suppressed.' }
    return @($Text -split "`r?`n" | Where-Object {$_})
}
function Invoke-SearchPermissionFixture([string]$Source,[string]$Replica,[string]$Base,[string]$Marker,[string]$UserName,[string]$DomainName,[string]$Binary,[string]$Result,$Evidence) {
    $password=$null; $ordinary=$null; $passwordBytes=$null; $wire=$null; $wireBytes=$null; $process=$null; $entry=$null; $replicaEntry=$null
    try {
        $Evidence.phase='create-ordinary-user'
        $password=ConvertTo-SecureString ('Aa9!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
        $ordinary=[PSCredential]::new("$DomainName\$UserName",$password)
        $user=New-ADUser -Name $UserName -SamAccountName $UserName -UserPrincipalName "$UserName@ad.sdk.test" -Path $Base -Description $Marker -AccountPassword $password -Enabled:$true -ChangePasswordAtLogon:$false -Server $Source -PassThru
        $Evidence.user_guid=$user.ObjectGUID.ToString()
        $user=Get-ADUser -Identity $user.ObjectGUID -Properties memberOf,primaryGroupID,description -Server $Source
        if ($user.Description -cne $Marker -or $user.DistinguishedName -ine "CN=$UserName,$Base" -or -not $user.Enabled -or $user.primaryGroupID -ne 513 -or @($user.memberOf).Count -ne 0) { throw 'Permission fixture identity is not the owned ordinary user.' }
        $Evidence.username=$UserName; $Evidence.user_sid=$user.SID.Value; $Evidence.primary_group_id=$user.primaryGroupID; $Evidence.explicit_group_count=@($user.memberOf).Count
        $Evidence.phase='owned-property-acl'
        $root=Get-ADRootDSE -Server $Source
        $schema=@(Get-ADObject -LDAPFilter '(&(objectClass=attributeSchema)(lDAPDisplayName=description))' -SearchBase $root.schemaNamingContext -Properties schemaIDGUID -Server $Source)
        if ($schema.Count -ne 1 -or $schema[0].schemaIDGUID.Length -ne 16) { throw 'Description schema identity is unavailable.' }
        $attributeGUID=[guid]::new([byte[]]$schema[0].schemaIDGUID)
        $target=Get-ADObject -Identity "CN=ADSDK-Search-0,$Base" -Properties description -Server $Source
        $control=Get-ADObject -Identity "CN=ADSDK-Search-1,$Base" -Properties description -Server $Source
        foreach ($object in @($target,$control)) {
            if ($object.Description -cne $Marker -or $object.ObjectClass -ne 'container') { throw 'Permission fixture object ownership mismatch.' }
        }
        $entry=[DirectoryServices.DirectoryEntry]::new("LDAP://$Source/$($target.DistinguishedName)")
        $entry.AuthenticationType=[DirectoryServices.AuthenticationTypes]'Secure,Signing,Sealing'
        $entry.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
        $security=$entry.ObjectSecurity
        $original=$security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        if (@($security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -eq $user.SID.Value}).Count) { throw 'New ordinary user unexpectedly has an existing target ACE.' }
        $rule=New-SearchDescriptionRule $user.SID $attributeGUID
        Assert-SearchDescriptionRule $rule $user.SID.Value $attributeGUID
        $security.AddAccessRule($rule)
        $entry.ObjectSecurity=$security; $entry.CommitChanges()
        $entry.RefreshCache(@('ntSecurityDescriptor'))
        $readback=$entry.ObjectSecurity
        $rules=@($readback.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -eq $user.SID.Value})
        if ($rules.Count -ne 1) { throw 'Target ACL did not retain exactly one owned-user ACE.' }
        Assert-SearchDescriptionRule $rules[0] $user.SID.Value $attributeGUID
        # Change only the in-memory verification copy; do not commit it.
        $readback.RemoveAccessRuleSpecific($rules[0])
        if ($readback.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -cne $original) { throw 'Unrelated target DACL entries or inheritance changed.' }
        $Evidence.ace=[ordered]@{target_dn=$target.DistinguishedName;target_guid=$target.ObjectGUID.ToString();trustee_sid=$user.SID.Value;attribute='description';attribute_schema_guid=$attributeGUID.ToString();rights='ReadProperty';type='Deny';inheritance='None';inherited=$false;other_dacl_entries_unchanged=$true}
        Sync-ADObject -Object $user.ObjectGUID -Source $Source -Destination $Replica
        Sync-ADObject -Object $target.ObjectGUID -Source $Source -Destination $Replica
        $null=Get-ADUser -Identity $user.ObjectGUID -Server $Replica
        $replicaEntry=[DirectoryServices.DirectoryEntry]::new("LDAP://$Replica/$($target.DistinguishedName)")
        $replicaEntry.AuthenticationType=[DirectoryServices.AuthenticationTypes]'Secure,Signing,Sealing'
        $replicaEntry.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Dacl
        $replicaRules=@($replicaEntry.ObjectSecurity.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -eq $user.SID.Value})
        if ($replicaRules.Count -ne 1) { throw 'Replica did not receive the owned property ACE.' }
        Assert-SearchDescriptionRule $replicaRules[0] $user.SID.Value $attributeGUID
        $Evidence.ace.replica_verified=$true
        $Evidence.phase='same-credential-reference'
        foreach ($case in @('hidden','visible')) {
            $object=if ($case -eq 'hidden') {$target} else {$control}
            $admin=Get-ADObject -Identity $object.ObjectGUID -Properties description -Server $Source
            if ($admin.Description -cne $Marker) { throw 'Administrator-set description was changed instead of hidden.' }
            $reference=Get-ADObject -Identity $object.ObjectGUID -Properties description,objectGUID -Server $Source -Credential $ordinary
            $property=$reference.PSObject.Properties['description']
            $description=if ($property) {$property.Value} else {$null}
            if ($reference.DistinguishedName -ine $object.DistinguishedName -or $reference.ObjectGUID -ne $object.ObjectGUID) { throw 'Ordinary identity lost the visible object identity.' }
            if (($case -eq 'hidden' -and $null -ne $description) -or ($case -eq 'visible' -and $description -cne $Marker)) { throw 'Get-ADObject did not hide only the denied description.' }
            $Evidence.reference+=@([ordered]@{case=$case;dn=$reference.DistinguishedName;guid_base64=[Convert]::ToBase64String($reference.ObjectGUID.ToByteArray());description=$description;admin_description=$admin.Description})
        }
        $Evidence.phase='same-credential-native'
        $passwordBytes=[Text.Encoding]::UTF8.GetBytes($ordinary.GetNetworkCredential().Password)
        $wire=@{Server=$Source;Domain=$DomainName;Username=$UserName;Base=$Base;Marker=$Marker;Password=[Convert]::ToBase64String($passwordBytes)} | ConvertTo-Json -Compress
        $start=[Diagnostics.ProcessStartInfo]::new()
        $start.FileName=$Binary; $start.Arguments='-test.run ^TestSearchPermissionLab$ -test.v -test.count=1 -test.timeout=60s'
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true
        $start.RedirectStandardInput=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        $start.StandardOutputEncoding=[Text.Encoding]::UTF8; $start.StandardErrorEncoding=[Text.Encoding]::UTF8
        $start.EnvironmentVariables['ADSDK_SEARCH_PERMISSION_LAB']='1'; $start.EnvironmentVariables['ADSDK_SEARCH_PERMISSION_RESULT']=$Result
        $process=[Diagnostics.Process]::new(); $process.StartInfo=$start
        if (-not $process.Start()) { throw 'Search permission process did not start.' }
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        $wireBytes=[Text.Encoding]::UTF8.GetBytes($wire)
        $process.StandardInput.BaseStream.Write($wireBytes,0,$wireBytes.Length)
        $process.StandardInput.BaseStream.Flush(); $process.StandardInput.Close()
        [Array]::Clear($wireBytes,0,$wireBytes.Length); $wireBytes=$null; $wire=$null
        if (-not $process.WaitForExit(75000)) { $process.Kill(); $process.WaitForExit(); throw 'Search permission process exceeded its deadline.' }
        $Evidence.native_exit_code=$process.ExitCode
        $text=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
        $Evidence.output=@(Protect-SearchPermissionOutput $text $passwordBytes)
        if ($process.ExitCode -ne 0) { throw 'Native search permission test failed.' }
        $native=Get-Content -LiteralPath $Result -Raw | ConvertFrom-Json
        Compare-SearchPermissionProjection $native $Evidence.reference $Marker $UserName $Source
        $Evidence.passed=$true; $Evidence.phase='complete'
    } catch {
        # Never propagate a credential-bearing command or input through a remote error.
        $Evidence.failure_type=$_.Exception.GetType().FullName
        throw 'Owned search permission qualification failed; inspect its public phase and proof.'
    } finally {
        try {
            if ($process) { try { if (-not $process.HasExited) {$process.Kill(); $process.WaitForExit()} } finally {$process.Dispose()} }
        } finally {
            $wire=$null
            if ($wireBytes) {[Array]::Clear($wireBytes,0,$wireBytes.Length)}
            if ($passwordBytes) {[Array]::Clear($passwordBytes,0,$passwordBytes.Length)}
            $ordinary=$null
            if ($password) {$password.Dispose()}
            if ($entry) {$entry.Dispose()}
            if ($replicaEntry) {$replicaEntry.Dispose()}
        }
    }
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
    $phase='ordinary-user-permission'
    Invoke-SearchPermissionFixture $Server $Destination $base $marker $username $domain.NetBIOSName $Executable ($ResultPath+'.permission.json') $permission
} catch { $failure=$_ }
finally {
    foreach ($key in $saved.Keys) { [Environment]::SetEnvironmentVariable($key,$saved[$key],'Process') }
    if ($created) {
        $cleanupErrors=[Collections.Generic.List[Exception]]::new()
        try { Remove-SearchFixtures $Server $domain.DistinguishedName $name $ouGuid $marker $username $permission.user_guid } catch { $cleanupErrors.Add($_.Exception) }
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
    binary_sha256=$ExpectedHash; reference=$reference; native_exit_code=$exitCode; output=$output; permission=$permission; fixture_cleanup_passed=$clean; cleanup_on_both_controllers=$cleanupControllers
    failure_phase=$(if ($failure) {$phase} else {$null}); failure_type=$(if ($failure) {$failure.Exception.GetType().FullName} else {$null}); cleanup_failure_type=$(if ($cleanupFailure) {$cleanupFailure.Exception.GetType().FullName} else {$null})
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath ($ResultPath+'.reference.json') -Encoding UTF8
if ($failure -and $cleanupFailure) { throw [AggregateException]::new('Search qualification and cleanup failed.',[Exception[]]@($failure.Exception,$cleanupFailure.Exception)) }
if ($failure) { throw $failure }
if ($cleanupFailure) { throw $cleanupFailure }
