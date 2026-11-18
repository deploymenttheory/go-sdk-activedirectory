#Requires -Version 5.1
param([string]$RunId,[string]$Server,[PSCredential]$ReferenceCredential)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($RunId-cnotmatch '\Asdk06-gmsa-cas-[0-9tz-]{10,28}\z'-or$Server-cne'adsdk25dc1.ad.sdk.test'-or$env:COMPUTERNAME-cne'ADSDK25DC1'){throw 'Unexpected isolated reference target.'}
Import-Module ActiveDirectory
Add-Type -AssemblyName System.DirectoryServices.Protocols
$root=Get-ADRootDSE -Server $Server
if($root.defaultNamingContext-cne'DC=ad,DC=sdk,DC=test'-or$root.dnsHostName.ToLowerInvariant()-cne$Server){throw 'Reference directory identity differs.'}
$marker='ADSDK-sdk06-gmsa-cas:'+$RunId
$ouDN='OU='+$RunId+','+$root.defaultNamingContext
$ou=$null;$objects=@();$connectionObservations=[Collections.Generic.List[object]]::new();$tagSids=@{}
$result=[ordered]@{schema_version=1;run_id=$RunId;server=$Server;scope='Owned gMSA retrieval-descriptor protocol probe, not portable SDK/backend qualification';attribute='msDS-GroupMSAMembership';account_disabled=$true;kds_root_or_password_operations=$false;sdk_runtime_used=$false;requested_security=@{authentication='Kerberos';signing=$true;sealing=$true};loaded_sd_flags=$null;probe_cases=@();cleanup_verified=$false;started_utc=[DateTime]::UtcNow.ToString('o')}
$journalRoot='C:\adsdk-security-descriptor-reference\'+$RunId
foreach($path in @('C:\adsdk-security-descriptor-reference',$journalRoot)){if((Test-Path -LiteralPath $path)-and((Get-Item -LiteralPath $path -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Unsafe reference journal path.'}}
if(Test-Path -LiteralPath $journalRoot){throw 'Fresh reference journal required.'}
$null=New-Item -ItemType Directory -Path $journalRoot -Force
$result.journal_directory=$journalRoot
$script:journalIndex=0
function Save-ProbeJournal([string]$Phase){
    $script:journalIndex++;$result.phase=$Phase
    $path=Join-Path $journalRoot ('event-'+$script:journalIndex.ToString('D4')+'.json')
    [IO.File]::WriteAllText($path,($result|ConvertTo-Json -Depth 18),[Text.UTF8Encoding]::new($false))
}
Save-ProbeJournal 'initial'
function Open-ProbeConnection {
    $identifier=[System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server,389,$true,$false)
    $client=[System.DirectoryServices.Protocols.LdapConnection]::new($identifier,$ReferenceCredential.GetNetworkCredential(),[System.DirectoryServices.Protocols.AuthType]::Kerberos)
    try{
        $client.Timeout=[TimeSpan]::FromSeconds(20);$client.SessionOptions.ProtocolVersion=3
        $client.SessionOptions.Signing=$true;$client.SessionOptions.Sealing=$true;$client.Bind()
        if(-not$client.SessionOptions.Signing-or-not$client.SessionOptions.Sealing){throw 'Required native reference protection not reported.'}
        $connectionObservations.Add([pscustomobject]@{auth_type=$client.AuthType.ToString();signing_option=$client.SessionOptions.Signing;sealing_option=$client.SessionOptions.Sealing})
        return $client
    }catch{$client.Dispose();throw}
}
function Add-ProbeControls($Request){
    # SD-flags is specific to nTSecurityDescriptor, not this ordinary attribute.
}
function Read-ProbeDescriptor($Object){
    $client=Open-ProbeConnection
    try{
        $request=[System.DirectoryServices.Protocols.SearchRequest]::new($Object.DistinguishedName,'(objectClass=msDS-GroupManagedServiceAccount)',[System.DirectoryServices.Protocols.SearchScope]::Base,[string[]]@('msDS-GroupMSAMembership','objectGUID','description'))
        Add-ProbeControls $request
        $response=[System.DirectoryServices.Protocols.SearchResponse]$client.SendRequest($request)
        if($response.Entries.Count-ne1){throw 'Expected one owned gMSA.'}
        $entry=$response.Entries[0]
        if([guid]::new([byte[]]$entry.Attributes['objectGUID'][0])-ne$Object.ObjectGUID-or[string]$entry.Attributes['description'][0]-cne$marker){throw 'Owned reference identity changed.'}
        $bytes=[byte[]]$entry.Attributes['msDS-GroupMSAMembership'][0]
        $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($bytes,0)
        $aces=@(foreach($ace in $descriptor.DiscretionaryAcl){$raw=[byte[]]::new($ace.BinaryLength);$ace.GetBinaryForm($raw,0);[Convert]::ToBase64String($raw)})
        [pscustomobject]@{raw=$bytes;binary_base64=[Convert]::ToBase64String($bytes);control=[int]$descriptor.ControlFlags;dacl_ace_count=$descriptor.DiscretionaryAcl.Count;ace_bytes=$aces;object_guid=$Object.ObjectGUID.ToString();dn=$entry.DistinguishedName}
    }finally{$client.Dispose()}
}
function Public-Snapshot($Snapshot){$Snapshot|Select-Object binary_base64,control,dacl_ace_count,ace_bytes,object_guid,dn}
function With-FixtureAllow([byte[]]$Bytes,[guid]$Tag){
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Bytes,0)
    if($null-eq$descriptor.DiscretionaryAcl){throw 'Reference baseline must have a non-NULL DACL.'}
    # Match the SDK edit's basic ReadProperty allow ACE shape. This native
    # reference tests value CAS, not actual password retrieval/effective access.
    $ace=[Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,16,[Security.Principal.SecurityIdentifier]::new($tagSids[$Tag.ToString()]),$false,$null)
    $position=0
    while($position -lt $descriptor.DiscretionaryAcl.Count -and (([int]$descriptor.DiscretionaryAcl[$position].AceFlags -band 0x10) -eq 0)){$position++}
    $descriptor.DiscretionaryAcl.InsertAce($position,$ace)
    $updated=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($updated,0)
    return ,$updated
}
function Contains-Tag($Snapshot,[guid]$Tag){
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Snapshot.raw,0)
    foreach($ace in $descriptor.DiscretionaryAcl){if($ace-is[Security.AccessControl.CommonAce]-and$ace.SecurityIdentifier.Value-ceq$tagSids[$Tag.ToString()]-and$ace.AccessMask-eq16){return $true}}
    return $false
}
function Modify-Probe($Object,[byte[]]$Old,[byte[]]$New,[bool]$ConcurrentSetup=$false){
    $client=Open-ProbeConnection
    try{
        $request=[System.DirectoryServices.Protocols.ModifyRequest]::new($Object.DistinguishedName)
        Add-ProbeControls $request
        if(-not$ConcurrentSetup){
            $delete=[System.DirectoryServices.Protocols.DirectoryAttributeModification]::new();$delete.Name='msDS-GroupMSAMembership';$delete.Operation=[System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
            $null=$delete.Add($Old);$null=$request.Modifications.Add($delete)
        }
        $add=[System.DirectoryServices.Protocols.DirectoryAttributeModification]::new();$add.Name='msDS-GroupMSAMembership'
        $add.Operation=if($ConcurrentSetup){[System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace}else{[System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add}
        $null=$add.Add($New);$null=$request.Modifications.Add($add)
        try{
            $response=[System.DirectoryServices.Protocols.ModifyResponse]$client.SendRequest($request)
            [pscustomobject]@{response_received=$true;ldap_result_code=[int]$response.ResultCode;diagnostic=$response.ErrorMessage;accepted=([int]$response.ResultCode-eq0);uncertain=$false}
        } catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
            $response=$_.Exception.Response
            [pscustomobject]@{response_received=($null-ne$response);ldap_result_code=if($response){[int]$response.ResultCode}else{$null};diagnostic=if($response){$response.ErrorMessage}else{$null};accepted=$false;uncertain=($null-eq$response)}
        }catch{
            [pscustomobject]@{response_received=$false;ldap_result_code=$null;diagnostic=$null;accepted=$false;uncertain=$true;error_type=$_.Exception.GetType().Name}
        }
    }finally{$client.Dispose()}
}
try{
    $result.fixture_ace=@{type='AccessAllowed CommonAce';mask=16;permission_or_sdk_qualification=$false;prior_control_mask=256}
    $kdsBase='CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,'+$root.configurationNamingContext
    $keys=@(Get-ADObject -LDAPFilter '(objectClass=msKds-ProvRootKey)' -SearchBase $kdsBase -Properties 'msKds-UseStartTime','msKds-CreateTime' -Server $Server)
    $result.prerequisites=@{domain_controller_functionality=$root.domainControllerFunctionality;kds_key_metadata=@($keys|Select-Object Name,objectGUID,@{n='use_start_time';e={$_.'msKds-UseStartTime'}},@{n='create_time';e={$_.'msKds-CreateTime'}});key_material_requested=$false}
    Save-ProbeJournal 'prerequisites-observed'
    if(Get-ADObject -LDAPFilter ('(ou='+$RunId+')') -SearchBase $root.defaultNamingContext -Server $Server){throw 'Fresh owned probe namespace required.'}
    $ou=New-ADOrganizationalUnit -Name $RunId -Path $root.defaultNamingContext -Description $marker -ProtectedFromAccidentalDeletion $false -PassThru -Server $Server
    $result.owner_ou_guid=$ou.ObjectGUID.ToString();Save-ProbeJournal 'owned-ou-created'
    foreach($name in @('matching','stale')){
        $domain=Get-ADDomain -Server $Server
        $baseline=[Security.AccessControl.RawSecurityDescriptor]::new(('O:SYG:SYD:(A;;CR;;;'+$domain.DomainSID.Value+'-512)'))
        $baselineBytes=[byte[]]::new($baseline.BinaryLength);$baseline.GetBinaryForm($baselineBytes,0)
        $sam='sdk06p'+[guid]::NewGuid().ToString('N').Substring(0,10)+'$'
        $attributes=@{description=$marker;sAMAccountName=$sam;dnsHostName=($sam.TrimEnd('$')+'.ad.sdk.test');userAccountControl=4098;'msDS-SupportedEncryptionTypes'=24;'msDS-ManagedPasswordInterval'=30;'msDS-GroupMSAMembership'=$baselineBytes}
        # Disabled disposable account only. No KDS root or password operation.
        $object=New-ADObject -Name $name -Type msDS-GroupManagedServiceAccount -Path $ouDN -OtherAttributes $attributes -PassThru -Server $Server
        $objects+=$object
        $result.owned_gmsa_guids=@($objects|ForEach-Object{$_.ObjectGUID.ToString()});Save-ProbeJournal 'owned-gmsa-created'
        $before=Read-ProbeDescriptor $object
        $desiredTag=[guid]::NewGuid();$concurrentTag=[guid]::NewGuid()
        # Privileged SYSTEM/Administrators only, on disabled disposable gMSAs.
        $tagSids[$desiredTag.ToString()]='S-1-5-18';$tagSids[$concurrentTag.ToString()]='S-1-5-32-544'
        $desired=With-FixtureAllow $before.raw $desiredTag
        $concurrent=$null;$current=$before
        if($name-ceq'stale'){
            # This is an independent lab fixture actor, before the stale CAS.
            # It is never an unconditional replacement fallback for the SDK.
            $concurrentBytes=With-FixtureAllow $before.raw $concurrentTag
            $concurrent=Modify-Probe $object $before.raw $concurrentBytes $true
            if(-not$concurrent.accepted){throw 'Independent fixture actor did not establish the concurrent change.'}
            $current=Read-ProbeDescriptor $object
            if(-not(Contains-Tag $current $concurrentTag)){throw 'Concurrent fixture ACE missing on independent read.'}
        }
        $result.pending_attempt=@{case_id=$name;object_guid=$object.ObjectGUID.ToString();old_binary_base64=$before.binary_base64;new_binary_base64=[Convert]::ToBase64String($desired)};Save-ProbeJournal 'before-cas-submit'
        $attempt=Modify-Probe $object $before.raw $desired
        $result.pending_attempt.response=$attempt;Save-ProbeJournal 'cas-response-or-uncertainty'
        $after=Read-ProbeDescriptor $object
        $result.probe_cases+=[pscustomobject]@{id=$name;object_guid=$object.ObjectGUID.ToString();before=(Public-Snapshot $before);current_before_attempt=(Public-Snapshot $current);requested_old_binary_base64=$before.binary_base64;requested_new_binary_base64=[Convert]::ToBase64String($desired);concurrent_setup=$concurrent;response=$attempt;after=(Public-Snapshot $after);managed_ace_present=(Contains-Tag $after $desiredTag);concurrent_ace_present=(Contains-Tag $after $concurrentTag);unchanged_after_rejection=($after.binary_base64-ceq$current.binary_base64);critical_sd_flags=$null;permissive_control_used=$false}
        Save-ProbeJournal 'independent-after-read'
        if($attempt.uncertain){throw 'Probe mutation is uncertain; independent read retained and no further mutation attempted.'}
    }
    $result.completed=$true
}catch{
    $result.completed=$false;$result.failure_type=$_.Exception.GetType().Name
    $result.failure_message=$_.Exception.Message;$result.failure_hresult=$_.Exception.HResult
    $result.failure_id=$_.FullyQualifiedErrorId
    if($_.Exception.PSObject.Properties['ErrorCode']){$result.failure_error_code=$_.Exception.ErrorCode}
    Save-ProbeJournal 'failed'
}
finally{
    $cleanup=@()
    foreach($object in $objects){
        $actual=Get-ADObject -Identity $object.ObjectGUID -Properties description,objectClass -Server $Server
        $expectedDN='CN='+$actual.Name+','+$ouDN
        if($actual.description-cne$marker-or$actual.objectClass-cne'msDS-GroupManagedServiceAccount'-or-not$actual.DistinguishedName.Equals($expectedDN,[StringComparison]::OrdinalIgnoreCase)){throw 'Owned cleanup identity changed.'}
        Remove-ADObject -Identity $object.ObjectGUID -Server $Server -Confirm:$false
        $cleanup+=$object.ObjectGUID.ToString()
    }
    if($ou){
        $actual=Get-ADObject -Identity $ou.ObjectGUID -Properties description,objectClass -Server $Server
        if($actual.description-cne$marker-or$actual.objectClass-cne'organizationalUnit'-or$actual.DistinguishedName-cne$ouDN-or@(Get-ADObject -SearchBase $ouDN -SearchScope OneLevel -Filter * -Server $Server).Count){throw 'Unknown descendant or owned OU identity changed.'}
        Remove-ADOrganizationalUnit -Identity $ou.ObjectGUID -Server $Server -Confirm:$false
        $cleanup+=$ou.ObjectGUID.ToString()
    }
    $remaining=@(Get-ADObject -LDAPFilter ('(description='+$marker+')') -SearchBase $root.defaultNamingContext -Server $Server)
    $result.cleanup=@{removed_guids=$cleanup;live_owned_objects_remaining=$remaining.Count;tombstones_retained=$true}
    $result.cleanup_verified=($remaining.Count-eq0);$result.native_connection_observations=@($connectionObservations.ToArray())
    $os=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.server_build=([string]$os.CurrentBuildNumber+'.'+[string]$os.UBR);$result.module_version=(Get-Module ActiveDirectory).Version.ToString();$result.finished_utc=[DateTime]::UtcNow.ToString('o')
    Save-ProbeJournal 'cleanup-complete'
}
[pscustomobject]$result
