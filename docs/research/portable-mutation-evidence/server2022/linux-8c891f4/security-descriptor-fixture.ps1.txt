#Requires -Version 5.1
# Functions only. Provisioning/reference tooling, never an SDK runtime gateway.
# Execute only through the verified private lab's approved PowerShell Direct path.

function Get-DescriptorFixtureNames([string]$RunId) {
    if ($RunId -cnotmatch '\Asdk06-[a-z0-9][a-z0-9-]{4,41}\z') {throw 'Invalid descriptor fixture run identity.'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($RunId))} finally {$sha.Dispose()}
    $suffix=([BitConverter]::ToString($digest).Replace('-','').ToLowerInvariant()).Substring(0,12)
    $parent="OU=sdk06-$RunId,DC=ad,DC=sdk,DC=test"
    return [pscustomobject]@{
        parent_dn=$parent;parent_marker="sdk06-descriptor-parent:$RunId"
        actor_dn="CN=actor,$parent";actor_marker="sdk06-descriptor-actor:$RunId";sam="sd6u$suffix";upn="sd6u$suffix@AD.SDK.TEST"
        matching_dn="CN=matching,$parent";matching_marker="sdk06-descriptor-gmsa:$($RunId):matching";matching_sam="sd6m$suffix`$"
        stale_dn="CN=stale,$parent";stale_marker="sdk06-descriptor-gmsa:$($RunId):stale";stale_sam="sd6s$suffix`$"
    }
}

function Assert-DescriptorFixtureContext([string]$RunId,[string]$Server) {
    $null=Get-DescriptorFixtureNames $RunId
    if ($Server -cnotmatch '\Aadsdk(16|19|22|25)dc1\.ad\.sdk\.test\z' -or $Server -ine "$env:COMPUTERNAME.ad.sdk.test") {throw 'Unexpected descriptor lab DC.'}
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $root=Get-ADRootDSE -Server $Server -ErrorAction Stop
    if ($root.defaultNamingContext -cne 'DC=ad,DC=sdk,DC=test' -or $root.dnsHostName -ine $Server) {throw 'Descriptor lab directory differs.'}
    return $root
}

function Assert-DescriptorFixturePath([string]$Path) {
    $root=[IO.Path]::GetFullPath('C:\adsdk-descriptor-fixtures').TrimEnd('\')
    $full=[IO.Path]::GetFullPath($Path)
    if ($full -cne $root -and -not $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Descriptor journal path escaped its root.'}
    for ($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Descriptor fixture path traverses a reparse point.'}
    }
    return $full
}

function Save-DescriptorFixtureState($State,[string]$Phase) {
    $directory=Assert-DescriptorFixturePath (Join-Path 'C:\adsdk-descriptor-fixtures' $State.run_id)
    $State.phase=$Phase;$State.updated_utc=[DateTime]::UtcNow.ToString('o');$State.journal_index++
    $bytes=[Text.Encoding]::UTF8.GetBytes(($State|ConvertTo-Json -Depth 16))
    $event=Join-Path $directory ('event-'+$State.journal_index.ToString('D4')+'.json')
    $stream=[IO.File]::Open($event,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length)} finally {$stream.Dispose()}
    $temporary=Join-Path $directory 'state.next.json'
    [IO.File]::WriteAllBytes($temporary,$bytes)
    Move-Item -LiteralPath $temporary -Destination (Join-Path $directory 'state.json') -Force
}

function Initialize-DescriptorFixtureJournal([string]$RunId,[string]$Server) {
    $root=Assert-DescriptorFixturePath 'C:\adsdk-descriptor-fixtures'
    $marker=Join-Path $root 'owner.json'
    if (Test-Path -LiteralPath $root) {
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {throw 'Existing descriptor journal root is not owned.'}
        $owner=Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json
        if ($owner.schema_version -ne 1 -or $owner.purpose -cne 'sdk-descriptor-journals' -or $owner.server -cne $Server) {throw 'Descriptor journal root identity differs.'}
    } else {
        $null=New-Item -ItemType Directory -Path $root
        [IO.File]::WriteAllText($marker,(@{schema_version=1;purpose='sdk-descriptor-journals';server=$Server}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    }
    $directory=Assert-DescriptorFixturePath (Join-Path $root $RunId)
    if (Test-Path -LiteralPath $directory) {throw 'Fresh descriptor journal required.'}
    $null=New-Item -ItemType Directory -Path $directory
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $root -AclObject $acl
    Set-Acl -LiteralPath $directory -AclObject $acl
}

function Assert-DescriptorFixtureState($State) {
    $names=Get-DescriptorFixtureNames $State.run_id
    if ($State.schema_version -ne 1 -or $State.purpose -cne 'sdk-portable-descriptor-fixture' -or
        $State.server -cnotmatch '\Aadsdk(16|19|22|25)dc1\.ad\.sdk\.test\z' -or $State.parent_dn -cne $names.parent_dn -or
        $State.actor_dn -cne $names.actor_dn -or $State.actor_sam -cne $names.sam -or $State.actor_upn -cne $names.upn) {throw 'Descriptor fixture state identity changed.'}
    if (@($State.accounts).Count -ne 2) {throw 'Descriptor fixture account plan changed.'}
    foreach ($id in @('matching','stale')) {
        $account=@($State.accounts|Where-Object id -CEQ $id)
        if ($account.Count -ne 1 -or $account[0].dn -cne $names.($id+'_dn') -or $account[0].sam -cne $names.($id+'_sam')) {throw 'Descriptor fixture child plan changed.'}
    }
    foreach ($value in @($State.parent_guid,$State.actor_guid)+@($State.accounts|ForEach-Object {$_.guid})) {
        if ($value -and ([guid]$value) -eq [guid]::Empty) {throw 'Empty descriptor fixture GUID.'}
    }
}

function Assert-DescriptorFixtureObjects($State,[object[]]$Objects,[bool]$AllowMissing) {
    Assert-DescriptorFixtureState $State
    $names=Get-DescriptorFixtureNames $State.run_id
    $expected=@{
        $names.parent_dn=@{guid=$State.parent_guid;class='organizationalUnit';marker=$names.parent_marker;sam=$null}
        $names.actor_dn=@{guid=$State.actor_guid;class='user';marker=$names.actor_marker;sam=$names.sam}
    }
    foreach ($account in $State.accounts) {$expected[$account.dn]=@{guid=$account.guid;class='msDS-GroupManagedServiceAccount';marker=$names.($account.id+'_marker');sam=$account.sam}}
    $seen=@{}
    foreach ($object in $Objects) {
        $dn=[string]$object.DistinguishedName
        if (-not $expected.ContainsKey($dn) -or $seen.ContainsKey($dn)) {throw 'Unexpected or duplicate descriptor fixture descendant.'}
        $owned=$expected[$dn]
        if ($object.ObjectClass -cne $owned.class -or [string]$object.description -cne $owned.marker -or
            ($owned.sam -and [string]$object.sAMAccountName -cne $owned.sam) -or
            ($owned.guid -and ([guid]$object.ObjectGUID) -ne ([guid]$owned.guid))) {throw 'Descriptor fixture object GUID, class or marker differs.'}
        # An unrecorded GUID is allowed only for recovery of a journaled creation
        # intent in this fresh namespace, never to adopt a pre-existing object.
        if (-not $owned.guid -and $State.phase -cnotin @('parent-create-intent','actor-create-intent','matching-create-intent','stale-create-intent')) {throw 'Unrecorded descriptor fixture object outside a creation intent.'}
        $seen[$dn]=$true
    }
    if (-not $AllowMissing) {foreach ($dn in $expected.Keys) {if (-not $seen.ContainsKey($dn)) {throw 'Recorded descriptor fixture object is absent.'}}}
}

function Get-DescriptorFixtureLiveObjects($State,[bool]$AllowMissing) {
    Assert-DescriptorFixtureState $State
    $server=$State.server
    $parent=@(Get-ADObject -Server $server -LDAPFilter "(distinguishedName=$($State.parent_dn))" -Properties description,sAMAccountName -ErrorAction Stop)
    if ($parent.Count -gt 1) {throw 'Ambiguous descriptor parent.'}
    $objects=@()
    if ($parent.Count -eq 1) {$objects=@(Get-ADObject -Server $server -SearchBase $State.parent_dn -SearchScope Subtree -LDAPFilter '(objectClass=*)' -Properties description,sAMAccountName -ErrorAction Stop)}
    Assert-DescriptorFixtureObjects $State $objects $AllowMissing
    foreach ($pair in @(@($State.parent_guid,$State.parent_dn),@($State.actor_guid,$State.actor_dn))+@($State.accounts|ForEach-Object {,@($_.guid,$_.dn)})) {
        if (-not $pair[0]) {continue}
        $hex=([guid]$pair[0]).ToByteArray()|ForEach-Object {'\'+$_.ToString('x2')}
        $found=@(Get-ADObject -Server $server -LDAPFilter ('(objectGUID='+($hex -join '')+')') -Properties description,sAMAccountName -ErrorAction Stop)
        if ($found.Count -gt 1 -or ($found.Count -eq 1 -and $found[0].DistinguishedName -cne $pair[1])) {throw 'Recorded descriptor fixture GUID moved outside its owned DN.'}
        if (-not $AllowMissing -and $found.Count -ne 1) {throw 'Recorded descriptor fixture GUID is absent.'}
    }
    return $objects
}

function Open-DescriptorFixtureConnection([string]$Server,[PSCredential]$Credential) {
    if (-not $Credential) {throw 'Explicit protected provisioning credential required.'}
    $identifier=[DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server,389,$true,$false)
    $connection=[DirectoryServices.Protocols.LdapConnection]::new($identifier,$Credential.GetNetworkCredential(),[DirectoryServices.Protocols.AuthType]::Kerberos)
    try {
        $connection.Timeout=[TimeSpan]::FromSeconds(20);$connection.SessionOptions.ProtocolVersion=3
        $connection.SessionOptions.Signing=$true;$connection.SessionOptions.Sealing=$true;$connection.Bind()
        return $connection
    } catch {$connection.Dispose();throw}
}

function Get-DescriptorFixtureGUIDTarget([guid]$GUID) {
    if ($GUID -eq [guid]::Empty) {throw 'Empty GUID target refused.'}
    return '<GUID='+([BitConverter]::ToString($GUID.ToByteArray()).Replace('-','').ToLowerInvariant())+'>'
}

function Read-DescriptorFixtureDACL($Connection,[guid]$GUID,[string]$Marker) {
    $request=[DirectoryServices.Protocols.SearchRequest]::new((Get-DescriptorFixtureGUIDTarget $GUID),'(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,[string[]]@('nTSecurityDescriptor','objectGUID','description'))
    $control=[DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new([DirectoryServices.Protocols.SecurityMasks]::Dacl)
    $control.IsCritical=$true;$null=$request.Controls.Add($control)
    $response=[DirectoryServices.Protocols.SearchResponse]$Connection.SendRequest($request)
    if ($response.Entries.Count -ne 1) {throw 'Controlled descriptor fixture read is not unique.'}
    $entry=$response.Entries[0]
    if ([guid]::new([byte[]]$entry.Attributes['objectGUID'][0]) -ne $GUID -or [string]$entry.Attributes['description'][0] -cne $Marker) {throw 'Controlled descriptor fixture read identity differs.'}
    return ,[byte[]]$entry.Attributes['nTSecurityDescriptor'][0]
}

function Assert-DescriptorFixtureGrant([byte[]]$Raw,[string]$SID,[guid]$AttributeGUID) {
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Raw,0)
    if (-not $descriptor.DiscretionaryAcl -or $descriptor.DiscretionaryAcl.Revision -ne 4) {throw 'ObjectAce delegation requires an object-capable ACL revision.'}
    $matching=@($descriptor.DiscretionaryAcl|Where-Object {($_ -is [Security.AccessControl.KnownAce]) -and $_.SecurityIdentifier.Value -ceq $SID})
    if ($matching.Count -ne 1) {throw 'Expected exactly one owned actor DACL grant.'}
    $ace=$matching[0]
    if ($ace -isnot [Security.AccessControl.ObjectAce] -or $ace.AceFlags -ne [Security.AccessControl.AceFlags]::None -or
        $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or $ace.AccessMask -ne 0x30 -or
        $ace.ObjectAceFlags -ne [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent -or $ace.ObjectAceType -ne $AttributeGUID) {
        throw 'Actor delegation exceeds exact Read/Write Property on the retrieval attribute.'
    }
}

function Set-DescriptorFixtureGrant($State,$Account,[PSCredential]$Credential) {
    $names=Get-DescriptorFixtureNames $State.run_id
    $connection=Open-DescriptorFixtureConnection $State.server $Credential
    try {
        $raw=Read-DescriptorFixtureDACL $connection ([guid]$Account.guid) $names.($Account.id+'_marker')
        $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($raw,0)
        $sid=[Security.Principal.SecurityIdentifier]::new($State.actor_sid)
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if ($ace -is [Security.AccessControl.KnownAce] -and $ace.SecurityIdentifier.Value -ceq $State.actor_sid) {throw 'Actor already has an unexpected explicit fixture grant.'}
        }
        $acl=[Security.AccessControl.RawAcl]::new(4,$descriptor.DiscretionaryAcl.Count+1)
        $inserted=$false
        $grant=[Security.AccessControl.ObjectAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,0x30,$sid,
            [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,[guid]$State.attribute_schema_guid,[guid]::Empty,$false,$null)
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if (-not $inserted -and (([int]$ace.AceFlags -band 0x10) -ne 0)) {$acl.InsertAce($acl.Count,$grant);$inserted=$true}
            $acl.InsertAce($acl.Count,$ace)
        }
        if (-not $inserted) {$acl.InsertAce($acl.Count,$grant)}
        $descriptor.DiscretionaryAcl=$acl
        $next=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($next,0)
        Assert-DescriptorFixtureGrant $next $State.actor_sid ([guid]$State.attribute_schema_guid)
        $Account.baseline_dacl_base64=[Convert]::ToBase64String($raw);$Account.expected_dacl_base64=[Convert]::ToBase64String($next)
        Save-DescriptorFixtureState $State ($Account.id+'-grant-intent')
        # This is exclusive provisioning of a new GUID/marker-owned fixture,
        # not a production atomic read/modify/write route or assertion fallback.
        $current=Read-DescriptorFixtureDACL $connection ([guid]$Account.guid) $names.($Account.id+'_marker')
        if ([Convert]::ToBase64String($current) -cne $Account.baseline_dacl_base64) {throw 'Fixture ACL changed before provisioning.'}
        $request=[DirectoryServices.Protocols.ModifyRequest]::new((Get-DescriptorFixtureGUIDTarget ([guid]$Account.guid)))
        $modification=[DirectoryServices.Protocols.DirectoryAttributeModification]::new()
        $modification.Name='nTSecurityDescriptor';$modification.Operation=[DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        $null=$modification.Add($next);$null=$request.Modifications.Add($modification)
        $control=[DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new([DirectoryServices.Protocols.SecurityMasks]::Dacl);$control.IsCritical=$true;$null=$request.Controls.Add($control)
        $response=$connection.SendRequest($request)
        if ([int]$response.ResultCode -ne 0) {throw 'Fixture delegation was refused.'}
        $actual=Read-DescriptorFixtureDACL $connection ([guid]$Account.guid) $names.($Account.id+'_marker')
        Assert-DescriptorFixtureGrant $actual $State.actor_sid ([guid]$State.attribute_schema_guid)
        $Account.ready_dacl_base64=[Convert]::ToBase64String($actual)
        Save-DescriptorFixtureState $State ($Account.id+'-grant-verified')
    } finally {$connection.Dispose()}
}

function New-DescriptorDirectoryFixture([string]$RunId,[string]$Server,[SecureString]$Password,[PSCredential]$ProvisioningCredential) {
    $root=Assert-DescriptorFixtureContext $RunId $Server
    if (-not $Password -or $Password.Length -lt 24 -or -not $ProvisioningCredential) {throw 'Fresh strong actor password and protected provisioning credential required.'}
    $names=Get-DescriptorFixtureNames $RunId
    $directory=Assert-DescriptorFixturePath (Join-Path 'C:\adsdk-descriptor-fixtures' $RunId)
    if ((Test-Path -LiteralPath $directory) -or @(Get-ADObject -Server $Server -LDAPFilter "(|(distinguishedName=$($names.parent_dn))(sAMAccountName=$($names.sam))(sAMAccountName=$($names.matching_sam))(sAMAccountName=$($names.stale_sam)))").Count) {throw 'Descriptor fixture namespace is not fresh.'}
    $schema=@(Get-ADObject -Server $Server -SearchBase $root.schemaNamingContext -LDAPFilter '(&(objectClass=attributeSchema)(lDAPDisplayName=msDS-GroupMSAMembership))' -Properties schemaIDGUID)
    if ($schema.Count -ne 1 -or $schema[0].schemaIDGUID.Length -ne 16) {throw 'Retrieval descriptor schema identity is unavailable.'}
    Initialize-DescriptorFixtureJournal $RunId $Server
    $state=[pscustomobject]@{
        schema_version=1;purpose='sdk-portable-descriptor-fixture';run_id=$RunId;server=$Server;parent_dn=$names.parent_dn;parent_guid=$null
        actor_dn=$names.actor_dn;actor_sam=$names.sam;actor_upn=$names.upn;actor_guid=$null;actor_sid=$null;actor_kvno=$null
        attribute_schema_guid=([guid]::new([byte[]]$schema[0].schemaIDGUID)).ToString();phase='initial';journal_index=0;updated_utc=$null
        kds_or_managed_password_operations=$false;policy_or_tls_changes=$false;accounts=@(
            [pscustomobject]@{id='matching';dn=$names.matching_dn;sam=$names.matching_sam;guid=$null;baseline_dacl_base64=$null;expected_dacl_base64=$null;ready_dacl_base64=$null}
            [pscustomobject]@{id='stale';dn=$names.stale_dn;sam=$names.stale_sam;guid=$null;baseline_dacl_base64=$null;expected_dacl_base64=$null;ready_dacl_base64=$null}
        )
    }
    Save-DescriptorFixtureState $state 'parent-create-intent'
    $parent=New-ADOrganizationalUnit -Server $Server -Name "sdk06-$RunId" -Path 'DC=ad,DC=sdk,DC=test' -Description $names.parent_marker -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Stop
    $state.parent_guid=$parent.ObjectGUID.ToString();Save-DescriptorFixtureState $state 'actor-create-intent'
    $actor=New-ADUser -Server $Server -Name 'actor' -Path $names.parent_dn -SamAccountName $names.sam -UserPrincipalName $names.upn -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -AccountNotDelegated $true -Description $names.actor_marker -OtherAttributes @{'msDS-SupportedEncryptionTypes'=[int]24} -PassThru -ErrorAction Stop
    $state.actor_guid=$actor.ObjectGUID.ToString()
    $actor=Get-ADUser -Server $Server -Identity $actor.ObjectGUID -Properties objectSID,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes',Enabled -ErrorAction Stop
    if (-not $actor.Enabled -or $actor.'msDS-SupportedEncryptionTypes' -ne 24 -or $actor.'msDS-KeyVersionNumber' -lt 1) {throw 'Independent actor verification failed.'}
    $state.actor_sid=$actor.SID.Value;$state.actor_kvno=[int]$actor.'msDS-KeyVersionNumber'
    Save-DescriptorFixtureState $state 'actor-verified'
    $baseline=[Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:(A;;CR;;;SY)(A;;WP;;;BA)')
    $baselineBytes=[byte[]]::new($baseline.BinaryLength);$baseline.GetBinaryForm($baselineBytes,0)
    foreach ($account in $state.accounts) {
        Save-DescriptorFixtureState $state ($account.id+'-create-intent')
        $attributes=@{description=$names.($account.id+'_marker');sAMAccountName=$account.sam;dNSHostName=($account.sam.TrimEnd('$')+'.ad.sdk.test');userAccountControl=4098;'msDS-SupportedEncryptionTypes'=24;'msDS-ManagedPasswordInterval'=30;'msDS-GroupMSAMembership'=$baselineBytes}
        $object=New-ADObject -Server $Server -Name $account.id -Type msDS-GroupManagedServiceAccount -Path $names.parent_dn -OtherAttributes $attributes -PassThru -ErrorAction Stop
        $account.guid=$object.ObjectGUID.ToString();Save-DescriptorFixtureState $state ($account.id+'-created')
        Set-DescriptorFixtureGrant $state $account $ProvisioningCredential
    }
    $null=Get-DescriptorFixtureLiveObjects $state $false
    Save-DescriptorFixtureState $state 'ready'
    return $state
}

function Remove-DescriptorDirectoryFixture([string]$RunId,[string]$Server) {
    $null=Assert-DescriptorFixtureContext $RunId $Server
    $directory=Assert-DescriptorFixturePath (Join-Path 'C:\adsdk-descriptor-fixtures' $RunId)
    $statePath=Join-Path $directory 'state.json'
    if (-not (Test-Path -LiteralPath $statePath)) {
        $names=Get-DescriptorFixtureNames $RunId
        $filter="(|(distinguishedName=$($names.parent_dn))(sAMAccountName=$($names.sam))(sAMAccountName=$($names.matching_sam))(sAMAccountName=$($names.stale_sam)))"
        if (@(Get-ADObject -Server $Server -LDAPFilter $filter -ErrorAction Stop).Count) {throw 'Unjournaled descriptor identities remain; manual reconciliation required.'}
        # Source order guarantees the first durable intent precedes AD writes.
        # The host still checks both DCs by markers and all deterministic SAMs.
        return [pscustomobject]@{run_id=$RunId;verified=$true;live_owned_objects_remaining=0;tombstones_retained=$true;journal_absent=$true;
            state=[pscustomobject]@{parent_guid=$null;actor_guid=$null;accounts=@([pscustomobject]@{guid=$null},[pscustomobject]@{guid=$null})}}
    }
    $state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
    if ($state.server -cne $Server -or $state.run_id -cne $RunId) {throw 'Descriptor cleanup run or server changed.'}
    $objects=@(Get-DescriptorFixtureLiveObjects $state $true)
    if ($objects.Count -eq 0 -and $state.phase -ceq 'removed') {
        return [pscustomobject]@{run_id=$RunId;verified=$true;live_owned_objects_remaining=0;tombstones_retained=$true;state=$state;already_removed=$true}
    }
    # Validate every child before the first deletion. No recursive delete.
    foreach ($object in @($objects|Where-Object DistinguishedName -CNE $state.parent_dn)) {
        Remove-ADObject -Server $Server -Identity ([guid]$object.ObjectGUID) -Confirm:$false -ErrorAction Stop
    }
    $parent=@($objects|Where-Object DistinguishedName -CEQ $state.parent_dn)
    if ($parent.Count -eq 1) {
        $children=@(Get-ADObject -Server $Server -SearchBase $state.parent_dn -SearchScope OneLevel -LDAPFilter '(objectClass=*)' -ErrorAction Stop)
        if ($children.Count) {throw 'Descriptor children remain; parent deletion refused.'}
        Remove-ADOrganizationalUnit -Server $Server -Identity ([guid]$parent[0].ObjectGUID) -Confirm:$false -ErrorAction Stop
    }
    if (@(Get-DescriptorFixtureLiveObjects $state $true).Count) {throw 'Descriptor fixture remains live after cleanup.'}
    Save-DescriptorFixtureState $state 'removed'
    return [pscustomobject]@{run_id=$RunId;verified=$true;live_owned_objects_remaining=0;tombstones_retained=$true;state=$state}
}
