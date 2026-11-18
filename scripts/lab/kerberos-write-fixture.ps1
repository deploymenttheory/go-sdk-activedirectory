#Requires -Version 5.1
# Dot-source after kerberos-fixture.ps1 inside the verified isolated DC guest.
# Apply strict policy first; remove this child fixture before common cleanup.

function Get-KerberosWriteNames([string]$RunId) {
    if ($RunId -cnotmatch '\A[a-z0-9][a-z0-9-]{5,39}\z') {throw 'Invalid SASL write fixture identity.'}
    $parent="OU=sdk-kerberos-$RunId,DC=ad,DC=sdk,DC=test"
    $child="OU=sasl,$parent"
    return [pscustomobject]@{
        parent_dn=$parent;child_dn=$child;contact_dn="CN=probe,$child"
        child_marker="sdk-sasl-child:$RunId";contact_marker="sdk-sasl-contact:$RunId"
        description_prefix="sdk-sasl-value:$($RunId):"
    }
}

function Assert-KerberosWriteState($RootState,$State) {
    $names=Get-KerberosWriteNames $RootState.run_id
    if ($State.schema_version -ne 1 -or $State.run_id -cne $RootState.run_id -or $State.server -cne $RootState.server -or
        $State.parent_dn -cne $names.parent_dn -or $RootState.parent_dn -cne $names.parent_dn -or
        $State.parent_guid -cne $RootState.parent_guid -or $State.client_guid -cne $RootState.client_guid -or
        $State.child_dn -cne $names.child_dn -or $State.contact_dn -cne $names.contact_dn -or
        $State.contact_marker -cne $names.contact_marker -or $State.child_marker -cne $names.child_marker -or
        $State.client_sid -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z') {throw 'SASL write fixture journal identity changed.'}
    foreach ($value in @($State.parent_guid,$State.client_guid,$State.child_guid,$State.contact_guid,$State.description_schema_guid)) {
        if ($null -ne $value -and $value -cne '' -and ([guid]$value) -eq [guid]::Empty) {throw 'Empty SASL fixture GUID.'}
    }
    if ($State.phase -cnotin @('prepared','child-created','contact-created','acl-prepared','ready','contact-removed','child-removed','cleaned')) {
        throw 'Unknown SASL write fixture phase.'
    }
}

function Assert-KerberosWriteObjects($RootState,$State,[object[]]$Objects,[bool]$AllowMissing) {
    Assert-KerberosWriteState $RootState $State
    $names=Get-KerberosWriteNames $State.run_id
    $expected=@{
        $State.parent_dn=@{guid=$State.parent_guid;class='organizationalUnit';marker="sdk-kerberos-parent:$($State.run_id)";attribute='description'}
        $RootState.client_dn=@{guid=$State.client_guid;class='user';marker="sdk-kerberos-client:$($State.run_id)";attribute='description'}
    }
    if ($State.child_guid) {$expected[$State.child_dn]=@{guid=$State.child_guid;class='organizationalUnit';marker=$State.child_marker;attribute='description'}}
    if ($State.contact_guid) {$expected[$State.contact_dn]=@{guid=$State.contact_guid;class='contact';marker=$State.contact_marker;attribute='displayName'}}
    $seen=@{}
    foreach ($object in $Objects) {
        $dn=[string]$object.DistinguishedName
        if (-not $expected.ContainsKey($dn) -or $seen.ContainsKey($dn)) {throw 'Unexpected, moved or duplicate SASL fixture descendant.'}
        $owned=$expected[$dn]
        if (([guid]$object.ObjectGUID) -ne ([guid]$owned.guid) -or $object.ObjectClass -cne $owned.class -or
            [string]$object.($owned.attribute) -cne $owned.marker) {throw 'SASL fixture object ownership changed.'}
        if ($dn -ceq $State.contact_dn -and -not ([string]$object.description).StartsWith($names.description_prefix,[StringComparison]::Ordinal)) {
            throw 'SASL contact description changed outside the owned probe.'
        }
        $seen[$dn]=$true
    }
    foreach ($dn in @($State.parent_dn,$RootState.client_dn)) {if (-not $seen.ContainsKey($dn)) {throw 'Common Kerberos fixture identity is absent.'}}
    if (-not $AllowMissing) {foreach ($dn in $expected.Keys) {if (-not $seen.ContainsKey($dn)) {throw 'Recorded SASL fixture object is absent or moved.'}}}
}

function Save-KerberosWriteState($State) {
    $directory=Get-KerberosFixtureDirectory $State.run_id
    $path=Assert-KerberosFixturePath (Join-Path $directory 'write-fixture.json')
    $temporary=Assert-KerberosFixturePath (Join-Path $directory 'write-fixture.next.json')
    [IO.File]::WriteAllText($temporary,($State|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $path -Force
}

function Get-KerberosWriteState($RootState) {
    $path=Assert-KerberosFixturePath (Join-Path (Get-KerberosFixtureDirectory $RootState.run_id) 'write-fixture.json')
    $state=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    Assert-KerberosWriteState $RootState $state
    return $state
}

function Get-KerberosWriteLiveObjects($RootState,$State,[bool]$AllowMissing=$false) {
    Assert-KerberosWriteState $RootState $State
    $objects=@(Get-ADObject -Server $State.server -SearchBase $State.parent_dn -SearchScope Subtree -LDAPFilter '(objectClass=*)' -Properties description,displayName)
    Assert-KerberosWriteObjects $RootState $State $objects $AllowMissing
    # A known GUID moved outside the search base is not absence.
    foreach ($pair in @(@($State.child_guid,$State.child_dn),@($State.contact_guid,$State.contact_dn))) {
        if (-not $pair[0]) {continue}
        $found=$null
        try {$found=Get-ADObject -Server $State.server -Identity ([guid]$pair[0]) -Properties description,displayName -ErrorAction Stop}
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {}
        if ($found -and $found.DistinguishedName -cne $pair[1]) {throw 'A known SASL fixture GUID moved outside its owned location.'}
        if (-not $found -and -not $AllowMissing) {throw 'A known SASL fixture GUID is absent.'}
    }
    return $objects
}

function Open-KerberosWriteDirectoryEntry([string]$Server,[guid]$GUID) {
    if ($GUID -eq [guid]::Empty -or $Server -cnotmatch '\Aadsdk(16|19|22|25)dc[12]\.ad\.sdk\.test\z') {throw 'Invalid pinned ACL target.'}
    $auth=[DirectoryServices.AuthenticationTypes]::Secure -bor [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
    $entry=[DirectoryServices.DirectoryEntry]::new("LDAP://$Server/<GUID=$($GUID.ToString('D'))>",$null,$null,$auth)
    try {
        $entry.Options.SecurityMasks=[DirectoryServices.SecurityMasks]::Owner -bor [DirectoryServices.SecurityMasks]::Group -bor [DirectoryServices.SecurityMasks]::Dacl
        $entry.RefreshCache(@('nTSecurityDescriptor'))
        if ($entry.Guid -ne $GUID) {throw 'ACL readback resolved a different GUID.'}
        return $entry
    } catch {$entry.Dispose();throw}
}

function Get-KerberosWriteSDDL($Entry) {
    $sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access
    return $Entry.ObjectSecurity.GetSecurityDescriptorSddlForm($sections)
}

function Assert-KerberosWriteACL($State,[string]$ActualSDDL) {
    if (-not $State.baseline_sddl -or -not $State.expected_sddl -or ($ActualSDDL -cne $State.baseline_sddl -and $ActualSDDL -cne $State.expected_sddl)) {
        throw 'The contact ACL changed outside the exact owned grant; refusing mutation.'
    }
}

function Assert-KerberosWriteGrant($Security,[string]$SID,[guid]$AttributeGUID) {
    $rules=@($Security.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -ceq $SID})
    if ($rules.Count -ne 1 -or $rules[0].ActiveDirectoryRights -ne [DirectoryServices.ActiveDirectoryRights]::WriteProperty -or
        $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rules[0].ObjectType -ne $AttributeGUID -or
        $rules[0].InheritedObjectType -ne [guid]::Empty -or $rules[0].InheritanceType -ne [DirectoryServices.ActiveDirectorySecurityInheritance]::None -or $rules[0].IsInherited) {
        throw 'The delegated contact grant exceeds the exact description property.'
    }
}

function New-KerberosWriteFixture([string]$RunId,[string]$ExpectedServer) {
    $root=Get-KerberosFixtureState $RunId $ExpectedServer
    Assert-KerberosPolicyLease $root
    if (-not $root.policy_applied) {throw 'Apply strict policy before creating the write fixture.'}
    $policy=@(Get-KerberosPolicySnapshot)
    foreach ($desired in @(Get-KerberosDesiredStrictPolicy)) {
        $actual=@($policy | Where-Object {$_.name -ceq $desired.name})
        if ($actual.Count -ne 1 -or -not $actual[0].present -or $actual[0].kind -cne 'DWord' -or $actual[0].value -ne $desired.value) {
            throw 'Actual strict policy differs before write fixture provisioning.'
        }
    }
    $names=Get-KerberosWriteNames $RunId
    $journal=Assert-KerberosFixturePath (Join-Path (Get-KerberosFixtureDirectory $RunId) 'write-fixture.json')
    if (Test-Path -LiteralPath $journal) {throw 'Write fixture journal must be fresh.'}
    $parent=Get-ADObject -Server $root.server -Identity ([guid]$root.parent_guid) -Properties description
    $children=@(Get-ADObject -Server $root.server -SearchBase $root.parent_dn -SearchScope Subtree -LDAPFilter '(objectClass=*)' -Properties description,sAMAccountName | Where-Object {$_.ObjectGUID -ne $parent.ObjectGUID})
    Assert-KerberosOwnedObjects $root $parent $children
    $client=Get-ADUser -Server $root.server -Identity ([guid]$root.client_guid) -Properties objectSid,description
    if ($client.DistinguishedName -cne $root.client_dn -or [string]$client.description -cne "sdk-kerberos-client:$RunId") {throw 'Dedicated client identity changed.'}
    $schema=Get-ADRootDSE -Server $root.server
    $attributes=@(Get-ADObject -Server $root.server -SearchBase $schema.schemaNamingContext -LDAPFilter '(&(objectClass=attributeSchema)(lDAPDisplayName=description))' -Properties schemaIDGUID)
    if ($attributes.Count -ne 1 -or $attributes[0].schemaIDGUID.Length -ne 16) {throw 'Description attribute schema identity is ambiguous.'}
    $schemaGUID=[guid]::new([byte[]]$attributes[0].schemaIDGUID)
    $state=[pscustomobject]@{
        schema_version=1;run_id=$RunId;server=$root.server;parent_dn=$names.parent_dn;parent_guid=$root.parent_guid;client_guid=$root.client_guid
        client_sid=$client.SID.Value;child_dn=$names.child_dn;contact_dn=$names.contact_dn;child_marker=$names.child_marker;contact_marker=$names.contact_marker
        child_guid=$null;contact_guid=$null;description_schema_guid=$schemaGUID.ToString('D');baseline_sddl=$null;expected_sddl=$null;phase='prepared'
    }
    Assert-KerberosWriteState $root $state
    Save-KerberosWriteState $state
    $child=New-ADOrganizationalUnit -Server $root.server -Name 'sasl' -Path $root.parent_dn -Description $names.child_marker -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Stop
    $state.child_guid=$child.ObjectGUID.ToString();$state.phase='child-created';Save-KerberosWriteState $state
    $null=Get-KerberosWriteLiveObjects $root $state
    $contact=New-ADObject -Server $root.server -Name 'probe' -Type contact -Path $names.child_dn -OtherAttributes @{displayName=$names.contact_marker;description=($names.description_prefix+'baseline')} -PassThru -ErrorAction Stop
    $state.contact_guid=$contact.ObjectGUID.ToString();$state.phase='contact-created';Save-KerberosWriteState $state
    $null=Get-KerberosWriteLiveObjects $root $state
    $entry=Open-KerberosWriteDirectoryEntry $root.server ([guid]$state.contact_guid)
    try {
        $state.baseline_sddl=Get-KerberosWriteSDDL $entry
        $security=$entry.ObjectSecurity
        $sid=[Security.Principal.SecurityIdentifier]::new($state.client_sid)
        $existing=@($security.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference.Value -ceq $state.client_sid})
        if ($existing.Count -ne 0) {throw 'Dedicated user already has an unexpected explicit contact ACE.'}
        $rule=[DirectoryServices.ActiveDirectoryAccessRule]::new($sid,[DirectoryServices.ActiveDirectoryRights]::WriteProperty,[Security.AccessControl.AccessControlType]::Allow,$schemaGUID,[DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        $security.AddAccessRule($rule)
        Assert-KerberosWriteGrant $security $state.client_sid $schemaGUID
        $sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access
        $state.expected_sddl=$security.GetSecurityDescriptorSddlForm($sections)
        $state.phase='acl-prepared';Save-KerberosWriteState $state # Journal BEFORE the ACL write.
        $null=Get-KerberosWriteLiveObjects $root $state
        $entry.RefreshCache(@('nTSecurityDescriptor'))
        if ((Get-KerberosWriteSDDL $entry) -cne $state.baseline_sddl) {throw 'Contact ACL changed before the owned grant.'}
        $entry.ObjectSecurity=$security
        $entry.CommitChanges()
    } finally {$entry.Dispose()}
    $entry=Open-KerberosWriteDirectoryEntry $root.server ([guid]$state.contact_guid)
    try {
        if ((Get-KerberosWriteSDDL $entry) -cne $state.expected_sddl) {throw 'Independent contact ACL readback differs.'}
        Assert-KerberosWriteGrant $entry.ObjectSecurity $state.client_sid $schemaGUID
    } finally {$entry.Dispose()}
    $state.phase='ready';Save-KerberosWriteState $state
    return $state
}

function Remove-KerberosWriteFixture([string]$RunId,[string]$ExpectedServer) {
    $root=Get-KerberosFixtureState $RunId $ExpectedServer
    $state=Get-KerberosWriteState $root
    $objects=@(Get-KerberosWriteLiveObjects $root $state $true)
    $contact=@($objects | Where-Object {$_.DistinguishedName -ceq $state.contact_dn})
    if ($contact.Count -gt 1) {throw 'Ambiguous contact reconciliation.'}
    if ($contact.Count -eq 1) {
        $entry=Open-KerberosWriteDirectoryEntry $root.server ([guid]$state.contact_guid)
        try {Assert-KerberosWriteACL $state (Get-KerberosWriteSDDL $entry)} finally {$entry.Dispose()}
        Remove-ADObject -Server $root.server -Identity ([guid]$state.contact_guid) -Confirm:$false
        $state.phase='contact-removed';Save-KerberosWriteState $state
    }
    $objects=@(Get-KerberosWriteLiveObjects $root $state $true)
    if (@($objects | Where-Object {$_.DistinguishedName -ceq $state.contact_dn}).Count -ne 0) {throw 'Owned contact remains live.'}
    $child=@($objects | Where-Object {$_.DistinguishedName -ceq $state.child_dn})
    if ($child.Count -eq 1) {
        Remove-ADOrganizationalUnit -Server $root.server -Identity ([guid]$state.child_guid) -Confirm:$false
        $state.phase='child-removed';Save-KerberosWriteState $state
    }
    $remaining=@(Get-KerberosWriteLiveObjects $root $state $true)
    if ($remaining.Count -ne 2) {throw 'SASL write fixture cleanup is incomplete.'}
    $parent=@($remaining | Where-Object {$_.DistinguishedName -ceq $root.parent_dn})
    $client=@($remaining | Where-Object {$_.DistinguishedName -ceq $root.client_dn})
    Assert-KerberosOwnedObjects $root $parent[0] $client
    $state.phase='cleaned';Save-KerberosWriteState $state
    return [pscustomobject]@{run_id=$RunId;contact_guid=$state.contact_guid;child_guid=$state.child_guid;verified=$true;live_owned_objects_remaining=0;tombstones_retained=$true;common_fixture_guard_passed=$true}
}
