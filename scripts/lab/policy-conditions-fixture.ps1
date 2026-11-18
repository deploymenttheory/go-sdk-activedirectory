#Requires -Version 5.1
# Functions only: exclusive provisioning of four new config-NC fixtures.
# Load the byte-recorded security-descriptor-fixture.ps1 first for its native
# Kerberos+Sign/Seal LDAP connection, GUID target, and controlled DACL read helpers.
# This provisioning code is never an SDK runtime or production atomic ACL route.

function Get-PolicyConditionTargets([string]$RunId) {
    if ($RunId -cnotmatch '\A[A-Za-z0-9-]{1,40}\z') {throw 'Invalid policy fixture run identity.'}
    $configuration='CN=Configuration,DC=ad,DC=sdk,DC=test'
    foreach ($role in @('auth','auth-denied','rule','rule-denied')) {
        $parent='CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,'+$configuration
        $class='msDS-AuthNPolicy'
        if ($role.StartsWith('rule')) {$parent='CN=Central Access Rules,CN=Claims Configuration,CN=Services,'+$configuration;$class='msAuthz-CentralAccessRule'}
        [pscustomobject]@{role=$role;dn="CN=sdk08-$RunId-$role,$parent";name="sdk08-$RunId-$role";parent=$parent;class=$class;marker="sdk08-condition:$RunId`:$role"}
    }
}

function Get-PolicyConditionAttributes([bool]$Authentication) {
    if ($Authentication) {
        return @('msDS-UserAllowedToAuthenticateFrom','msDS-UserAllowedToAuthenticateTo','msDS-ComputerAllowedToAuthenticateTo',
            'msDS-ServiceAllowedToAuthenticateFrom','msDS-ServiceAllowedToAuthenticateTo')
    }
    return @('msAuthz-EffectiveSecurityPolicy','msAuthz-ProposedSecurityPolicy','msAuthz-LastEffectiveSecurityPolicy','msAuthz-ResourceCondition')
}

function Get-PolicyConditionReferencePairs {
    @(
        [pscustomobject]@{forward='msDS-UserAuthNPolicy';back='msDS-UserAuthNPolicyBL';link_id=2206},
        [pscustomobject]@{forward='msDS-ComputerAuthNPolicy';back='msDS-ComputerAuthNPolicyBL';link_id=2208},
        [pscustomobject]@{forward='msDS-ServiceAuthNPolicy';back='msDS-ServiceAuthNPolicyBL';link_id=2210},
        [pscustomobject]@{forward='msDS-AssignedAuthNPolicy';back='msDS-AssignedAuthNPolicyBL';link_id=2212},
        [pscustomobject]@{forward='msAuthz-MemberRulesInCentralAccessPolicy';back='msAuthz-MemberRulesInCentralAccessPolicyBL';link_id=2184}
    )
}

function Read-PolicyConditionReferenceSchema([string]$Server) {
    $result=@()
    foreach ($pair in Get-PolicyConditionReferencePairs) {
        foreach ($back in @($false,$true)) {
            $name=$pair.forward;$link=$pair.link_id
            if ($back) {$name=$pair.back;$link++}
            $rows=@(Get-ADObject -Server $Server -SearchBase 'CN=Schema,CN=Configuration,DC=ad,DC=sdk,DC=test' -SearchScope OneLevel -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$name))" -Properties lDAPDisplayName,linkID,schemaIDGUID,isDefunct -ErrorAction Stop -WarningAction Stop)
            if ($rows.Count -ne 1 -or $rows[0].lDAPDisplayName -cne $name -or $rows[0].linkID -ne $link -or
                $rows[0].schemaIDGUID.Length -ne 16 -or $rows[0].isDefunct) {throw 'Policy reference schema identity or link pair differs.'}
            $result+=[pscustomobject]@{name=$name;link_id=$link;guid=([guid]::new([byte[]]$rows[0].schemaIDGUID)).ToString()}
        }
    }
    return $result
}

function Test-PolicyConditionForwardReferences($State,[string]$Server) {
    # Query completion is mandatory. A failed/partial ADWS enumeration raises
    # with Error/WarningAction Stop and cannot become an empty reference set.
    # These are independent forward-link checks, not just absent backlinks.
    $observations=@()
    foreach ($target in $State.targets) {
        $pairs=@(Get-PolicyConditionReferencePairs|Where-Object {$_.forward.StartsWith('msDS-') -eq $target.role.StartsWith('auth')})
        $filter='(|'
        foreach ($pair in $pairs) {$filter+='('+$pair.forward+'='+$target.dn+')'}
        $filter+=')'
        $bases=@('CN=Configuration,DC=ad,DC=sdk,DC=test')
        if ($target.role.StartsWith('auth')) {$bases+=,'DC=ad,DC=sdk,DC=test'}
        foreach ($base in $bases) {
            $references=@(Get-ADObject -Server $Server -SearchBase $base -SearchScope Subtree -LDAPFilter $filter -ResultSetSize $null -Properties objectGUID -ErrorAction Stop -WarningAction Stop)
            $observations+=[pscustomobject]@{role=$target.role;server=$Server;search_base=$base;references=$references.Count;complete=$true;checked_utc=[DateTime]::UtcNow.ToString('o')}
            if ($references.Count) {throw 'Policy fixture acquired an assignment or silo/central-policy association; cleanup refused.'}
        }
    }
    return $observations
}

function Assert-PolicyConditionContext([string]$RunId,[string]$Server) {
    $null=Get-PolicyConditionTargets $RunId
    if ($Server -cnotmatch '\Aadsdk(16|19|22|25)dc1\.ad\.sdk\.test\z' -or
        $Server -ine ($env:COMPUTERNAME+'.ad.sdk.test')) {throw 'Unexpected isolated policy fixture DC.'}
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $root=Get-ADRootDSE -Server $Server -ErrorAction Stop
    if ($root.configurationNamingContext -cne 'CN=Configuration,DC=ad,DC=sdk,DC=test' -or
        $root.defaultNamingContext -cne 'DC=ad,DC=sdk,DC=test' -or $root.dnsHostName -ine $Server) {throw 'Policy fixture directory identity differs.'}
    return $root
}

function Assert-PolicyConditionPath([string]$Path) {
    $root=[IO.Path]::GetFullPath('C:\adsdk-policy-fixtures').TrimEnd('\')
    $full=[IO.Path]::GetFullPath($Path)
    if ($full -cne $root -and -not $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Policy journal escaped its root.'}
    for ($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Policy journal traverses a reparse point.'}
    }
    return $full
}

function Initialize-PolicyConditionJournal([string]$RunId,[string]$Server) {
    $root=Assert-PolicyConditionPath 'C:\adsdk-policy-fixtures'
    $marker=Join-Path $root 'owner.json'
    if (Test-Path -LiteralPath $root) {
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {throw 'Existing policy journal root is not owned.'}
        $owner=Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json
        if ($owner.schema_version -ne 1 -or $owner.purpose -cne 'sdk-policy-condition-fixtures' -or $owner.server -cne $Server) {throw 'Policy journal root identity differs.'}
    } else {
        $null=New-Item -ItemType Directory -Path $root
        [IO.File]::WriteAllText($marker,(@{schema_version=1;purpose='sdk-policy-condition-fixtures';server=$Server}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    }
    $directory=Assert-PolicyConditionPath (Join-Path $root $RunId)
    if (Test-Path -LiteralPath $directory) {throw 'Fresh policy fixture journal required.'}
    $null=New-Item -ItemType Directory -Path $directory
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $root -AclObject $acl;Set-Acl -LiteralPath $directory -AclObject $acl
}

function Save-PolicyConditionState($State,[string]$Phase) {
    $State.phase=$Phase;$State.updated_utc=[DateTime]::UtcNow.ToString('o');$State.journal_index++
    $directory=Assert-PolicyConditionPath (Join-Path 'C:\adsdk-policy-fixtures' $State.run_id)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($State|ConvertTo-Json -Depth 16))
    $event=Join-Path $directory ('event-{0:d4}.json' -f $State.journal_index)
    $file=[IO.File]::Open($event,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$file.Write($bytes,0,$bytes.Length)} finally {$file.Dispose()}
    [IO.File]::WriteAllBytes((Join-Path $directory 'state.json'),$bytes)
}

function Assert-PolicyConditionState($State) {
    if ($State.schema_version -ne 1 -or $State.purpose -cne 'sdk-policy-condition-fixture' -or
        $State.server -cnotmatch '\Aadsdk(16|19|22|25)dc1\.ad\.sdk\.test\z' -or
        $State.actor_sid -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z') {throw 'Policy fixture journal identity differs.'}
    $plan=@(Get-PolicyConditionTargets $State.run_id)
    if (@($State.targets).Count -ne 4) {throw 'Policy fixture target count changed.'}
    $seen=@{}
    foreach ($expected in $plan) {
        $target=@($State.targets|Where-Object role -CEQ $expected.role)
        if ($target.Count -ne 1 -or $target[0].dn -cne $expected.dn -or $target[0].class -cne $expected.class -or $target[0].marker -cne $expected.marker) {throw 'Policy fixture target plan differs.'}
        if ($target[0].guid) {
            $guid=([guid]$target[0].guid).ToString()
            if ($guid -ceq ([guid]::Empty).ToString() -or $seen.ContainsKey($guid)) {throw 'Policy fixture GUID is empty or duplicated.'}
            $seen[$guid]=$true
        }
    }
}

function Assert-PolicyConditionObjects($State,[object[]]$Objects,[bool]$AllowMissing) {
    Assert-PolicyConditionState $State
    $seen=@{}
    foreach ($object in $Objects) {
        $target=@($State.targets|Where-Object dn -CEQ $object.DistinguishedName)
        if ($target.Count -ne 1 -or $seen.ContainsKey($object.DistinguishedName) -or $object.ObjectClass -cne $target[0].class -or
            $object.description -cne $target[0].marker) {throw 'Unknown, moved, duplicated or foreign policy fixture object.'}
        $target=$target[0];$seen[$object.DistinguishedName]=$true
        if ($target.guid) {
            if ([guid]$target.guid -ne [guid]$object.ObjectGUID) {throw 'Policy fixture GUID was replaced.'}
        } elseif ($State.phase -cne ($target.role+'-create-intent')) {throw 'Unrecorded policy GUID outside its creation intent.'}
        if ($target.role.StartsWith('auth') -and $object.'msDS-AuthNPolicyEnforced' -ne $false) {throw 'Policy fixture audit state changed.'}
        foreach ($pair in Get-PolicyConditionReferencePairs) {
            if ($pair.forward.StartsWith('msDS-') -ne $target.role.StartsWith('auth')) {continue}
            if ($null -eq $object.PSObject.Properties[$pair.back]) {throw 'Requested policy backlink was not observed by the fixture reader.'}
            if ($null -ne $object.($pair.back) -and @($object.($pair.back)).Count -ne 0) {throw 'Owned policy acquired an assignment or silo/central-policy association; cleanup refused.'}
        }
    }
    if (-not $AllowMissing -and $seen.Count -ne 4) {throw 'Ready policy fixture is incomplete.'}
}

function Get-PolicyConditionObjects($State,[string]$Server,[bool]$AllowMissing) {
    Assert-PolicyConditionState $State
    $filter='(|(description=sdk08-condition:'+$State.run_id+':*)(name=sdk08-'+$State.run_id+'-*)'
    foreach ($target in $State.targets) {
        if ($target.guid) {$hex=([guid]$target.guid).ToByteArray()|ForEach-Object {'\'+$_.ToString('x2')};$filter+='(objectGUID='+($hex -join '')+')'}
    }
    $filter+=')'
    $objects=@(Get-ADObject -Server $Server -SearchBase 'CN=Configuration,DC=ad,DC=sdk,DC=test' -SearchScope Subtree -LDAPFilter $filter -Properties description,
        'msDS-AuthNPolicyEnforced','msDS-AssignedAuthNPolicyBL','msDS-UserAuthNPolicyBL','msDS-ComputerAuthNPolicyBL','msDS-ServiceAuthNPolicyBL',
        'msAuthz-MemberRulesInCentralAccessPolicyBL' -ErrorAction Stop -WarningAction Stop)
    Assert-PolicyConditionObjects $State $objects $AllowMissing
    return $objects
}

function Assert-PolicyConditionGrant([byte[]]$Raw,[string]$SID,[object[]]$Attributes,[bool]$Denied) {
    $schemaSeen=@{}
    foreach ($attribute in $Attributes) {
        $guid=([guid]$attribute.guid).ToString()
        if ($guid -ceq ([guid]::Empty).ToString() -or $schemaSeen.ContainsKey($guid)) {throw 'Policy grant attribute GUID is empty or duplicated.'}
        $schemaSeen[$guid]=$true
    }
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Raw,0)
    if (-not $descriptor.DiscretionaryAcl -or $descriptor.DiscretionaryAcl.Revision -ne 4) {throw 'Policy object grants require ACL revision4.'}
    $owned=@($descriptor.DiscretionaryAcl|Where-Object {($_ -is [Security.AccessControl.KnownAce]) -and $_.SecurityIdentifier.Value -ceq $SID})
    if ($owned.Count -ne ($Attributes.Count+1)) {throw 'Unexpected policy actor grant count.'}
    $read=@($owned|Where-Object {$_ -is [Security.AccessControl.CommonAce]})
    if ($read.Count -ne 1 -or $read[0].AccessMask -ne 0x10 -or $read[0].AceFlags -ne 0 -or
        $read[0].AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed) {throw 'Policy actor read grant exceeds ReadProperty.'}
    $qualifier=[Security.AccessControl.AceQualifier]::AccessAllowed
    if ($Denied) {$qualifier=[Security.AccessControl.AceQualifier]::AccessDenied}
    foreach ($attribute in $Attributes) {
        $matches=@($owned|Where-Object {$_ -is [Security.AccessControl.ObjectAce] -and $_.ObjectAceType -eq [guid]$attribute.guid})
        if ($matches.Count -ne 1 -or $matches[0].AccessMask -ne 0x20 -or $matches[0].AceFlags -ne 0 -or $matches[0].AceQualifier -ne $qualifier -or
            $matches[0].ObjectAceFlags -ne [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) {throw 'Policy actor grant exceeds exact attribute WriteProperty.'}
    }
}

function Set-PolicyConditionGrant($State,$Target,[PSCredential]$Credential) {
    $connection=Open-DescriptorFixtureConnection $State.server $Credential
    try {
        $raw=Read-DescriptorFixtureDACL $connection ([guid]$Target.guid) $Target.marker
        $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($raw,0)
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if ($ace -is [Security.AccessControl.KnownAce] -and $ace.SecurityIdentifier.Value -ceq $State.actor_sid) {throw 'Policy actor already has an unexpected fixture grant.'}
        }
        $names=@(Get-PolicyConditionAttributes ($Target.role.StartsWith('auth')))
        $attributes=@($State.attributes|Where-Object {$_.name -cin $names})
        if ($attributes.Count -ne $names.Count -or @($attributes.name|Select-Object -Unique).Count -ne $names.Count) {throw 'Policy attribute delegation plan is incomplete or duplicated.'}
        $denied=$Target.role.EndsWith('-denied')
        $sid=[Security.Principal.SecurityIdentifier]::new($State.actor_sid)
        $grants=@([Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,0x10,$sid,$false,$null))
        $qualifier=[Security.AccessControl.AceQualifier]::AccessAllowed
        if ($denied) {$qualifier=[Security.AccessControl.AceQualifier]::AccessDenied}
        foreach ($attribute in $attributes) {
            $grants+=[Security.AccessControl.ObjectAce]::new([Security.AccessControl.AceFlags]::None,$qualifier,0x20,$sid,
                [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,[guid]$attribute.guid,[guid]::Empty,$false,$null)
        }
        $acl=[Security.AccessControl.RawAcl]::new(4,$descriptor.DiscretionaryAcl.Count+$grants.Count)
        if ($denied) {foreach ($grant in $grants|Where-Object {$_ -is [Security.AccessControl.ObjectAce]}) {$acl.InsertAce($acl.Count,$grant)}}
        $inserted=$false
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if (-not $inserted -and (([int]$ace.AceFlags -band 0x10) -ne 0)) {
                foreach ($grant in $grants) {if (-not $denied -or $grant -is [Security.AccessControl.CommonAce]) {$acl.InsertAce($acl.Count,$grant)}}
                $inserted=$true
            }
            $acl.InsertAce($acl.Count,$ace)
        }
        if (-not $inserted) {foreach ($grant in $grants) {if (-not $denied -or $grant -is [Security.AccessControl.CommonAce]) {$acl.InsertAce($acl.Count,$grant)}}}
        $descriptor.DiscretionaryAcl=$acl
        $next=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($next,0)
        Assert-PolicyConditionGrant $next $State.actor_sid $attributes $denied
        $Target.before_dacl_base64=[Convert]::ToBase64String($raw);$Target.proposed_dacl_base64=[Convert]::ToBase64String($next)
        Save-PolicyConditionState $State ($Target.role+'-grant-intent')
        $current=Read-DescriptorFixtureDACL $connection ([guid]$Target.guid) $Target.marker
        if ([Convert]::ToBase64String($current) -cne $Target.before_dacl_base64) {throw 'Exclusive new policy fixture DACL changed before provisioning.'}
        $request=[DirectoryServices.Protocols.ModifyRequest]::new((Get-DescriptorFixtureGUIDTarget ([guid]$Target.guid)))
        $mod=[DirectoryServices.Protocols.DirectoryAttributeModification]::new();$mod.Name='nTSecurityDescriptor';$mod.Operation=[DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        $null=$mod.Add($next);$null=$request.Modifications.Add($mod)
        $control=[DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new([DirectoryServices.Protocols.SecurityMasks]::Dacl);$control.IsCritical=$true;$null=$request.Controls.Add($control)
        $response=$connection.SendRequest($request)
        if ([int]$response.ResultCode -ne 0) {throw 'Policy fixture delegation refused.'}
        $actual=Read-DescriptorFixtureDACL $connection ([guid]$Target.guid) $Target.marker
        Assert-PolicyConditionGrant $actual $State.actor_sid $attributes $denied
        $Target.ready_dacl_base64=[Convert]::ToBase64String($actual)
        Save-PolicyConditionState $State ($Target.role+'-grant-verified')
    } finally {$connection.Dispose()}
}

function New-PolicyConditionFixture([string]$RunId,[string]$Server,[string]$ActorSID,[PSCredential]$Credential) {
    $root=Assert-PolicyConditionContext $RunId $Server
    if (-not $Credential -or $ActorSID -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z') {throw 'Dedicated actor SID and protected provisioning credential required.'}
    $actor=Get-ADUser -Server $Server -Identity $ActorSID -Properties Enabled,'msDS-SupportedEncryptionTypes' -ErrorAction Stop
    if (-not $actor.Enabled -or $actor.SID.Value -cne $ActorSID -or $actor.'msDS-SupportedEncryptionTypes' -ne 24) {throw 'Dedicated AES actor identity differs.'}
    $plan=@(Get-PolicyConditionTargets $RunId)
    $attributes=@()
    foreach ($name in @((Get-PolicyConditionAttributes $true)+(Get-PolicyConditionAttributes $false))) {
        $schema=@(Get-ADObject -Server $Server -SearchBase $root.schemaNamingContext -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$name))" -Properties schemaIDGUID,isDefunct -ErrorAction Stop)
        if ($schema.Count -ne 1 -or $schema[0].schemaIDGUID.Length -ne 16 -or $schema[0].isDefunct) {throw 'Exact policy attribute schema GUID unavailable.'}
        $guid=[guid]::new([byte[]]$schema[0].schemaIDGUID)
        if ($guid -eq [guid]::Empty -or @($attributes|Where-Object guid -CEQ $guid.ToString()).Count) {throw 'Policy schema GUID is empty or duplicated.'}
        $attributes+=[pscustomobject]@{name=$name;guid=$guid.ToString()}
    }
    $referenceSchema=@(Read-PolicyConditionReferenceSchema $Server)
    $state=[pscustomobject]@{
        schema_version=1;purpose='sdk-policy-condition-fixture';run_id=$RunId;server=$Server;actor_sid=$ActorSID;actor_guid=$actor.ObjectGUID.ToString()
        phase='planned';journal_index=0;updated_utc=$null;attributes=$attributes;targets=@();reference_schema=$referenceSchema;reference_checks=@()
        assignments_or_enforcement=$false;global_policy_or_claim_changes=$false;actor_cleanup_owned_by_outer_fixture=$true
    }
    foreach ($target in $plan) {
        $state.targets+=[pscustomobject]@{role=$target.role;dn=$target.dn;class=$target.class;marker=$target.marker;guid=$null;
            before_dacl_base64=$null;proposed_dacl_base64=$null;ready_dacl_base64=$null}
    }
    if (@(Get-PolicyConditionObjects $state $Server $true).Count) {throw 'Policy fixture namespace is not fresh.'}
    Initialize-PolicyConditionJournal $RunId $Server
    Save-PolicyConditionState $state 'planned'
    foreach ($target in $plan) {
        $record=@($state.targets|Where-Object role -CEQ $target.role)[0]
        Save-PolicyConditionState $state ($target.role+'-create-intent')
        $other=@{}
        if ($target.role.StartsWith('auth')) {$other['msDS-AuthNPolicyEnforced']=$false}
        else {$other['msAuthz-EffectiveSecurityPolicy']='O:SYG:SYD:(A;;FR;;;WD)'}
        $object=New-ADObject -Server $Server -Type $target.class -Name $target.name -Path $target.parent -Description $target.marker -OtherAttributes $other -PassThru -ErrorAction Stop
        $record.guid=$object.ObjectGUID.ToString();Save-PolicyConditionState $state ($target.role+'-created')
        Set-PolicyConditionGrant $state $record $Credential
    }
    $null=Get-PolicyConditionObjects $state $Server $false
    $state.reference_checks=@(Test-PolicyConditionForwardReferences $state $Server)
    Save-PolicyConditionState $state 'ready'
    return $state
}

function Remove-PolicyConditionFixture([string]$RunId,[string]$Server) {
    $null=Assert-PolicyConditionContext $RunId $Server
    $path=Assert-PolicyConditionPath (Join-Path (Join-Path 'C:\adsdk-policy-fixtures' $RunId) 'state.json')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {throw 'Policy cleanup requires its recorded journal.'}
    $state=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    if ($state.run_id -cne $RunId -or $state.server -cne $Server) {throw 'Policy cleanup journal endpoint differs.'}
    $objects=@(Get-PolicyConditionObjects $state $Server $true)
    $state.reference_schema=@(Read-PolicyConditionReferenceSchema $Server)
    $state.reference_checks=@(Test-PolicyConditionForwardReferences $state $Server)
    # Check every identity before the first deletion, including GUID-less create
    # intents. No recursive delete, arbitrary DN adoption or assignment removal.
    foreach ($object in $objects) {
        $target=@($state.targets|Where-Object dn -CEQ $object.DistinguishedName)[0]
        if (-not $target.guid) {$target.guid=$object.ObjectGUID.ToString()}
    }
    Save-PolicyConditionState $state 'cleanup-planned'
    foreach ($target in $state.targets) {
        $objects=@(Get-PolicyConditionObjects $state $Server $true)
        $state.reference_checks+=@(Test-PolicyConditionForwardReferences $state $Server)
        $object=@($objects|Where-Object DistinguishedName -CEQ $target.dn)
        if ($object.Count -eq 0) {continue}
        Save-PolicyConditionState $state ($target.role+'-delete-intent')
        Remove-ADObject -Server $Server -Identity ([guid]$target.guid) -Confirm:$false -ErrorAction Stop
        Save-PolicyConditionState $state ($target.role+'-deleted')
    }
    $null=Get-PolicyConditionObjects $state $Server $true
    $observations=@();$verified=$false
    for ($attempt=0;$attempt -lt 15;$attempt++) {
        $observations=@(foreach ($dc in @($Server,$Server.Replace('dc1.','dc2.'))) {
            $remaining=@(Get-PolicyConditionObjects $state $dc $true)
            [pscustomobject]@{server=$dc;search_base='CN=Configuration,DC=ad,DC=sdk,DC=test';live_owned_objects_remaining=$remaining.Count;checked_utc=[DateTime]::UtcNow.ToString('o')}
        })
        if (@($observations|Where-Object live_owned_objects_remaining -NE 0).Count -eq 0) {$verified=$true;break}
        Start-Sleep -Seconds 2
    }
    Save-PolicyConditionState $state 'cleanup-observed'
    return [pscustomobject]@{run_id=$RunId;verified=$verified;observations=$observations;state=$state;actor_cleanup_owned_by_outer_fixture=$true;tombstones_retained=$true}
}
