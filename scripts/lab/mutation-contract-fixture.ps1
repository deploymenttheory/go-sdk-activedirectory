#Requires -Version 5.1
# Functions only. Owned AD lab provisioning/reference tooling, never SDK runtime.
# Load the byte-recorded security-descriptor-fixture.ps1 for its Kerberos-only
# signed/sealed connection and critical DACL read helpers. No policy/KDS changes.

function Get-MutationFixturePlan([string]$RunId) {
    if ($RunId -cnotmatch '\A[A-Za-z0-9-]{1,40}\z') {throw 'Invalid mutation fixture run identity.'}
    $domain='DC=ad,DC=sdk,DC=test';$configuration='CN=Configuration,'+$domain
    $parent="OU=sdk09-$RunId,$domain";$site="CN=sdk09-$RunId,CN=Sites,$configuration"
    foreach ($role in @('parent','subject','manager','hidden','group-allowed','group-denied','delete-unverified','delete-verified','site','settings','servers','licensing')) {
        $name=$role;$class='user';$container=$parent;$sam=$null
        switch -CaseSensitive ($role) {
            'parent' {$name='sdk09-'+$RunId;$class='organizationalUnit';$container=$domain}
            'site' {$name='sdk09-'+$RunId;$class='site';$container='CN=Sites,'+$configuration}
            'settings' {$name='NTDS Site Settings';$class='nTDSSiteSettings';$container=$site}
            'servers' {$name='Servers';$class='serversContainer';$container=$site}
            'licensing' {$name='Licensing Site Settings';$class='licensingSiteSettings';$container=$site}
            {$_ -cin @('group-allowed','group-denied')} {$class='group'}
        }
        if ($class -cin @('user','group')) {
            $sha=[Security.Cryptography.SHA256]::Create()
            try {$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($RunId+':'+$role))} finally {$sha.Dispose()}
            $sam='sd9'+([BitConverter]::ToString($digest).Replace('-','').ToLowerInvariant()).Substring(0,12)
        }
        $rdn='CN';if ($role -ceq 'parent') {$rdn='OU'}
        $marker="sdk09-value:$RunId`:$role";if ($role -ceq 'parent') {$marker='sdk09-mutations:'+$RunId}
        [pscustomobject]@{role=$role;name=$name;dn="$rdn=$name,$container";parent=$container;class=$class;sam=$sam;marker=$marker}
    }
}

function Assert-MutationFixtureContext([string]$RunId,[string]$Server) {
    $null=Get-MutationFixturePlan $RunId
    if ($Server -cnotmatch '\Aadsdk(16|19|22|25)dc1\.ad\.sdk\.test\z' -or $Server -ine "$env:COMPUTERNAME.ad.sdk.test") {throw 'Unexpected mutation lab DC.'}
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $root=Get-ADRootDSE -Server $Server -ErrorAction Stop -WarningAction Stop
    if ($root.defaultNamingContext -cne 'DC=ad,DC=sdk,DC=test' -or $root.configurationNamingContext -cne 'CN=Configuration,DC=ad,DC=sdk,DC=test' -or
        $root.dnsHostName -ine $Server) {throw 'Mutation fixture directory identity differs.'}
    return $root
}

function Assert-MutationFixturePath([string]$Path) {
    $root=[IO.Path]::GetFullPath('C:\adsdk-mutation-fixtures').TrimEnd('\');$full=[IO.Path]::GetFullPath($Path)
    if ($full -cne $root -and -not $full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Mutation journal escaped its root.'}
    for ($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Mutation journal traverses a reparse point.'}
    }
    return $full
}

function Initialize-MutationFixtureJournal([string]$RunId,[string]$Server) {
    $root=Assert-MutationFixturePath 'C:\adsdk-mutation-fixtures';$marker=Join-Path $root 'owner.json'
    if (Test-Path -LiteralPath $root) {
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {throw 'Existing mutation journal root is unowned.'}
        $owner=Get-Content -LiteralPath $marker -Raw|ConvertFrom-Json
        if ($owner.schema_version -ne 1 -or $owner.purpose -cne 'sdk-mutation-journals' -or $owner.server -cne $Server) {throw 'Mutation journal owner differs.'}
    } else {
        $null=New-Item -ItemType Directory -Path $root
        [IO.File]::WriteAllText($marker,(@{schema_version=1;purpose='sdk-mutation-journals';server=$Server}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    }
    $directory=Assert-MutationFixturePath (Join-Path $root $RunId)
    if (Test-Path -LiteralPath $directory) {throw 'Fresh mutation fixture journal required.'}
    $null=New-Item -ItemType Directory -Path $directory
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $root -AclObject $acl;Set-Acl -LiteralPath $directory -AclObject $acl
}

function Save-MutationFixtureState($State,[string]$Phase) {
    $State.phase=$Phase;$State.updated_utc=[DateTime]::UtcNow.ToString('o');$State.journal_index++
    $directory=Assert-MutationFixturePath (Join-Path 'C:\adsdk-mutation-fixtures' $State.run_id)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($State|ConvertTo-Json -Depth 16))
    $stream=[IO.File]::Open((Join-Path $directory ('event-{0:d4}.json' -f $State.journal_index)),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$stream.Write($bytes,0,$bytes.Length)} finally {$stream.Dispose()}
    [IO.File]::WriteAllBytes((Join-Path $directory 'state.json'),$bytes)
}

function Assert-MutationFixtureState($State) {
    if ($State.schema_version -ne 1 -or $State.purpose -cne 'sdk-mutation-contract-fixture' -or
        $State.server -cnotmatch '\Aadsdk(16|19|22|25)dc1\.ad\.sdk\.test\z' -or
        $State.actor_sid -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z' -or ([guid]$State.actor_guid) -eq [guid]::Empty) {throw 'Mutation state actor or directory identity differs.'}
    $plan=@(Get-MutationFixturePlan $State.run_id)
    if (@($State.targets).Count -ne $plan.Count) {throw 'Mutation target plan count differs.'}
    $schemaSeen=@{}
    if (@($State.attributes).Count -ne 4) {throw 'Mutation delegation schema inventory differs.'}
    foreach ($name in @('manager','description','member','options')) {
        $attribute=@($State.attributes|Where-Object name -CEQ $name)
        if ($attribute.Count -ne 1) {throw 'Mutation attribute identity missing or duplicated.'}
        $guid=([guid]$attribute[0].guid).ToString()
        if ($guid -ceq ([guid]::Empty).ToString() -or $schemaSeen.ContainsKey($guid)) {throw 'Empty or duplicate mutation attribute GUID.'}
        $schemaSeen[$guid]=$true
    }
    $seen=@{}
    foreach ($expected in $plan) {
        $target=@($State.targets|Where-Object role -CEQ $expected.role)
        if ($target.Count -ne 1 -or $target[0].dn -cne $expected.dn -or $target[0].class -cne $expected.class -or $target[0].sam -cne $expected.sam) {throw 'Mutation target identity plan differs.'}
        if ($target[0].guid) {
            $guid=([guid]$target[0].guid).ToString()
            if ($guid -ceq ([guid]::Empty).ToString() -or $seen.ContainsKey($guid)) {throw 'Empty or duplicate mutation fixture GUID.'}
            $seen[$guid]=$true
        }
    }
}

function Assert-MutationFixtureObjects($State,[object[]]$Objects,[bool]$AllowMissing) {
    Assert-MutationFixtureState $State
    $seen=@{};$plan=@(Get-MutationFixturePlan $State.run_id)
    foreach ($object in $Objects) {
        $target=@($State.targets|Where-Object dn -CEQ $object.DistinguishedName)
        if ($target.Count -ne 1 -or $seen.ContainsKey($object.DistinguishedName)) {throw 'Foreign, moved or duplicate mutation fixture descendant.'}
        $target=$target[0];$seen[$target.dn]=$true
        if ($object.ObjectClass -cne $target.class -or ($target.sam -and $object.sAMAccountName -cne $target.sam) -or
            ($target.guid -and ([guid]$object.ObjectGUID) -ne ([guid]$target.guid))) {throw 'Mutation fixture GUID, class or account name differs.'}
        if (-not $target.guid -and $State.phase -cne ($target.role+'-create-intent')) {throw 'Unrecorded mutation GUID outside exact creation intent.'}
        if ($target.role -ceq 'parent' -and $object.description -cne ('sdk09-mutations:'+$State.run_id)) {throw 'Immutable mutation parent marker differs.'}
        if ($target.class -ceq 'user' -and (([int64]$object.userAccountControl -band 2) -eq 0)) {throw 'Mutation fixture user became enabled.'}
        # Mutable description values are deliberately not ownership markers.
        foreach ($property in @('member','memberOf','directReports','manager','managedBy')) {
            if ($null -eq $object.PSObject.Properties[$property]) {throw 'Mutation association observation was omitted by the reference reader.'}
            foreach ($link in @($object.$property)) {
                if (-not $link) {continue}
                $allowed=$false
                if (($target.role -ceq 'group-allowed' -and $property -ceq 'member') -or ($target.role -ceq 'manager' -and $property -ceq 'directReports')) {
                    $allowed=$link -ieq @($plan|Where-Object role -CEQ 'subject')[0].dn
                }
                if ($target.role -ceq 'subject' -and $property -ceq 'memberOf') {$allowed=$link -ieq @($plan|Where-Object role -CEQ 'group-allowed')[0].dn}
                if ($target.role -ceq 'subject' -and $property -ceq 'manager') {$allowed=$link -ieq @($plan|Where-Object role -CEQ 'manager')[0].dn}
                if (-not $allowed) {throw 'Mutation fixture acquired an unexpected account or management association.'}
            }
        }
    }
    if (-not $AllowMissing -and $seen.Count -ne $plan.Count) {throw 'Ready mutation fixture is incomplete.'}
}

function Get-MutationFixtureObjects($State,[string]$Server,[bool]$AllowMissing) {
    Assert-MutationFixtureState $State
    $plan=@(Get-MutationFixturePlan $State.run_id);$objects=@{};$domain='DC=ad,DC=sdk,DC=test';$configuration='CN=Configuration,'+$domain
    foreach ($partition in @($domain,$configuration)) {
        $filter='(|(name=sdk09-'+$State.run_id+')'
        foreach ($target in $State.targets) {
            if ($target.guid) {$hex=([guid]$target.guid).ToByteArray()|ForEach-Object {'\'+$_.ToString('x2')};$filter+='(objectGUID='+($hex -join '')+')'}
        }
        $filter+=')'
        $rows=@(Get-ADObject -Server $Server -SearchBase $partition -SearchScope Subtree -LDAPFilter $filter -Properties description,sAMAccountName,userAccountControl,member,memberOf,directReports,manager,managedBy -ErrorAction Stop -WarningAction Stop)
        foreach ($row in $rows) {$objects[$row.DistinguishedName]=$row}
    }
    foreach ($role in @('parent','site')) {
        $dn=@($plan|Where-Object role -CEQ $role)[0].dn
        if ($objects.ContainsKey($dn)) {
            $rows=@(Get-ADObject -Server $Server -SearchBase $dn -SearchScope Subtree -LDAPFilter '(objectClass=*)' -Properties description,sAMAccountName,userAccountControl,member,memberOf,directReports,manager,managedBy -ErrorAction Stop -WarningAction Stop)
            foreach ($row in $rows) {$objects[$row.DistinguishedName]=$row}
        }
    }
    $result=@($objects.Values)
    Assert-MutationFixtureObjects $State $result $AllowMissing
    return $result
}

function Get-MutationFixtureGrantPlan($Target) {
    [pscustomobject]@{attribute=$null;mask=0x10;denied=$false}
    switch -CaseSensitive ($Target.role) {
        'subject' {foreach ($name in @('manager','description')) {[pscustomobject]@{attribute=$name;mask=0x20;denied=$false}}}
        'hidden' {
            [pscustomobject]@{attribute='description';mask=0x10;denied=$true}
            [pscustomobject]@{attribute='description';mask=0x20;denied=$false}
        }
        'group-allowed' {[pscustomobject]@{attribute='member';mask=0x20;denied=$false}}
        'group-denied' {[pscustomobject]@{attribute='member';mask=0x20;denied=$true}}
        'site' {[pscustomobject]@{attribute='description';mask=0x20;denied=$false}}
        'settings' {[pscustomobject]@{attribute='options';mask=0x20;denied=$true}}
        'delete-unverified' {[pscustomobject]@{attribute=$null;mask=0x10000;denied=$false}}
    }
}

function New-MutationFixtureGrant($State,$Grant) {
    $sid=[Security.Principal.SecurityIdentifier]::new($State.actor_sid)
    $qualifier=[Security.AccessControl.AceQualifier]::AccessAllowed
    if ($Grant.denied) {$qualifier=[Security.AccessControl.AceQualifier]::AccessDenied}
    if (-not $Grant.attribute) {return [Security.AccessControl.CommonAce]::new([Security.AccessControl.AceFlags]::None,$qualifier,$Grant.mask,$sid,$false,$null)}
    $schema=@($State.attributes|Where-Object name -CEQ $Grant.attribute)
    if ($schema.Count -ne 1 -or ([guid]$schema[0].guid) -eq [guid]::Empty) {throw 'Exact mutation delegation attribute GUID unavailable.'}
    return [Security.AccessControl.ObjectAce]::new([Security.AccessControl.AceFlags]::None,$qualifier,$Grant.mask,$sid,
        [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent,[guid]$schema[0].guid,[guid]::Empty,$false,$null)
}

function Get-MutationFixtureAceBytes($Ace) {
    $raw=[byte[]]::new($Ace.BinaryLength);$Ace.GetBinaryForm($raw,0)
    return [Convert]::ToBase64String($raw)
}

function Get-MutationFixtureUnownedAces([byte[]]$Raw,[string]$SID) {
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Raw,0)
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.KnownAce] -or $ace.SecurityIdentifier.Value -cne $SID) {Get-MutationFixtureAceBytes $ace}
    }
}

function Assert-MutationFixtureGrant($State,$Target,[byte[]]$Raw) {
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Raw,0)
    if (-not $descriptor.DiscretionaryAcl -or $descriptor.DiscretionaryAcl.Revision -ne 4) {throw 'Mutation grant ACL revision differs.'}
    $actual=@($descriptor.DiscretionaryAcl|Where-Object {$_ -is [Security.AccessControl.KnownAce] -and $_.SecurityIdentifier.Value -ceq $State.actor_sid}|ForEach-Object {Get-MutationFixtureAceBytes $_}|Sort-Object)
    $expected=@(Get-MutationFixtureGrantPlan $Target|ForEach-Object {Get-MutationFixtureAceBytes (New-MutationFixtureGrant $State $_)}|Sort-Object)
    if ($actual.Count -ne $expected.Count -or ($actual -join ';') -cne ($expected -join ';')) {throw 'Mutation actor grants exceed the exact property/read/delete plan.'}
}

function Set-MutationFixtureGrant($State,$Target,[PSCredential]$Credential) {
    $connection=Open-DescriptorFixtureConnection $State.server $Credential
    try {
        $connection.SessionOptions.ReferralChasing=[DirectoryServices.Protocols.ReferralChasingOptions]::None
        $marker=@(Get-MutationFixturePlan $State.run_id|Where-Object role -CEQ $Target.role)[0].marker
        $raw=Read-DescriptorFixtureDACL $connection ([guid]$Target.guid) $marker
        $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($raw,0)
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if ($ace -is [Security.AccessControl.KnownAce] -and $ace.SecurityIdentifier.Value -ceq $State.actor_sid) {throw 'Actor already has an unexpected new-fixture grant.'}
        }
        $grants=@(Get-MutationFixtureGrantPlan $Target|ForEach-Object {New-MutationFixtureGrant $State $_})
        $acl=[Security.AccessControl.RawAcl]::new(4,$descriptor.DiscretionaryAcl.Count+$grants.Count)
        foreach ($ace in $grants|Where-Object AceQualifier -EQ ([Security.AccessControl.AceQualifier]::AccessDenied)) {$acl.InsertAce($acl.Count,$ace)}
        $inserted=$false
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if (-not $inserted -and (([int]$ace.AceFlags -band 0x10) -ne 0)) {
                foreach ($grant in $grants|Where-Object AceQualifier -EQ ([Security.AccessControl.AceQualifier]::AccessAllowed)) {$acl.InsertAce($acl.Count,$grant)}
                $inserted=$true
            }
            $acl.InsertAce($acl.Count,$ace)
        }
        if (-not $inserted) {foreach ($grant in $grants|Where-Object AceQualifier -EQ ([Security.AccessControl.AceQualifier]::AccessAllowed)) {$acl.InsertAce($acl.Count,$grant)}}
        $descriptor.DiscretionaryAcl=$acl;$next=[byte[]]::new($descriptor.BinaryLength);$descriptor.GetBinaryForm($next,0)
        Assert-MutationFixtureGrant $State $Target $next
        $unowned=@(Get-MutationFixtureUnownedAces $raw $State.actor_sid)
        if (($unowned -join ';') -cne (@(Get-MutationFixtureUnownedAces $next $State.actor_sid) -join ';')) {throw 'Fixture proposal changed unrelated ACEs.'}
        $Target.before_dacl_base64=[Convert]::ToBase64String($raw);$Target.proposed_dacl_base64=[Convert]::ToBase64String($next)
        Save-MutationFixtureState $State ($Target.role+'-grant-intent')
        if ([Convert]::ToBase64String((Read-DescriptorFixtureDACL $connection ([guid]$Target.guid) $marker)) -cne $Target.before_dacl_base64) {throw 'Exclusive new fixture DACL changed before provisioning.'}
        $request=[DirectoryServices.Protocols.ModifyRequest]::new((Get-DescriptorFixtureGUIDTarget ([guid]$Target.guid)))
        $mod=[DirectoryServices.Protocols.DirectoryAttributeModification]::new();$mod.Name='nTSecurityDescriptor';$mod.Operation=[DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        $null=$mod.Add($next);$null=$request.Modifications.Add($mod)
        $control=[DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new([DirectoryServices.Protocols.SecurityMasks]::Dacl);$control.IsCritical=$true;$null=$request.Controls.Add($control)
        $response=$connection.SendRequest($request)
        if ([int]$response.ResultCode -ne 0) {throw 'Mutation fixture delegation refused.'}
        $actual=Read-DescriptorFixtureDACL $connection ([guid]$Target.guid) $marker
        $Target.ready_dacl_base64=[Convert]::ToBase64String($actual)
        Save-MutationFixtureState $State ($Target.role+'-grant-observed')
        Assert-MutationFixtureGrant $State $Target $actual
        if (($unowned -join ';') -cne (@(Get-MutationFixtureUnownedAces $actual $State.actor_sid) -join ';')) {throw 'Fixture readback changed unrelated ACEs.'}
        Save-MutationFixtureState $State ($Target.role+'-grant-verified')
    } finally {$connection.Dispose()}
}

function Get-MutationFixtureObjectParameters($Target,[string]$Server) {
    $parameters=@{Server=$Server;Name=$Target.name;Type=$Target.class;Path=$Target.parent;Description=$Target.marker;PassThru=$true;ErrorAction='Stop'}
    # New-ADObject rejects an explicitly supplied empty OtherAttributes table.
    # Administrative objects with no extra attributes must omit the parameter.
    if ($Target.role -ceq 'settings') {$parameters.OtherAttributes=@{options=0}}
    return $parameters
}

function New-MutationContractFixture([string]$RunId,[string]$Server,[string]$ActorSID,[PSCredential]$Credential) {
    $root=Assert-MutationFixtureContext $RunId $Server
    if (-not $Credential -or $ActorSID -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z') {throw 'Explicit provisioning credential and dedicated actor SID required.'}
    $actor=Get-ADUser -Server $Server -Identity $ActorSID -Properties Enabled,'msDS-SupportedEncryptionTypes' -ErrorAction Stop
    if (-not $actor.Enabled -or $actor.SID.Value -cne $ActorSID -or $actor.'msDS-SupportedEncryptionTypes' -ne 24) {throw 'Dedicated AES actor differs.'}
    $attributes=@()
    foreach ($name in @('manager','description','member','options')) {
        $rows=@(Get-ADObject -Server $Server -SearchBase $root.schemaNamingContext -SearchScope OneLevel -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$name))" -Properties lDAPDisplayName,schemaIDGUID,isDefunct -ErrorAction Stop -WarningAction Stop)
        if ($rows.Count -ne 1 -or $rows[0].lDAPDisplayName -cne $name -or $rows[0].schemaIDGUID.Length -ne 16 -or $rows[0].isDefunct) {throw 'Mutation attribute schema identity unavailable.'}
        $attributes+=[pscustomobject]@{name=$name;guid=([guid]::new([byte[]]$rows[0].schemaIDGUID)).ToString()}
    }
    $state=[pscustomobject]@{schema_version=1;purpose='sdk-mutation-contract-fixture';run_id=$RunId;server=$Server;actor_sid=$ActorSID;actor_guid=$actor.ObjectGUID.ToString();
        phase='planned';journal_index=0;updated_utc=$null;attributes=$attributes;targets=@();reference_checks=@();actor_cleanup_owned_by_outer_fixture=$true;
        global_acl_or_policy_changes=$false;kds_or_password_retrieval=$false;credential_payloads_persisted=$false}
    $plan=@(Get-MutationFixturePlan $RunId)
    foreach ($target in $plan) {$state.targets+=[pscustomobject]@{role=$target.role;dn=$target.dn;class=$target.class;sam=$target.sam;guid=$null;before_dacl_base64=$null;proposed_dacl_base64=$null;ready_dacl_base64=$null}}
    if (@(Get-MutationFixtureObjects $state $Server $true).Count) {throw 'Mutation fixture namespace is not fresh.'}
    Initialize-MutationFixtureJournal $RunId $Server;Save-MutationFixtureState $state 'planned'
    foreach ($target in $plan) {
        $record=@($state.targets|Where-Object role -CEQ $target.role)[0]
        Save-MutationFixtureState $state ($target.role+'-create-intent')
        switch -CaseSensitive ($target.class) {
            'organizationalUnit' {$object=New-ADOrganizationalUnit -Server $Server -Name $target.name -Path $target.parent -Description $target.marker -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Stop}
            'user' {$object=New-ADUser -Server $Server -Name $target.name -SamAccountName $target.sam -Path $target.parent -Description $target.marker -Enabled $false -PassThru -ErrorAction Stop}
            'group' {$object=New-ADGroup -Server $Server -Name $target.name -SamAccountName $target.sam -Path $target.parent -Description $target.marker -GroupScope Global -GroupCategory Security -PassThru -ErrorAction Stop}
            default {
                $objectParameters=Get-MutationFixtureObjectParameters $target $Server
                $object=New-ADObject @objectParameters
            }
        }
        $record.guid=$object.ObjectGUID.ToString();Save-MutationFixtureState $state ($target.role+'-created')
        Set-MutationFixtureGrant $state $record $Credential
    }
    $null=Get-MutationFixtureObjects $state $Server $false
    Save-MutationFixtureState $state 'ready'
    return $state
}

function Test-MutationFixtureSiteReferences($State,[string]$Server) {
    $site=@($State.targets|Where-Object role -CEQ 'site')[0]
    $rows=@(Get-ADObject -Server $Server -SearchBase 'CN=Configuration,DC=ad,DC=sdk,DC=test' -SearchScope Subtree -LDAPFilter "(|(siteObject=$($site.dn))(siteList=$($site.dn))(msDS-Preferred-GC-Site=$($site.dn)))" -ErrorAction Stop -WarningAction Stop)
    if ($rows.Count) {throw 'Owned mutation site acquired a foreign subnet, site-link or caching reference; cleanup refused.'}
    return [pscustomobject]@{server=$Server;configuration_search_complete=$true;site_guid=$site.guid;foreign_site_references=0;checked_utc=[DateTime]::UtcNow.ToString('o')}
}

function Remove-MutationContractFixture([string]$RunId,[string]$Server) {
    $null=Assert-MutationFixtureContext $RunId $Server
    $path=Assert-MutationFixturePath (Join-Path (Join-Path 'C:\adsdk-mutation-fixtures' $RunId) 'state.json')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {throw 'Mutation cleanup requires its exact journal.'}
    $state=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    if ($state.server -cne $Server -or $state.run_id -cne $RunId) {throw 'Mutation cleanup endpoint differs.'}
    $objects=@(Get-MutationFixtureObjects $state $Server $true)
    $state.reference_checks+=Test-MutationFixtureSiteReferences $state $Server
    foreach ($object in $objects) {
        $target=@($state.targets|Where-Object dn -CEQ $object.DistinguishedName)[0]
        if (-not $target.guid) {$target.guid=$object.ObjectGUID.ToString()}
    }
    Save-MutationFixtureState $state 'cleanup-planned'
    $order=@('licensing','servers','settings','site','delete-verified','delete-unverified','group-denied','group-allowed','hidden','manager','subject','parent')
    foreach ($role in $order) {
        $objects=@(Get-MutationFixtureObjects $state $Server $true)
        $state.reference_checks+=Test-MutationFixtureSiteReferences $state $Server
        $target=@($state.targets|Where-Object role -CEQ $role)[0]
        if (@($objects|Where-Object DistinguishedName -CEQ $target.dn).Count -eq 0) {continue}
        Save-MutationFixtureState $state ($role+'-delete-intent')
        Remove-ADObject -Server $Server -Identity ([guid]$target.guid) -Confirm:$false -ErrorAction Stop
        Save-MutationFixtureState $state ($role+'-deleted')
    }
    $observations=@();$verified=$false
    for ($attempt=0;$attempt -lt 15;$attempt++) {
        $observations=@(foreach ($dc in @($Server,$Server.Replace('dc1.','dc2.'))) {
            $remaining=@(Get-MutationFixtureObjects $state $dc $true)
            $state.reference_checks+=Test-MutationFixtureSiteReferences $state $dc
            [pscustomobject]@{server=$dc;domain_and_configuration_searches_complete=$true;live_owned_objects_remaining=$remaining.Count;checked_utc=[DateTime]::UtcNow.ToString('o')}
        })
        if (@($observations|Where-Object live_owned_objects_remaining -NE 0).Count -eq 0) {$verified=$true;break}
        Start-Sleep -Seconds 2
    }
    Save-MutationFixtureState $state 'cleanup-observed'
    return [pscustomobject]@{run_id=$RunId;verified=$verified;observations=$observations;state=$state;actor_cleanup_owned_by_outer_fixture=$true;tombstones_retained=$true;global_deleted_container_acl_changes=$false}
}
