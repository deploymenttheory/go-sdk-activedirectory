#Requires -Version 5.1
# Dot-sourceable helpers. Loading this file does not connect to or change AD.
Set-StrictMode -Version Latest

function Get-DmsaAttributeNames {
    return @('ntsecuritydescriptor','msds-groupmsamembership','useraccountcontrol',
        'msds-user-account-control-computed','accountexpires','pwdlastset',
        'msds-supportedencryptiontypes','serviceprincipalname','msds-allowedtodelegateto',
        'msds-allowedtoactonbehalfofotheridentity','msds-assignedauthnpolicy',
        'msds-assignedauthnpolicysilo','msds-authnpolicysilomembersbl','memberof',
        'msds-delegatedmsastate','msds-supersededserviceaccountstate',
        'msds-managedaccountprecededbylink','msds-managedaccountprecededbylinkbl',
        'msds-supersededmanagedaccountlink','msds-supersededmanagedaccountlinkbl')
}

function Get-DmsaError($Record) {
    $items=@(); $pending=[Collections.Generic.Queue[Exception]]::new()
    $pending.Enqueue($Record.Exception)
    while($pending.Count) {
        $exception=$pending.Dequeue();$code=$null
        if($exception.PSObject.Properties['ErrorCode']) {$code=[long]$exception.ErrorCode}
        $items += [ordered]@{type=$exception.GetType().FullName;hresult=[long]$exception.HResult;code=$code}
        if($exception -is [AggregateException]) {foreach($inner in $exception.InnerExceptions){$pending.Enqueue($inner)}}
        elseif($exception.InnerException){$pending.Enqueue($exception.InnerException)}
    }
    return $items
}

function Get-DmsaFieldKind([string]$Name) {
    if($Name -in @('ntsecuritydescriptor','msds-groupmsamembership','msds-allowedtoactonbehalfofotheridentity')) {return 'security_descriptor'}
    if($Name -in @('useraccountcontrol','msds-user-account-control-computed','accountexpires','pwdlastset','msds-supportedencryptiontypes','msds-delegatedmsastate','msds-supersededserviceaccountstate')) {return 'integer'}
    if($Name -match 'link(bl)?$|memberof|assignedauthnpolicy|silomembersbl') {return 'dn'}
    return 'string'
}

function Convert-DmsaField([string]$Name,$Attribute) {
    $kind=Get-DmsaFieldKind $Name
    if($null -eq $Attribute -or $Attribute.Count -eq 0) {return [ordered]@{status='absent';kind=$kind;values=@()}}
    $values=@()
    if($kind -eq 'security_descriptor') {
        foreach($item in $Attribute.GetValues([byte[]])) {$values += [Convert]::ToBase64String([byte[]]$item)}
    } else { $values=@($Attribute.GetValues([string])) }
    [string[]]$sorted=@($values)
    [Array]::Sort($sorted,[StringComparer]::Ordinal)
    return [ordered]@{status='present';kind=$kind;values=@($sorted)}
}

function New-DmsaLdapConnection([string]$Server) {
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $connection=[DirectoryServices.Protocols.LdapConnection]::new($Server)
    $connection.AuthType=[DirectoryServices.Protocols.AuthType]::Negotiate
    $connection.SessionOptions.ProtocolVersion=3
    $connection.SessionOptions.Signing=$true
    $connection.SessionOptions.Sealing=$true
    $connection.Timeout=[TimeSpan]::FromSeconds(20)
    try {$connection.Bind();return $connection} catch {$connection.Dispose();throw}
}

function Get-DmsaCapture($Connection,[string]$Server,[string]$RunId,[string]$CaseId,[string]$Point,[object[]]$Targets) {
    $capture=[ordered]@{schema_version=1;run_id=$RunId;case_id=$CaseId;point=$Point;server=$Server;started_at=[DateTime]::UtcNow.ToString('o');finished_at=$null;objects=@();errors=@()}
    foreach($target in $Targets) {
        $object=[ordered]@{role=$target.role;guid=$target.guid;sid=$target.sid;dn=$target.dn;class=$target.class;marker=$target.marker;status='read_error';sd_sections=0;fields=[ordered]@{};metadata=@()}
        foreach($name in Get-DmsaAttributeNames) {$object.fields[$name]=[ordered]@{status='read_error';kind=(Get-DmsaFieldKind $name);values=@()}}
        try {
            $attributes=@('objectGUID','objectSid','objectClass','description')+@(Get-DmsaAttributeNames | Where-Object {$_ -ne 'ntsecuritydescriptor'})
            $request=[DirectoryServices.Protocols.SearchRequest]::new($target.dn,'(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,[string[]]$attributes)
            try {$response=$Connection.SendRequest($request)} catch [DirectoryServices.Protocols.DirectoryOperationException] {
                if($_.Exception.Response.ResultCode -eq [DirectoryServices.Protocols.ResultCode]::NoSuchObject -and $Point -eq 'cleanup') {
                    $object.status='absent';$object.fields=[ordered]@{};$capture.objects+=@($object);continue
                }
                throw
            }
            if($response.Entries.Count -ne 1) {throw 'Expected one owned object.'}
            $entry=$response.Entries[0]
            $actualGuid=[guid]::new([byte[]]$entry.Attributes['objectGUID'][0])
            if($actualGuid.ToString() -ne $target.guid -or [string]$entry.Attributes['description'][0] -cne $target.marker -or
                @($entry.Attributes['objectClass'].GetValues([string])) -notcontains $target.class) {throw 'Capture ownership mismatch.'}
            if($target.sid) {
                $actualSid=[Security.Principal.SecurityIdentifier]::new([byte[]]$entry.Attributes['objectSid'][0],0).Value
                if($actualSid -ne $target.sid) {throw 'Capture SID mismatch.'}
            }
            $object.status='present'
            foreach($name in Get-DmsaAttributeNames | Where-Object {$_ -ne 'ntsecuritydescriptor'}) {$object.fields[$name]=Convert-DmsaField $name $entry.Attributes[$name]}
            try {
                $sdRequest=[DirectoryServices.Protocols.SearchRequest]::new($target.dn,'(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,[string[]]@('objectGUID','description','nTSecurityDescriptor'))
                $null=$sdRequest.Controls.Add([DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new([DirectoryServices.Protocols.SecurityMasks]15))
                $sdResponse=$Connection.SendRequest($sdRequest)
                if($sdResponse.Entries.Count -ne 1 -or [guid]::new([byte[]]$sdResponse.Entries[0].Attributes['objectGUID'][0]) -ne $actualGuid -or
                    [string]$sdResponse.Entries[0].Attributes['description'][0] -cne $target.marker) {throw 'Descriptor ownership mismatch.'}
                $object.fields['ntsecuritydescriptor']=Convert-DmsaField 'ntsecuritydescriptor' $sdResponse.Entries[0].Attributes['nTSecurityDescriptor']
                if($object.fields['ntsecuritydescriptor'].status -eq 'present') {$object.sd_sections=15}
            } catch {$capture.errors+=@(Get-DmsaError $_)}
            try {
                $object.metadata=@(Get-ADReplicationAttributeMetadata -Object $actualGuid -Server $Server -ShowAllLinkedValues -ErrorAction Stop | ForEach-Object {
                    $valueKey=''
                    if($_.AttributeValue) {
                        # Only linked-value metadata is keyed; never retrieve secret attribute values.
                        $hash=[Security.Cryptography.SHA256]::Create()
                        try {$valueKey=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$_.AttributeValue)))).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
                    }
                    [ordered]@{name=$_.AttributeName.ToLowerInvariant();value_key=$valueKey;version=[long]$_.Version;originating_usn=[string]$_.LastOriginatingChangeUsn}
                })
            } catch {$capture.errors+=@(Get-DmsaError $_)}
        } catch {$capture.errors+=@(Get-DmsaError $_)}
        $capture.objects+=@($object)
    }
    $capture.finished_at=[DateTime]::UtcNow.ToString('o')
    return $capture
}

function Write-DmsaArtifact([string]$Directory,[string]$Name,$Value) {
    if($Name -notmatch '^[a-z0-9][a-z0-9.-]*\.json$') {throw 'Invalid artifact name.'}
    $path=Join-Path $Directory $Name
    if(Test-Path -LiteralPath $path) {throw 'Artifact already exists; refusing overwrite.'}
    [IO.File]::WriteAllText($path,($Value|ConvertTo-Json -Depth 32),[Text.UTF8Encoding]::new($false))
    return [ordered]@{path=$Name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}

function Remove-DmsaOwnedFixtures([object[]]$Ledger,[string]$Marker,[string]$Server) {
    $errors=[Collections.Generic.List[Exception]]::new()
    foreach($item in $Ledger) {
        try {
            $identity=$item.dn
            if($item.guid) {$identity=[guid]$item.guid}
            try {$found=Get-ADObject -Identity $identity -Server $Server -Properties Description -ErrorAction Stop}
            catch {if($_.Exception.GetType().FullName -eq 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException') {continue};throw}
            if($found.Description -cne $Marker -or $found.DistinguishedName -cne $item.dn -or $found.ObjectClass -cne $item.class -or
                ($item.guid -and $found.ObjectGUID.ToString() -ne $item.guid)) {throw 'Cleanup ownership mismatch.'}
            # The caller puts children before the OU. Never remove recursively.
            Remove-ADObject -Identity $found.ObjectGUID -Server $Server -Confirm:$false -ErrorAction Stop
        } catch {$errors.Add($_.Exception)}
    }
    if($errors.Count) {throw [AggregateException]::new('DMSA fixture cleanup failed.',$errors.ToArray())}
}
