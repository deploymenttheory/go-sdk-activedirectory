#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Specification,[Parameter(Mandatory)][PSCredential]$Reader)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.DirectoryServices.Protocols
$spec=$Specification | ConvertFrom-Json
$id=[guid]::ParseExact($spec.id,'D').ToString('D')
$directory="C:\ad-sdk-lds\$id"
$dn="CN=SDKReader,$($spec.partition)"
if($spec.member -ine $env:COMPUTERNAME -or $spec.server -ine "$env:COMPUTERNAME.ad.sdk.test" -or $spec.partition -cne 'CN=SdkLds,DC=lab,DC=test' -or $spec.marker -cne "ad-sdk-lds:$id" -or $Reader.UserName -cne $dn){throw 'Unexpected LDS reader fixture.'}
foreach($path in @('C:\ad-sdk-lds',$directory)) {if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point in reader fixture directory.'}}
$owned=Get-Content (Join-Path $directory 'ownership.json') -Raw | ConvertFrom-Json
if($owned.id -ne $id -or $owned.lab_id -ne $spec.lab_id -or $owned.marker -cne $spec.marker){throw 'Reader fixture ownership differs.'}
$statePath=Join-Path $directory 'reader.json'
if(Test-Path -LiteralPath $statePath) {
    if((Get-Item -LiteralPath $statePath).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reader state is a reparse point.'}
    $state=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if($state.id -ne $id -or $state.lab_id -ne $spec.lab_id -or $state.dn -cne $dn){throw 'Reader state ownership differs.'}
} else {$state=[pscustomobject][ordered]@{id=$id;lab_id=$spec.lab_id;dn=$dn;object_guid='';phase='reserved'}}
function Save-ReaderState {
    $temporary=Join-Path $directory 'reader.tmp'
    if((Test-Path -LiteralPath $temporary) -and ((Get-Item -LiteralPath $temporary).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reader temporary state is a reparse point.'}
    $state | ConvertTo-Json | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $statePath -Force
}
Save-ReaderState
function Open-LDS([int]$Port,[PSCredential]$Account=$null) {
    $identifier=[DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($spec.server,$Port,$true,$false)
    $connection=[DirectoryServices.Protocols.LdapConnection]::new($identifier)
    try {
        $connection.Timeout=[TimeSpan]::FromSeconds(10)
        $connection.SessionOptions.ProtocolVersion=3
        $connection.SessionOptions.SecureSocketLayer=$true
        $connection.SessionOptions.ReferralChasing=[DirectoryServices.Protocols.ReferralChasingOptions]::None
        $connection.SessionOptions.Signing=$false;$connection.SessionOptions.Sealing=$false
        if($Account){$connection.AuthType=[DirectoryServices.Protocols.AuthType]::Basic;$connection.Credential=$Account.GetNetworkCredential()}else{$connection.AuthType=[DirectoryServices.Protocols.AuthType]::Negotiate}
        $connection.Bind()
        return $connection
    } catch {$connection.Dispose();throw}
}
function Read-LDS($Connection,[string]$DN,[string[]]$Attributes) {
    $request=[DirectoryServices.Protocols.SearchRequest]::new($DN,'(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,$Attributes)
    $response=[DirectoryServices.Protocols.SearchResponse]$Connection.SendRequest($request)
    if($response.Entries.Count -ne 1){throw 'Expected one LDS base entry.'}
    return $response.Entries[0]
}
function Values($Entry,[string]$Name) {
    if($Entry.Attributes.Contains($Name)){return @($Entry.Attributes[$Name].GetValues([string]))}
    return @()
}
function Change-LDS($Connection,[string]$DN,[string]$Attribute,[DirectoryServices.Protocols.DirectoryAttributeOperation]$Operation,$Value) {
    $modification=[DirectoryServices.Protocols.DirectoryAttributeModification]::new()
    $modification.Name=$Attribute;$modification.Operation=$Operation
    if($null -ne $Value){$null=$modification.Add($Value)}
    $request=[DirectoryServices.Protocols.ModifyRequest]::new($DN,$modification)
    $null=$Connection.SendRequest($request)
}
function Get-ReaderGUID($Entry) {
    if(@(Values $Entry 'description').Count -ne 1 -or (Values $Entry 'description') -cne $spec.marker -or 'user' -notin @(Values $Entry 'objectClass')){throw 'Existing LDS reader ownership/class differs.'}
    $guid=[guid]::new([byte[]]$Entry.Attributes['objectGUID'][0]).ToString('D')
    if($state.object_guid -and $state.object_guid -ne $guid){throw 'Recorded LDS reader identity changed.'}
    return $guid
}
$primary=$null;$replica=$null
try {
    $primary=Open-LDS $spec.ssl_port
    $replica=Open-LDS $spec.replica_ssl_port
    $rootA=Read-LDS $primary '' @('supportedCapabilities','dsServiceName','namingContexts','configurationNamingContext')
    $rootB=Read-LDS $replica '' @('supportedCapabilities','dsServiceName','namingContexts','configurationNamingContext')
    if('1.2.840.113556.1.4.1851' -notin @(Values $rootA 'supportedCapabilities') -or '1.2.840.113556.1.4.1851' -notin @(Values $rootB 'supportedCapabilities') -or $spec.partition -notin @(Values $rootA 'namingContexts') -or $spec.partition -notin @(Values $rootB 'namingContexts')){throw 'Expected LDS endpoints/partition are absent.'}
    $dsaA=@(Values $rootA 'dsServiceName');$dsaB=@(Values $rootB 'dsServiceName')
    if($dsaA.Count -ne 1 -or $dsaB.Count -ne 1 -or $dsaA[0] -ceq $dsaB[0] -or (Values $rootA 'configurationNamingContext') -cne (Values $rootB 'configurationNamingContext')){throw 'Expected distinct LDS replicas.'}
    $entryA=Read-LDS $primary $dsaA[0] @('msDS-DefaultNamingContext')
    if((Values $entryA 'msDS-DefaultNamingContext') -cne $spec.partition){Change-LDS $primary $dsaA[0] 'msDS-DefaultNamingContext' Replace $spec.partition}
    $entryB=Read-LDS $replica $dsaB[0] @('msDS-DefaultNamingContext')
    if(@(Values $entryB 'msDS-DefaultNamingContext').Count){Change-LDS $replica $dsaB[0] 'msDS-DefaultNamingContext' Delete $null}
    $entry=$null
    try {$entry=Read-LDS $primary $dn @('objectGUID','objectClass','description','msDS-UserAccountDisabled')} catch [DirectoryServices.Protocols.DirectoryOperationException] {
        if(-not $_.Exception.Response -or [int]$_.Exception.Response.ResultCode -ne 32){throw}
    }
    if(-not $entry) {
        if($state.object_guid -or $state.phase -ne 'reserved'){throw 'Recorded LDS reader disappeared.'}
        $attributes=[DirectoryServices.Protocols.DirectoryAttribute[]]@(
            [DirectoryServices.Protocols.DirectoryAttribute]::new('objectClass',[string[]]@('user')),
            [DirectoryServices.Protocols.DirectoryAttribute]::new('cn',[string[]]@('SDKReader')),
            [DirectoryServices.Protocols.DirectoryAttribute]::new('description',[string[]]@($spec.marker))
        )
        $null=$primary.SendRequest([DirectoryServices.Protocols.AddRequest]::new($dn,$attributes))
        $entry=Read-LDS $primary $dn @('objectGUID','objectClass','description','msDS-UserAccountDisabled')
    }
    $state.object_guid=Get-ReaderGUID $entry
    Save-ReaderState
    if($state.phase -eq 'password-setting'){throw 'Previous reader password assignment has an uncertain outcome; inspect the owned fixture before retrying.'}
    if($state.phase -eq 'reserved') {
        $state.phase='password-setting';Save-ReaderState
        $passwordBytes=$null
        try {
            $passwordBytes=[Text.Encoding]::Unicode.GetBytes('"'+$Reader.GetNetworkCredential().Password+'"')
            Change-LDS $primary $dn 'unicodePwd' Replace $passwordBytes
        } finally {if($passwordBytes){[Array]::Clear($passwordBytes,0,$passwordBytes.Length)}}
        $state.phase='password-set';Save-ReaderState
    }
    Change-LDS $primary $dn 'msDS-UserAccountDisabled' Replace 'FALSE'
    $role="CN=Readers,CN=Roles,$($spec.partition)"
    $roleEntry=Read-LDS $primary $role @('objectClass','member')
    if('group' -notin @(Values $roleEntry 'objectClass')){throw 'Application Readers role is not a group.'}
    if($dn -notin @(Values $roleEntry 'member')){Change-LDS $primary $role 'member' Add $dn}
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do {
        $ready=$false
        try {
            $replicaReader=Read-LDS $replica $dn @('objectGUID','objectClass','description','msDS-UserAccountDisabled')
            if((Get-ReaderGUID $replicaReader) -ne $state.object_guid){throw 'Replica reader GUID differs.'}
            $ready=(Values $replicaReader 'msDS-UserAccountDisabled') -ieq 'FALSE'
        } catch [DirectoryServices.Protocols.DirectoryOperationException] {if(-not $_.Exception.Response -or [int]$_.Exception.Response.ResultCode -ne 32){throw}}
        if(-not $ready){Start-Sleep -Seconds 2}
    } while(-not $ready -and [DateTime]::UtcNow -lt $deadline)
    if(-not $ready){throw 'LDS reader did not replicate within the fixture deadline.'}
    $readbacks=@()
    foreach($port in @($spec.ssl_port,$spec.replica_ssl_port)) {
        $readerConnection=Open-LDS $port $Reader
        try {
            $partition=Read-LDS $readerConnection $spec.partition @('distinguishedName','instanceType')
            $self=Read-LDS $readerConnection $dn @('description')
            $root=Read-LDS $readerConnection '' @('defaultNamingContext','supportedCapabilities')
            $default=@(Values $root 'defaultNamingContext')
            if(($port -eq $spec.ssl_port -and ($default.Count -ne 1 -or $default[0] -cne $spec.partition)) -or ($port -eq $spec.replica_ssl_port -and $default.Count -ne 0)){throw 'Per-instance default naming context differs.'}
            if((Values $self 'description') -cne $spec.marker -or ([int](Values $partition 'instanceType') -band 1) -eq 0){throw 'LDS reader cannot read its fixture or naming context.'}
            $readbacks += [ordered]@{port=$port;simple_bind=$true;partition_read=$true;self_read=$true;default_naming_context=$default}
        } finally {$readerConnection.Dispose()}
    }
    $state.phase='reader-ready';Save-ReaderState
    [ordered]@{phase=$state.phase;id=$id;dn=$dn;object_guid=$state.object_guid;readbacks=$readbacks;time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 6
} finally {if($primary){$primary.Dispose()};if($replica){$replica.Dispose()}}
