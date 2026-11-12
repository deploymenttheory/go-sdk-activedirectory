#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Specification)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$spec=$Specification | ConvertFrom-Json
$fixtureID=[guid]::ParseExact($spec.id,'D').ToString('D')
if($spec.member -ne $env:COMPUTERNAME -or $spec.marker -cne "ad-sdk-lds:$fixtureID" -or $spec.partition -cne 'CN=SdkLds,DC=lab,DC=test'){throw 'Unexpected LDS fixture specification.'}
if($spec.server -ine "$env:COMPUTERNAME.ad.sdk.test" -or $spec.administrator -ine 'ADSDK\Administrator'){throw 'Unexpected LDS server or administrator.'}
$currentIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $expectedIdentity=[Security.Principal.NTAccount]::new($spec.administrator).Translate([Security.Principal.SecurityIdentifier])
    if($currentIdentity.User -ne $expectedIdentity){throw 'LDS setup must run as the specified lab administrator.'}
} finally {$currentIdentity.Dispose()}
$suffix=$fixtureID.Replace('-','').Substring(0,8).ToUpperInvariant()
if($spec.primary -cne "ADSDKLDS-${suffix}-A" -or $spec.replica -cne "ADSDKLDS-${suffix}-B"){throw 'Unexpected LDS instance name.'}
if($spec.ldap_port -ne 51300 -or $spec.ssl_port -ne 51301 -or $spec.replica_ldap_port -ne 51400 -or $spec.replica_ssl_port -ne 51401){throw 'Unexpected LDS ports.'}
$root="C:\ad-sdk-lds\$fixtureID"
$markerPath=Join-Path $root 'ownership.json'
foreach($path in @('C:\ad-sdk-lds',$root)) {
    if((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'LDS fixture root must not be a reparse point.'}
}
if(Test-Path -LiteralPath $root) {
    if(-not (Test-Path -LiteralPath $markerPath)){throw 'Existing LDS directory has no ownership record.'}
    $owned=Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if($owned.id -ne $fixtureID -or $owned.lab_id -ne $spec.lab_id -or $owned.marker -cne $spec.marker){throw 'LDS directory ownership mismatch.'}
} else {
    $null=New-Item -ItemType Directory -Path $root
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-20'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
    Set-Acl -LiteralPath $root -AclObject $acl
    [ordered]@{id=$fixtureID;lab_id=$spec.lab_id;marker=$spec.marker} | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding UTF8
}
Add-Type -AssemblyName System.DirectoryServices.Protocols

function Get-OwnedLDSService([string]$Name,[int]$LDAPPort,[int]$SSLPort,[string]$DataPath) {
    $service=Get-CimInstance Win32_Service -Filter "Name='ADAM_$Name'"
    if(-not $service){return $null}
    if($service.Description -cne $spec.marker){throw 'Existing LDS service ownership marker differs.'}
    $parameters=Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\ADAM_$Name\Parameters"
    if($parameters.'Port LDAP' -ne $LDAPPort -or $parameters.'Port SSL' -ne $SSLPort){throw 'Owned LDS service ports differ.'}
    $data=[IO.Path]::GetFullPath($parameters.'DSA Database file')
    if(-not $data.StartsWith([IO.Path]::GetFullPath($DataPath).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Owned LDS data file is outside its fixture directory.'}
    $account=[Security.Principal.NTAccount]::new($service.StartName)
    if($account.Translate([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-20'){throw 'Owned LDS service has an unexpected service identity.'}
    return $service
}

function Install-OwnedLDS([string]$Name,[int]$LDAPPort,[int]$SSLPort,[bool]$Replica) {
    $instanceRoot=Join-Path $root $Name
    $data=Join-Path $instanceRoot 'data';$logs=Join-Path $instanceRoot 'logs'
    $service=Get-OwnedLDSService $Name $LDAPPort $SSLPort $data
    if(-not $service) {
        $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        if(@($listeners | Where-Object {$_.LocalPort -in @($LDAPPort,$SSLPort)}).Count){throw 'Requested LDS port is already in use.'}
        if(Test-Path -LiteralPath $instanceRoot){throw 'Incomplete LDS install directory requires inspection before retry.'}
        $null=New-Item -ItemType Directory -Path $instanceRoot
        $answer=@('[ADAMInstall]','ShowOrHideProgressGUI=Hide',"InstanceName=$Name","InstanceDescription=$($spec.marker)","LocalLDAPPortToListenOn=$LDAPPort","LocalSSLPortToListenOn=$SSLPort","DataFilesPath=$data","LogFilesPath=$logs")
        if($Replica) {
            $answer+=@('InstallType=Replica',"SourceServer=$($spec.server)","SourceLDAPPort=$($spec.ldap_port)","ApplicationPartitionsToReplicate=$($spec.partition)")
        } else {
            $answer+=@('InstallType=Unique',"NewApplicationPartitionToCreate=$($spec.partition)",'ImportLDIFFiles=MS-User.LDF','ConfigurationSetLevel=10')
        }
        # No account passwords are required: setup runs as the logged-on lab
        # administrator and uses the documented NetworkService default. Omit
        # Administrator too: the explicit field marks current-user admin false
        # in this installer, making LDIF import demand source credentials.
        $answerPath=Join-Path $instanceRoot 'install.ini'
        $answer | Set-Content -LiteralPath $answerPath -Encoding Unicode
        $start=[Diagnostics.ProcessStartInfo]::new()
        $start.FileName='C:\Windows\ADAM\adaminstall.exe';$start.Arguments='/answer:"'+$answerPath+'"'
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true
        $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $process=[Diagnostics.Process]::new();$process.StartInfo=$start
        try {
            if(-not $process.Start()){throw 'LDS installer did not start.'}
            $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
            if(-not $process.WaitForExit(600000)){throw 'LDS installer is still running; inspect before retry. It was not terminated.'}
            ($stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()) | Set-Content (Join-Path $instanceRoot 'install.log') -Encoding UTF8
            if($process.ExitCode -ne 0){throw "LDS installer returned $($process.ExitCode); inspect the owned instance install log."}
        } finally {$process.Dispose()}
        $service=Get-OwnedLDSService $Name $LDAPPort $SSLPort $data
        if(-not $service){throw 'LDS installer completed without the owned service.'}
    }
    if($service.State -eq 'Stopped'){Start-Service -Name $service.Name}
}

function Read-LDSRoot([int]$Port) {
    $identifier=[DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($spec.server,$Port,$true,$false)
    $connection=[DirectoryServices.Protocols.LdapConnection]::new($identifier)
    try {
        $connection.AuthType=[DirectoryServices.Protocols.AuthType]::Negotiate
        $connection.SessionOptions.ProtocolVersion=3
        $connection.SessionOptions.Signing=$true;$connection.SessionOptions.Sealing=$true
        $connection.SessionOptions.ReferralChasing=[DirectoryServices.Protocols.ReferralChasingOptions]::None
        $connection.Timeout=[TimeSpan]::FromSeconds(10)
        $connection.Bind()
        $attributes=[string[]]@('configurationNamingContext','schemaNamingContext','defaultNamingContext','dsServiceName','supportedCapabilities','namingContexts')
        $request=[DirectoryServices.Protocols.SearchRequest]::new('','(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,$attributes)
        $response=[DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
        if($response.Entries.Count -ne 1){throw 'LDS RootDSE entry count differs.'}
        $values=[ordered]@{}
        foreach($name in $attributes) {
            if($response.Entries[0].Attributes.Contains($name)){$values[$name]=@($response.Entries[0].Attributes[$name].GetValues([string]))}else{$values[$name]=@()}
        }
        if('1.2.840.113556.1.4.1851' -notin $values.supportedCapabilities){throw 'Endpoint did not identify as AD LDS.'}
        if($spec.partition -notin $values.namingContexts){throw 'Expected LDS application partition is missing.'}
        return $values
    } finally {$connection.Dispose()}
}

function Wait-LDSRoot([int]$Port) {
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do {
        try {return Read-LDSRoot $Port}catch{$last=$_.Exception.GetType().FullName}
        Start-Sleep -Seconds 2
    }while([DateTime]::UtcNow -lt $deadline)
    throw "LDS endpoint did not become ready; final error type $last."
}

Install-OwnedLDS $spec.primary $spec.ldap_port $spec.ssl_port $false
$primary=Wait-LDSRoot $spec.ldap_port
Install-OwnedLDS $spec.replica $spec.replica_ldap_port $spec.replica_ssl_port $true
$replica=Wait-LDSRoot $spec.replica_ldap_port
if($primary.configurationNamingContext[0] -cne $replica.configurationNamingContext[0] -or $primary.dsServiceName[0] -ceq $replica.dsServiceName[0]){throw 'LDS endpoints are not distinct replicas in the same configuration set.'}
[ordered]@{schema_version=1;phase='instances-ready';id=$fixtureID;computer=$env:COMPUTERNAME;primary=$primary;replica=$replica;setup_version=(Get-Item C:\Windows\ADAM\adaminstall.exe).VersionInfo.FileVersion;time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 8
