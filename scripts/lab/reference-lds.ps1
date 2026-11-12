#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Binary,[Parameter(Mandatory)][string]$ResultPath,[Parameter(Mandatory)][string]$Specification,[Parameter(Mandatory)][PSCredential]$Reader,[Parameter(Mandatory)][string]$BinaryHash)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
Add-Type -AssemblyName System.DirectoryServices.Protocols
$spec=$Specification | ConvertFrom-Json
if($spec.client -ine $env:COMPUTERNAME -or $spec.phase -ne 'fixture-ready' -or $Reader.UserName -cne $spec.reader.dn){throw 'Unexpected LDS qualification client/fixture.'}
if((Get-FileHash -LiteralPath $Binary).Hash -ne $BinaryHash){throw 'LDS test executable hash differs.'}
function Get-LDSError($ErrorRecord) {
    $exception=$ErrorRecord.Exception
    while($exception) {
        $entry=[ordered]@{type=$exception.GetType().FullName;hresult=$exception.HResult}
        if($exception -is [DirectoryServices.Protocols.LdapException]){$entry.ldap_code=$exception.ErrorCode}
        if($exception -is [DirectoryServices.Protocols.DirectoryOperationException] -and $exception.Response){$entry.ldap_code=[int]$exception.Response.ResultCode}
        [pscustomobject]$entry
        $exception=$exception.InnerException
    }
}
function Convert-RootDSEReferenceValue([string]$Name,$Value) {
    if($Name -eq 'supportedCapabilities' -and $Value -isnot [string]) {
        $oid=$Value.PSObject.Properties['Value']
        if($null -eq $oid){throw 'Unexpected RootDSE capability projection type.'}
        return [string]$oid.Value
    }
    return [string]$Value
}
function New-LDSReference([string]$Transport,[PSCredential]$Account) {
    $port=if($Transport -eq 'ldaps'){$spec.ssl_port}else{$spec.ldap_port}
    $connection=[DirectoryServices.Protocols.LdapConnection]::new([DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($spec.server,[int]$port,$true,$false))
    try {
        $connection.Timeout=[TimeSpan]::FromSeconds(10)
        $connection.SessionOptions.ProtocolVersion=3
        $connection.SessionOptions.ReferralChasing=[DirectoryServices.Protocols.ReferralChasingOptions]::None
        if($Transport -eq 'ldaps'){$connection.SessionOptions.SecureSocketLayer=$true}else{$connection.SessionOptions.StartTransportLayerSecurity($null)}
        $connection.AuthType=[DirectoryServices.Protocols.AuthType]::Basic
        $connection.Credential=$Account.GetNetworkCredential()
        $connection.Bind()
        return $connection
    } catch {$connection.Dispose();throw}
}
$process=$null;$passwordBytes=$null;$wireBytes=$null;$failure=$null;$phase='native';$output=@();$comparisons=@();$exitCode=-1;$processStopped=$false
try {
    $passwordBytes=[Text.Encoding]::UTF8.GetBytes($Reader.GetNetworkCredential().Password)
    $wire=[ordered]@{Server=$spec.server;LDAPPort=$spec.ldap_port;SSLPort=$spec.ssl_port;ReplicaLDAPPort=$spec.replica_ldap_port;ReplicaSSLPort=$spec.replica_ssl_port;Partition=$spec.partition;BindDN=$Reader.UserName;Password=[Convert]::ToBase64String($passwordBytes);Marker=$spec.marker} | ConvertTo-Json -Compress
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$Binary;$start.Arguments='-test.run ^TestADLDSLab$ -test.v';$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.StandardOutputEncoding=[Text.Encoding]::UTF8;$start.StandardErrorEncoding=[Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_LDS_LAB']='1';$start.EnvironmentVariables['ADSDK_LDS_RESULT']=$ResultPath
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    if(-not $process.Start()){throw 'LDS native test did not start.'}
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    $wireBytes=[Text.Encoding]::UTF8.GetBytes($wire)
    $process.StandardInput.BaseStream.Write($wireBytes,0,$wireBytes.Length);$process.StandardInput.BaseStream.Flush();$process.StandardInput.Close()
    [Array]::Clear($wireBytes,0,$wireBytes.Length);$wireBytes=$null;$wire=$null
    if(-not $process.WaitForExit(210000)){$process.Kill();$process.WaitForExit();throw 'LDS native test exceeded its deadline.'}
    $exitCode=$process.ExitCode
    $text=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
    if($text.Contains($Reader.GetNetworkCredential().Password) -or $text.Contains([Convert]::ToBase64String($passwordBytes))){throw 'LDS credential material detected; output suppressed.'}
    $output=@($text -split "`r?`n" | Where-Object {$_})
    if($exitCode -ne 0){throw 'LDS native test failed.'}
    $native=Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    if(-not $native.passed -or $native.reads.Count -ne 2){throw 'Native LDS result is incomplete.'}
    $phase='powershell-reference'
    $endpoint="$($spec.server):$($spec.ldap_port)"
    $reference=Get-ADRootDSE -Server $endpoint
    $partition=Get-ADObject -Identity $spec.partition -Partition $spec.partition -Server $endpoint -Properties instanceType
    foreach($row in $native.reads) {
        foreach($name in @('configurationNamingContext','schemaNamingContext','defaultNamingContext','dnsHostName','dsServiceName','namingContexts','supportedCapabilities')) {
            $phase="powershell-root-$($row.transport)-$name"
            $property=$row.root_attributes.PSObject.Properties[$name.ToLowerInvariant()]
            if(-not $property){throw 'Native LDS RootDSE omitted a comparison property.'}
            $actual=@($property.Value | ForEach-Object {[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))} | Sort-Object)
            $expected=@($reference.$name | ForEach-Object {Convert-RootDSEReferenceValue $name $_} | Sort-Object)
            if(($actual | ConvertTo-Json -Compress) -cne ($expected | ConvertTo-Json -Compress)){throw "LDS PowerShell RootDSE comparison differs for $name."}
        }
        $phase="powershell-partition-$($row.transport)"
        if($row.partition -cne $partition.DistinguishedName -or $row.instance_type -ne $partition.instanceType){throw 'LDS partition differs from PowerShell.'}
        $phase="dotnet-read-$($row.transport)"
        $connection=New-LDSReference $row.transport $Reader
        try {
            $request=[DirectoryServices.Protocols.SearchRequest]::new($spec.partition,'(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,[string[]]@('distinguishedName','instanceType'))
            $result=[DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
            if($result.Entries.Count -ne 1 -or [int]$result.Entries[0].Attributes['instanceType'][0] -ne $row.instance_type){throw 'LDS native-user reference read differs.'}
            $missingCode=$null
            try {$request.DistinguishedName="CN=ADSDK-MissingPartition,$($spec.partition)";$null=$connection.SendRequest($request)} catch [DirectoryServices.Protocols.DirectoryOperationException] {if($_.Exception.Response){$missingCode=[int]$_.Exception.Response.ResultCode}else{throw}}
            if($missingCode -ne $native.missing_partition_ldap_code){throw 'LDS missing-partition status differs.'}
        } finally {$connection.Dispose()}
        $phase="dotnet-wrong-password-$($row.transport)"
        $wrong=[PSCredential]::new($Reader.UserName,(ConvertTo-SecureString ($Reader.GetNetworkCredential().Password+'-wrong') -AsPlainText -Force))
        $wrongCode=$null;$unexpected=$null
        try {$unexpected=New-LDSReference $row.transport $wrong} catch [DirectoryServices.Protocols.LdapException] {$wrongCode=$_.Exception.ErrorCode} finally {if($unexpected){$unexpected.Dispose()};$wrong.Password.Dispose()}
        if($wrongCode -ne $native.wrong_password_ldap_code){throw 'LDS invalid-credential status differs.'}
        $comparisons += [ordered]@{transport=$row.transport;root_properties=7;partition_match=$true;native_user_read=$true;wrong_password_code=$wrongCode;missing_partition_code=$missingCode}
    }
    $phase='powershell-replica-default'
    $replicaRoot=Get-ADRootDSE -Server "$($spec.server):$($spec.replica_ldap_port)"
    if($replicaRoot.defaultNamingContext){throw 'PowerShell replica default should be absent.'}
} catch {$failure=[ordered]@{phase=$phase;line=$_.InvocationInfo.ScriptLineNumber;errors=@(Get-LDSError $_)}}
finally {
    if($process){try{if(-not $process.HasExited){$process.Kill();$process.WaitForExit()};$processStopped=$process.HasExited}finally{$process.Dispose()}}
    if($wireBytes){[Array]::Clear($wireBytes,0,$wireBytes.Length)}
    if($passwordBytes){[Array]::Clear($passwordBytes,0,$passwordBytes.Length)}
    $wire=$null
}
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[ordered]@{schema_version=1;passed=($null -eq $failure -and $processStopped);phase=$phase;error=$failure;exit_code=$exitCode;output=$output;comparisons=$comparisons;process_stopped=$processStopped;fixture_retained=$true;environment=[ordered]@{computer=$env:COMPUTERNAME;build="$($build.CurrentBuild).$($build.UBR)";architecture=$env:PROCESSOR_ARCHITECTURE;powershell=$PSVersionTable.PSVersion.ToString();ad_module=(Get-Module ActiveDirectory).Version.ToString()};time=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 10
