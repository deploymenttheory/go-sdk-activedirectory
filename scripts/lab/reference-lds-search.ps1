#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Binary,[Parameter(Mandatory)][string]$ResultPath,[Parameter(Mandatory)][string]$Specification,[Parameter(Mandatory)][PSCredential]$Reader,[Parameter(Mandatory)][string]$BinaryHash,[Parameter(Mandatory)][string]$RunId)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.DirectoryServices.Protocols
$spec=$Specification | ConvertFrom-Json
if ($spec.client -ine $env:COMPUTERNAME -or $spec.phase -ne 'fixture-ready' -or $spec.partition -cne 'CN=SdkLds,DC=lab,DC=test' -or $Reader.UserName -cne "CN=SDKReader,$($spec.partition)" -or $Reader.UserName -cne $spec.reader.dn -or $spec.marker -cne "ad-sdk-lds:$($spec.id)" -or $spec.server -ine "$($spec.member).ad.sdk.test") { throw 'Unexpected owned LDS search client/fixture.' }
if ((Get-FileHash -LiteralPath $Binary).Hash -ne $BinaryHash) { throw 'LDS search executable hash differs.' }

function New-LDSSearchReference([string]$Server,[int]$Port,[PSCredential]$Account) {
    $connection=[DirectoryServices.Protocols.LdapConnection]::new([DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Server,$Port,$true,$false))
    try {
        $connection.Timeout=[TimeSpan]::FromSeconds(10)
        $connection.SessionOptions.ProtocolVersion=3
        $connection.SessionOptions.SecureSocketLayer=$true
        $connection.SessionOptions.ReferralChasing=[DirectoryServices.Protocols.ReferralChasingOptions]::None
        $connection.AuthType=[DirectoryServices.Protocols.AuthType]::Basic
        $connection.Credential=$Account.GetNetworkCredential()
        $connection.Bind()
        return $connection
    } catch {$connection.Dispose();throw}
}
function Read-LDSSearchReference($Connection,[string]$Base,[DirectoryServices.Protocols.SearchScope]$Scope,[string]$Filter='(objectClass=*)') {
    $request=[DirectoryServices.Protocols.SearchRequest]::new($Base,$Filter,$Scope,[string[]]@('objectGUID','objectClass','description'))
    $page=[DirectoryServices.Protocols.PageResultRequestControl]::new(1)
    $page.IsCritical=$true
    $null=$request.Controls.Add($page)
    $objects=[Collections.Generic.List[object]]::new();$pages=0
    do {
        # The retained application fixture is small; refuse unexpected runaway
        # continuation instead of allowing an unbounded qualification process.
        if ($pages -ge 64) { throw 'LDS reference exceeded the owned fixture page bound.' }
        $response=[DirectoryServices.Protocols.SearchResponse]$Connection.SendRequest($request)
        $pages++
        if ($response.References.Count) { throw 'LDS reference returned a referral.' }
        foreach ($entry in $response.Entries) {
            $attributes=[ordered]@{}
            foreach ($name in @('objectGUID','objectClass','description')) {
                if ($entry.Attributes.Contains($name)) {
                    $values=@()
                    foreach ($value in $entry.Attributes[$name].GetValues([byte[]])) { $values+=@([Convert]::ToBase64String($value)) }
                    $attributes[$name.ToLowerInvariant()]=$values
                }
            }
            $objects.Add([pscustomobject]@{dn=$entry.DistinguishedName;attributes=[pscustomobject]$attributes})
        }
        $controls=@($response.Controls | Where-Object {$_ -is [DirectoryServices.Protocols.PageResultResponseControl]})
        if ($controls.Count -ne 1) { throw 'LDS reference did not return the critical paging response.' }
        $page.Cookie=$controls[0].Cookie
    } while ($page.Cookie.Length)
    return [pscustomobject]@{objects=$objects.ToArray();pages=$pages;complete=$true}
}
function Compare-LDSSearchProjection($Native,$Reference,[switch]$Subset) {
    if ((-not $Subset -and @($Native).Count -ne @($Reference).Count) -or ($Subset -and @($Native).Count -ne 1)) { throw 'LDS reference projection counts differ.' }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($object in $Native) {
        if (-not $seen.Add($object.DistinguishedName)) { throw 'Native LDS search returned a duplicate DN.' }
        $matches=@($Reference | Where-Object dn -ieq $object.DistinguishedName)
        if ($matches.Count -ne 1) { throw 'Native LDS search DN differs from the same-reader reference.' }
        $expected=$matches[0].attributes
        $actualKeys=@($object.Attributes.PSObject.Properties.Name | Sort-Object)
        $expectedKeys=@($expected.PSObject.Properties.Name | Sort-Object)
        if (($actualKeys | ConvertTo-Json -Compress) -cne ($expectedKeys | ConvertTo-Json -Compress)) { throw 'LDS selected attribute presence differs.' }
        foreach ($name in $actualKeys) {
            $actual=@($object.Attributes.$name | Sort-Object);$wanted=@($expected.$name | Sort-Object)
            if (($actual | ConvertTo-Json -Compress) -cne ($wanted | ConvertTo-Json -Compress)) { throw 'LDS raw attribute bytes differ.' }
        }
    }
}
function Get-LDSSearchError($Record) {
    $exception=$Record.Exception
    while ($exception) {
        $row=[ordered]@{type=$exception.GetType().FullName;hresult=$exception.HResult}
        if ($exception -is [DirectoryServices.Protocols.LdapException]) {$row.ldap_code=$exception.ErrorCode}
        if ($exception -is [DirectoryServices.Protocols.DirectoryOperationException] -and $exception.Response) {$row.ldap_code=[int]$exception.Response.ResultCode}
        [pscustomobject]$row
        $exception=$exception.InnerException
    }
}
$process=$null;$passwordBytes=$null;$wireBytes=$null;$wire=$null;$failure=$null;$cleanupErrors=@();$phase='native'
$output=@();$comparisons=@();$exitCode=$null;$processStopped=$false;$connectionsClosed=0
try {
    $passwordBytes=[Text.Encoding]::UTF8.GetBytes($Reader.GetNetworkCredential().Password)
    $wire=@{Server=$spec.server;SSLPort=$spec.ssl_port;ReplicaSSLPort=$spec.replica_ssl_port;Partition=$spec.partition;BindDN=$Reader.UserName;Password=[Convert]::ToBase64String($passwordBytes);Marker=$spec.marker} | ConvertTo-Json -Compress
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$Binary;$start.Arguments='-test.run ^TestADLDSSearchLab$ -test.v -test.count=1 -test.timeout=150s';$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.StandardOutputEncoding=[Text.Encoding]::UTF8;$start.StandardErrorEncoding=[Text.Encoding]::UTF8
    $start.EnvironmentVariables['ADSDK_LDS_SEARCH_LAB']='1';$start.EnvironmentVariables['ADSDK_LDS_SEARCH_RESULT']=$ResultPath
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    if (-not $process.Start()) {throw 'LDS search native test did not start.'}
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    $wireBytes=[Text.Encoding]::UTF8.GetBytes($wire)
    $process.StandardInput.BaseStream.Write($wireBytes,0,$wireBytes.Length);$process.StandardInput.BaseStream.Flush();$process.StandardInput.Close()
    [Array]::Clear($wireBytes,0,$wireBytes.Length);$wireBytes=$null;$wire=$null
    if (-not $process.WaitForExit(180000)) {$process.Kill();$process.WaitForExit();throw 'LDS native search process exceeded its deadline.'}
    $exitCode=$process.ExitCode
    $text=$stdout.GetAwaiter().GetResult()+$stderr.GetAwaiter().GetResult()
    if ($text.Contains($Reader.GetNetworkCredential().Password) -or $text.Contains([Convert]::ToBase64String($passwordBytes))) {throw 'LDS search credential material detected; output suppressed.'}
    $output=@($text -split "`r?`n" | Where-Object {$_})
    if ($exitCode -ne 0) {throw 'Native LDS search qualification failed.'}
    $native=Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
    if (-not $native.passed -or $native.server -ine $spec.server -or $native.partition -cne $spec.partition -or $native.bind_dn -cne $Reader.UserName -or $native.reads.Count -ne 2) {throw 'Native LDS search artifact identity/count differs.'}
    $phase='same-reader-dotnet-reference'
    $index=0
    foreach ($port in @($spec.ssl_port,$spec.replica_ssl_port)) {
        $rows=@($native.reads | Where-Object port -eq $port)
        if ($rows.Count -ne 1) {throw 'Native LDS endpoint is missing or duplicated.'}
        $row=$rows[0]
        if ($row.partition -cne $spec.partition -or $row.directory_type -cne 'AD LDS' -or -not $row.paging_supported -or -not $row.adds_prerequisite_rejected -or -not $row.explicit_base_without_config_partition -or -not $row.native_allocations_released -or $row.default_partition_absent -ne ($index -eq 1)) {throw 'Native LDS selection/capability/cleanup observations differ.'}
        $connection=New-LDSSearchReference $spec.server $port $Reader
        try {
            $rootRequest=[DirectoryServices.Protocols.SearchRequest]::new('','(objectClass=*)',[DirectoryServices.Protocols.SearchScope]::Base,[string[]]@('defaultNamingContext','supportedCapabilities','supportedControl'))
            $root=[DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($rootRequest)
            if ($root.Entries.Count -ne 1) {throw 'Reference LDS RootDSE is incomplete.'}
            $attributes=$root.Entries[0].Attributes
            if ('1.2.840.113556.1.4.1851' -notin @($attributes['supportedCapabilities'].GetValues([string])) -or '1.2.840.113556.1.4.319' -notin @($attributes['supportedControl'].GetValues([string]))) {throw 'Reference LDS/paging capabilities are absent.'}
            $default=@();if ($attributes.Contains('defaultNamingContext')) {$default=@($attributes['defaultNamingContext'].GetValues([string]))}
            if (($index -eq 0 -and ($default.Count -ne 1 -or $default[0] -cne $spec.partition)) -or ($index -eq 1 -and $default.Count)) {throw 'Reference LDS instance default differs.'}
            $base=Read-LDSSearchReference $connection $spec.partition Base
            $one=Read-LDSSearchReference $connection $spec.partition OneLevel
            $subtree=Read-LDSSearchReference $connection $spec.partition Subtree
            if ($one.objects.Count -lt 2 -or $one.pages -lt 2 -or $subtree.objects.Count -le $one.objects.Count) {throw 'Reference LDS fixture did not exercise paging and scopes.'}
            Compare-LDSSearchProjection $row.base $base.objects
            Compare-LDSSearchProjection $row.one_level $one.objects
            Compare-LDSSearchProjection $row.subtree $subtree.objects
            # LDAP search order is not promised; a limited native result must be
            # an exact projection of one member of the full reference set.
            Compare-LDSSearchProjection $row.limited $one.objects -Subset
            if (-not $row.limit_reached) {throw 'Native LDS caller limit was not reported.'}
            $zero=Read-LDSSearchReference $connection $spec.partition OneLevel '(objectClass=ADSDKSearchNoSuchClass)'
            if ($zero.objects.Count -ne 0 -or $row.zero_count -ne 0) {throw 'LDS zero-match reference differs.'}
            $missingCode=$null
            try {$null=Read-LDSSearchReference $connection "CN=ADSDK-Search-Missing,$($spec.partition)" Base} catch [DirectoryServices.Protocols.DirectoryOperationException] {if ($_.Exception.Response) {$missingCode=[int]$_.Exception.Response.ResultCode} else {throw}}
            if ($missingCode -ne 32 -or $row.missing_base_code -ne $missingCode) {throw 'LDS missing-base result differs from the reference.'}
            $comparisons+=@([ordered]@{port=$port;bind_dn=$Reader.UserName;partition=$spec.partition;default_naming_context=$default;base_count=$base.objects.Count;one_level_count=$one.objects.Count;one_level_pages=$one.pages;subtree_count=$subtree.objects.Count;limited_count=1;zero_count=0;missing_base_code=$missingCode;raw_projection_match=$true;directory_type='AD LDS';paging_advertised=$true})
        } finally {$connection.Dispose();$connectionsClosed++}
        $index++
    }
    $phase='complete'
} catch {$failure=[ordered]@{phase=$phase;line=$_.InvocationInfo.ScriptLineNumber;errors=@(Get-LDSSearchError $_)}}
finally {
    try {
        if ($process) {try {if (-not $process.HasExited) {$process.Kill();$process.WaitForExit()};$processStopped=$process.HasExited} finally {$process.Dispose()}}
    } catch {$cleanupErrors+=@(Get-LDSSearchError $_)}
    finally {
        if ($wireBytes) {[Array]::Clear($wireBytes,0,$wireBytes.Length)}
        if ($passwordBytes) {[Array]::Clear($passwordBytes,0,$passwordBytes.Length)}
        $wire=$null
    }
}
$os=Get-CimInstance Win32_OperatingSystem
$build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$module=Get-Module -ListAvailable ActiveDirectory | Sort-Object Version -Descending | Select-Object -First 1
$passed=$null -eq $failure -and $cleanupErrors.Count -eq 0 -and $processStopped -and $connectionsClosed -eq 2 -and $comparisons.Count -eq 2
[ordered]@{
    schema_version=1;run=$RunId;passed=$passed;timestamp=[DateTime]::UtcNow.ToString('o');server=$spec.server;fixture_id=$spec.id;fixture_retained=$true;directory_mutations=0
    binary_sha256=$BinaryHash;native_exit_code=$exitCode;output=$output;comparisons=$comparisons;failure=$failure;cleanup_errors=$cleanupErrors;process_stopped=$processStopped;reference_connections_closed=$connectionsClosed
    reference_engine='System.DirectoryServices.Protocols.LdapConnection';reference_identity=$Reader.UserName;reference_transport='LDAPS/SIMPLE';permission_scope='Reader visibility only; capability advertisements do not establish authorization.'
    client_environment=[ordered]@{computer=$env:COMPUTERNAME;os_caption=$os.Caption;os_version=$os.Version;os_build=$os.BuildNumber;os_revision=$build.UBR;powershell_version=$PSVersionTable.PSVersion.ToString();ad_module_version=$(if ($module) {$module.Version.ToString()} else {$null});dotnet_ldap_assembly=[DirectoryServices.Protocols.LdapConnection].Assembly.FullName}
} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath ($ResultPath+'.reference.json') -Encoding UTF8
if (-not $passed) {throw 'LDS search qualification failed; inspect its public reference artifact.'}
