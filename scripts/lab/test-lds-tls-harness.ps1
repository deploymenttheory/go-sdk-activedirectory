#Requires -Version 5.1
# Offline only: AST extraction and in-memory fixtures; no VM/store/firewall calls.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
function Import-Helper([string]$File,[string]$Name) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $File),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Script parse failed.'}
    $node=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name},$true)
    if(-not $node){throw "Missing function $Name"}
    return [scriptblock]::Create($node.Extent.Text)
}
. (Import-Helper 'scripts/lab/test-lds-tls.ps1' 'Test-LDSTLSPairedCase')
. (Import-Helper 'scripts/lab/guest-lds-tls-peer.ps1' 'Remove-PeerFirewall')
. (Import-Helper 'scripts/lab/guest-lds-tls-peer.ps1' 'Assert-OwnedPeerProcess')
. (Import-Helper 'scripts/lab/guest-lds-tls-peer.ps1' 'Assert-PeerTrustedCertificate')
. (Import-Helper 'scripts/lab/guest-lds-tls-peer.ps1' 'Get-PeerSHA256')
. (Import-Helper 'scripts/lab/guest-lds-tls-peer.ps1' 'Assert-PeerPath')
. (Import-Helper 'scripts/lab/reference-lds-tls.ps1' 'Assert-TLSOutputSafe')
. (Import-Helper 'scripts/lab/reference-lds-tls.ps1' 'Get-TLSReferenceError')

function New-PairFixture([bool]$Negative) {
    $leaf=if($Negative){'expired'}else{'valid'}
    $case=[pscustomobject]@{name="$leaf-starttls";leaf=$leaf;transport='starttls';port=52000;expect_failure=$Negative}
    $manifest=[pscustomobject]@{certificates=[pscustomobject]@{expired=[pscustomobject]@{sha256='expected-leaf';thumbprint='expected-thumbprint'};valid=[pscustomobject]@{sha256='expected-leaf';thumbprint='expected-thumbprint'}}}
    $guest=[pscustomobject]@{case=$case.name;passed=$true;output_secret_checked=$true;process_stopped=$true;native=[pscustomobject]@{context_expired=$false;dial_succeeded=(-not $Negative);tls_negotiation_error=$Negative;partition_read=(-not $Negative);partition='CN=partition';instance_type=5};reference=[pscustomobject]@{bind_succeeded=(-not $Negative);partition_read=(-not $Negative);partition='CN=partition';instance_type=5}}
    $policies=@(foreach($i in 1..2){[pscustomobject]@{passed=$true;result=$(if($Negative){'800B0101'}else{'0'});certificate_thumbprint='expected-thumbprint';certificate_sha256='expected-leaf';server_name='ADSDK25MEM.ad.sdk.test'}})
    $guest | Add-Member -NotePropertyName certificate_policy -NotePropertyValue ([pscustomobject]@{passed=$true;logging_restored=$true;native=$policies[0];reference=$policies[1]})
    $connections=@()
    foreach($i in 1..2){$connections+=@([pscustomobject]@{selected_certificate=[pscustomobject]@{sha256='expected-leaf'};plaintext_bind_requests=0;starttls_accepted=$true;handshake_complete=(-not $Negative);bind_requests=$(if($Negative){0}else{1});ldap_bytes_forwarded=$(if($Negative){0}else{99});ldap_bytes_received=$(if($Negative){0}else{99});upstream_handshake_complete=(-not $Negative);error_category='peer_tls_alert';upstream_certificate=[pscustomobject]@{sha256='upstream'};upstream_bytes_received=99})}
    $peer=[pscustomobject]@{passed=$true;peer=[pscustomobject]@{mode='starttls';address='10.77.23.20:52000';connection_limit=2;connections=$connections;outcome='connection_limit';configured_certificate=[pscustomobject]@{sha256='expected-leaf'}}}
    return [pscustomobject]@{case=$case;manifest=$manifest;guest=$guest;peer=$peer}
}
foreach($name in @('negative-ok','positive-ok','selected-mismatch','configured-mismatch','bind-leak','forward-leak','upstream-started','plaintext-bind','timeout','one-connection','wrong-address','context-expired','read-mismatch','unvalidated-upstream','missing-selection','missing-policy','wrong-policy','wrong-leaf','wrong-sha256','wrong-host','reference-policy','logging-not-restored','generic-error','canceled','empty-error')) {
    $positive=$name -in @('positive-ok','read-mismatch','unvalidated-upstream')
    $f=New-PairFixture (-not $positive)
    switch($name) {
        'selected-mismatch' {$f.peer.peer.connections[1].selected_certificate.sha256='foreign'}
        'configured-mismatch' {$f.peer.peer.configured_certificate.sha256='foreign'}
        'missing-policy' {$f.guest.PSObject.Properties.Remove('certificate_policy')}
        'wrong-policy' {$f.guest.certificate_policy.native.result='0'}
        'wrong-leaf' {$f.guest.certificate_policy.native.certificate_thumbprint='foreign'}
        'wrong-sha256' {$f.guest.certificate_policy.native.certificate_sha256='foreign'}
        'wrong-host' {$f.guest.certificate_policy.native.server_name='foreign.ad.sdk.test'}
        'reference-policy' {$f.guest.certificate_policy.reference.passed=$false}
        'logging-not-restored' {$f.guest.certificate_policy.logging_restored=$false}
        'generic-error' {$f.peer.peer.connections[0].error_category='transport_or_tls_failure'}
        'canceled' {$f.peer.peer.connections[0].error_category='canceled'}
        'empty-error' {$f.peer.peer.connections[0].error_category=''}
        'bind-leak' {$f.peer.peer.connections[0].bind_requests=1}
        'forward-leak' {$f.peer.peer.connections[0].ldap_bytes_forwarded=1}
        'upstream-started' {$f.peer.peer.connections[0].upstream_handshake_complete=$true}
        'plaintext-bind' {$f.peer.peer.connections[0].plaintext_bind_requests=1}
        'timeout' {$f.peer.peer.connections[0].error_category='timeout'}
        'one-connection' {$f.peer.peer.connections=@($f.peer.peer.connections[0])}
        'wrong-address' {$f.peer.peer.address='10.77.23.21:52000'}
        'context-expired' {$f.guest.native.context_expired=$true}
        'read-mismatch' {$f.guest.reference.partition='CN=other'}
        'unvalidated-upstream' {$f.peer.peer.connections[0].upstream_handshake_complete=$false}
        'missing-selection' {$f.peer.peer.connections[0].PSObject.Properties.Remove('selected_certificate')}
    }
    $caught=$false
    try {$null=Test-LDSTLSPairedCase $f.case $f.manifest $f.guest $f.peer} catch {$caught=$true}
    if($caught -eq ($name -in @('negative-ok','positive-ok'))){throw "Paired-evidence case $name failed."}
}
Write-Output '25 paired-evidence cases passed'

$runRoot='C:\ad-sdk-lds\owned\tls-peers\run'
$marker='owned-marker';$PeerHash='expected-hash';$state=[pscustomobject]@{owner_sid='owned-sid'}
function Test-FirewallGuard([string]$Case) {
    $fixture=@{present=($Case -ne 'absent');removed=0}
    $entry=[pscustomobject]@{name='expired-ldaps';marker=$marker;firewall='owned-rule';port=52000}
    $rule=[pscustomobject]@{Name='owned-rule';Description=$marker;Direction='Inbound';Action='Allow'}
    $ports=[pscustomobject]@{Protocol='TCP';LocalPort=52000}
    $addresses=[pscustomobject]@{LocalAddress='10.77.23.20';RemoteAddress='10.77.23.11'}
    $application=[pscustomobject]@{Program=(Join-Path $runRoot 'tls-peer.exe')}
    switch($Case) {
        'foreign-marker' {$rule.Description='foreign'}
        'foreign-port' {$ports.LocalPort=389}
        'foreign-address' {$addresses.RemoteAddress='Any'}
        'foreign-program' {$application.Program='C:\foreign.exe'}
    }
    function Get-NetFirewallRule {
        [CmdletBinding()]param($PolicyStore)
        if($Case -eq 'lookup-error'){throw 'Injected lookup error.'}
        if($fixture.present){return $rule}
    }
    function Get-NetFirewallPortFilter {param([Parameter(ValueFromPipeline)]$InputObject) process {return $ports}}
    function Get-NetFirewallAddressFilter {param([Parameter(ValueFromPipeline)]$InputObject) process {return $addresses}}
    function Get-NetFirewallApplicationFilter {param([Parameter(ValueFromPipeline)]$InputObject) process {return $application}}
    function Remove-NetFirewallRule {param([Parameter(ValueFromPipeline)]$InputObject) process {$fixture.removed++;if($Case -ne 'no-effect'){$fixture.present=$false}}}
    $caught=$false
    try {Remove-PeerFirewall $entry} catch {$caught=$true}
    if($caught -eq ($Case -in @('success','absent'))){throw "Firewall guard $Case failed."}
    if($Case -notin @('success','no-effect') -and $fixture.removed){throw 'Foreign or unknown firewall rule was removed.'}
}
foreach($name in @('success','absent','foreign-marker','foreign-port','foreign-address','foreign-program','lookup-error','no-effect')){Test-FirewallGuard $name}
Write-Output '8 firewall cleanup cases passed without firewall access'

foreach($name in @('success','marker','pid-reuse','path','owner','owner-query','hash','commandline')) {
    $when=[DateTime]::Parse('2026-11-12T12:00:00Z').ToUniversalTime()
    $entry=[pscustomobject]@{name='expired-ldaps';marker=$marker;started=$when.ToString('o')}
    $process=[pscustomobject]@{StartTime=$when}
    $executable=Join-Path $runRoot 'tls-peer.exe'
    $native=[pscustomobject]@{ExecutablePath=$executable;CommandLine=($executable+' -ready '+(Join-Path $runRoot 'expired-ldaps')+'\ready.json')}
    $sid=[pscustomobject]@{ReturnValue=0;Sid='owned-sid'}
    $hash=$PeerHash
    switch($name) {
        'marker' {$entry.marker='foreign'}
        'pid-reuse' {$process.StartTime=$when.AddMinutes(1)}
        'path' {$native.ExecutablePath='C:\foreign.exe'}
        'owner' {$sid.Sid='foreign'}
        'owner-query' {$sid.ReturnValue=5}
        'hash' {$hash='foreign'}
        'commandline' {$native.CommandLine='foreign'}
    }
    $caught=$false
    try {Assert-OwnedPeerProcess $entry $process $native $sid $executable $hash} catch {$caught=$true}
    if($caught -eq ($name -eq 'success')){throw "Process identity guard $name failed."}
}
Write-Output '8 process identity cases passed without process access'

foreach($name in @('success','marker','private-key','subject','hash')) {
    $certificate=[pscustomobject]@{HasPrivateKey=$false;Subject='CN=AD SDK TLS fixture trusted-root';RawData=[byte[]]@(1,2,3)}
    $expected=[pscustomobject]@{marker=$marker;sha256=(Get-PeerSHA256 $certificate.RawData)}
    switch($name) {
        'marker' {$expected.marker='foreign'}
        'private-key' {$certificate.HasPrivateKey=$true}
        'subject' {$certificate.Subject='CN=foreign'}
        'hash' {$expected.sha256='foreign'}
    }
    $caught=$false
    try {Assert-PeerTrustedCertificate $certificate $expected} catch {$caught=$true}
    if($caught -eq ($name -eq 'success')){throw "Root ownership guard $name failed."}
}
Write-Output '5 certificate ownership cases passed without store access'

foreach($path in @((Join-Path $runRoot 'certificates\valid.pem'),$runRoot)){$null=Assert-PeerPath $path}
foreach($path in @('C:\outside.txt',($runRoot+'-foreign\file'),(Join-Path $runRoot '..\foreign.txt'))) {
    $caught=$false;try{$null=Assert-PeerPath $path}catch{$caught=$true}
    if(-not $caught){throw 'Outside peer path was accepted.'}
}
Write-Output '5 path boundary cases passed'

Add-Type -AssemblyName System.DirectoryServices.Protocols
$secret='synthetic-output-secret'
$account=[PSCredential]::new('fixture-reader',(ConvertTo-SecureString $secret -AsPlainText -Force))
$passwordBytes=[Text.Encoding]::UTF8.GetBytes($secret)
Assert-TLSOutputSafe 'safe output' $account $passwordBytes
foreach($text in @($secret,[Convert]::ToBase64String($passwordBytes))) {
    $caught=$false;try{Assert-TLSOutputSafe $text $account $passwordBytes}catch{$caught=$true}
    if(-not $caught){throw 'Secret output was accepted.'}
}
$exception=[InvalidOperationException]::new($secret,[DirectoryServices.Protocols.LdapException]::new(81,$secret))
$details=@(Get-TLSReferenceError ([pscustomobject]@{Exception=$exception}))
$json=$details | ConvertTo-Json -Compress
if($details.Count -ne 2 -or $details[1].ldap_code -ne 81 -or $json.Contains($secret)){throw 'Error sanitization failed.'}
[Array]::Clear($passwordBytes,0,$passwordBytes.Length)
$account.Password.Dispose()
Write-Output '4 output/error non-disclosure cases passed'

foreach($file in @('test-lds-tls.ps1','reference-lds-tls.ps1','guest-lds-tls-peer.ps1')) {
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo "scripts/lab/$file"),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'PowerShell parse failed.'}
}
Write-Output ('PowerShell '+$PSVersionTable.PSVersion.ToString()+': offline checks passed; no guest operations executed')

