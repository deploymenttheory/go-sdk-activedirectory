#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Initialize','Generate','Trust','Start','Collect','Cleanup')][string]$Action,
    [Parameter(Mandatory)][string]$Specification,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$PeerHash,
    [Parameter(Mandatory)][string]$NativeHash,
    [string]$Case = '',
    [string]$PublicRoot = ''
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$spec=$Specification | ConvertFrom-Json
$fixtureId=[guid]::ParseExact($spec.id,'D').ToString('D')
if($RunId -cnotmatch '^lds-tls-\d{8}T\d{6}Z-[a-f0-9]{8}$' -or $PeerHash -notmatch '^[A-Fa-f0-9]{64}$' -or $NativeHash -notmatch '^[A-Fa-f0-9]{64}$'){throw 'Invalid TLS peer run identity.'}
if($spec.phase -ne 'fixture-ready' -or $spec.member -cne 'ADSDK25MEM' -or $spec.client -cne 'ADSDK25DC2' -or $spec.server -ine 'ADSDK25MEM.ad.sdk.test' -or $spec.marker -cne "ad-sdk-lds:$fixtureId"){throw 'Unexpected LDS TLS matrix fixture.'}
$role=if($env:COMPUTERNAME -ieq $spec.member){'member'}elseif($env:COMPUTERNAME -ieq $spec.client){'client'}else{throw 'Unexpected TLS matrix guest.'}
$fixtureRoot="C:\ad-sdk-lds\$fixtureId"
$container=Join-Path $fixtureRoot 'tls-peers'
$runRoot=Join-Path $container $RunId
$marker="ad-sdk-lds-tls:${fixtureId}:$RunId"
$ownerPath=Join-Path $runRoot 'ownership.json'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $ownerSID=$identity.User.Value
    if($spec.administrator -ine 'ADSDK\Administrator' -or $ownerSID -ne [Security.Principal.NTAccount]::new($spec.administrator).Translate([Security.Principal.SecurityIdentifier]).Value){throw 'Unexpected TLS matrix guest identity.'}
} finally {$identity.Dispose()}
foreach($path in @('C:\ad-sdk-lds',$fixtureRoot,$container,$runRoot)) {
    if((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse point in TLS matrix directory.'}
}
if($role -eq 'member') {
    if((Get-Item -LiteralPath (Join-Path $fixtureRoot 'ownership.json') -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Member ownership file is a reparse point.'}
    $fixtureOwner=Get-Content -LiteralPath (Join-Path $fixtureRoot 'ownership.json') -Raw | ConvertFrom-Json
    if($fixtureOwner.id -ne $fixtureId -or $fixtureOwner.lab_id -ne $spec.lab_id -or $fixtureOwner.marker -cne $spec.marker){throw 'Member fixture ownership differs.'}
} else {
    if((Get-Item -LiteralPath (Join-Path $fixtureRoot 'client-trust.json') -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Client ownership file is a reparse point.'}
    $fixtureOwner=Get-Content -LiteralPath (Join-Path $fixtureRoot 'client-trust.json') -Raw | ConvertFrom-Json
    if($fixtureOwner.id -ne $fixtureId -or $fixtureOwner.lab_id -ne $spec.lab_id -or $fixtureOwner.root_thumbprint -ne $spec.tls.root_thumbprint){throw 'Client fixture ownership differs.'}
}

function Assert-PeerPath([string]$Path) {
    $resolved=[IO.Path]::GetFullPath($Path)
    if($resolved -ine $runRoot -and -not $resolved.StartsWith($runRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Path is outside the owned TLS run.'}
    $cursor=$resolved
    while($cursor.Length -ge $runRoot.Length) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse point in TLS run path.'}
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    return $resolved
}
function Save-PeerOwner {
    $temporary=Assert-PeerPath (Join-Path $runRoot 'ownership.tmp')
    $state | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination (Assert-PeerPath $ownerPath) -Force
}
function Get-PeerSHA256([byte[]]$Data) {
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($algorithm.ComputeHash($Data)).Replace('-','').ToLowerInvariant()} finally {$algorithm.Dispose()}
}
function Get-PeerError($Record) {
    $exception=$Record.Exception
    while($exception) {
        [pscustomobject]@{type=$exception.GetType().FullName;hresult=$exception.HResult}
        $exception=$exception.InnerException
    }
}
function Get-PeerEnvironment {
    $build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    return [ordered]@{computer=$env:COMPUTERNAME;build="$($build.CurrentBuild).$($build.UBR)";architecture=$env:PROCESSOR_ARCHITECTURE;powershell=$PSVersionTable.PSVersion.ToString();wldap32=(Get-Item "$env:windir\System32\wldap32.dll").VersionInfo.FileVersion;schannel=(Get-Item "$env:windir\System32\schannel.dll").VersionInfo.FileVersion}
}
function Remove-PeerFirewall($Entry) {
    # Enumerate the local persistent store with terminating errors: a failed
    # lookup must never be mistaken for an already-absent owned rule.
    $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -ceq $Entry.firewall)
    if($rules.Count -eq 0){return}
    if($rules.Count -ne 1){throw 'Ambiguous TLS peer firewall rule.'}
    $rule=$rules[0]
    $ports=$rule | Get-NetFirewallPortFilter
    $addresses=$rule | Get-NetFirewallAddressFilter
    $application=$rule | Get-NetFirewallApplicationFilter
    if($Entry.marker -cne $marker -or $rule.Description -cne $marker -or $rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow' -or $ports.Protocol -ne 'TCP' -or (@($ports.LocalPort) -join ',') -cne [string]$Entry.port -or (@($addresses.LocalAddress) -join ',') -cne '10.77.23.20' -or (@($addresses.RemoteAddress) -join ',') -cne '10.77.23.11' -or $application.Program -ine (Join-Path $runRoot 'tls-peer.exe')){throw 'TLS peer firewall ownership differs.'}
    $rule | Remove-NetFirewallRule
    if(@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -ceq $Entry.firewall).Count){throw 'TLS peer firewall cleanup was not confirmed.'}
}
function Stop-OwnedPeer($Entry) {
    if($Entry.process_stopped){return}
    if(-not $Entry.pid){$Entry.process_stopped=$true;return}
    try {$process=[Diagnostics.Process]::GetProcessById([int]$Entry.pid)} catch [ArgumentException] {$Entry.process_stopped=$true;return}
    try {
        $null=$process.Handle
        $native=Get-CimInstance Win32_Process -Filter "ProcessId=$($Entry.pid)"
        if(-not $native){$Entry.process_stopped=$true;return}
        $sid=Invoke-CimMethod -InputObject $native -MethodName GetOwnerSid
        $executable=Assert-PeerPath (Join-Path $runRoot 'tls-peer.exe')
        Assert-OwnedPeerProcess $Entry $process $native $sid $executable ((Get-FileHash -LiteralPath $executable).Hash)
        $process.Kill()
        if(-not $process.WaitForExit(5000)){throw 'Owned TLS peer did not stop.'}
        $Entry.process_stopped=$true
    } finally {$process.Dispose()}
}
function Assert-OwnedPeerProcess($Entry,$Process,$Native,$SID,[string]$Executable,[string]$ActualHash) {
    if($Entry.marker -cne $marker -or $Process.StartTime.ToUniversalTime().ToString('o') -cne $Entry.started -or $Native.ExecutablePath -ine $Executable -or $SID.ReturnValue -ne 0 -or $SID.Sid -ne $state.owner_sid -or $ActualHash -ne $PeerHash -or -not $Native.CommandLine -or $Native.CommandLine.IndexOf((Join-Path $runRoot $Entry.name),[StringComparison]::OrdinalIgnoreCase) -lt 0){throw 'TLS peer process ownership differs; refusing termination.'}
}
function Assert-PeerTrustedCertificate($Certificate,$Expected) {
    if($Expected.marker -cne $marker -or $Certificate.HasPrivateKey -or $Certificate.Subject -cne 'CN=AD SDK TLS fixture trusted-root' -or (Get-PeerSHA256 $Certificate.RawData) -cne $Expected.sha256){throw 'TLS peer trusted root ownership differs.'}
}
function Remove-PeerTrust {
    if(-not $state.trust -or -not $state.trust.attempted){return}
    if($state.trust.marker -cne $marker){throw 'TLS peer trust marker differs.'}
    $store=[Security.Cryptography.X509Certificates.X509Store]::new('Root',[Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $matches=@($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$state.trust.thumbprint,$false))
        foreach($certificate in $matches) {
            Assert-PeerTrustedCertificate $certificate $state.trust
            $store.Remove($certificate)
        }
        if($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$state.trust.thumbprint,$false).Count){throw 'TLS peer root cleanup was not confirmed.'}
        $state.trust.cleaned=$true
        Save-PeerOwner
    } finally {$store.Dispose()}
}

if($Action -eq 'Initialize') {
    if(Test-Path -LiteralPath $runRoot){throw 'TLS matrix run already exists.'}
    $null=New-Item -ItemType Directory -Path $runRoot
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')) {$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    Set-Acl -LiteralPath $runRoot -AclObject $acl
    $state=[pscustomobject][ordered]@{schema_version=1;fixture_id=$fixtureId;lab_id=$spec.lab_id;run=$RunId;marker=$marker;role=$role;owner_sid=$ownerSID;peer_sha256=$PeerHash;native_sha256=$NativeHash;cases=@();trust=$null;phase='initialized'}
    Save-PeerOwner
    [ordered]@{passed=$true;directory=$runRoot;environment=Get-PeerEnvironment} | ConvertTo-Json -Depth 8
    return
}
$state=Get-Content -LiteralPath (Assert-PeerPath $ownerPath) -Raw | ConvertFrom-Json
if($state.fixture_id -ne $fixtureId -or $state.lab_id -ne $spec.lab_id -or $state.run -cne $RunId -or $state.marker -cne $marker -or $state.role -ne $role -or $state.owner_sid -ne $ownerSID -or $state.peer_sha256 -ne $PeerHash -or $state.native_sha256 -ne $NativeHash){throw 'TLS matrix run ownership differs.'}
$result=[ordered]@{passed=$false;action=$Action;case=$Case;error=$null;environment=Get-PeerEnvironment}
try {
    switch($Action) {
        'Generate' {
            if($role -ne 'member'){throw 'PEM generation requires the owned member.'}
            $binary=Assert-PeerPath (Join-Path $runRoot 'tls-peer.exe')
            if((Get-FileHash -LiteralPath $binary).Hash -ne $PeerHash){throw 'TLS peer executable hash differs.'}
            $certDirectory=Assert-PeerPath (Join-Path $runRoot 'certificates')
            $null=& $binary generate -dir $certDirectory -server $spec.server 2>&1
            if($LASTEXITCODE -ne 0){throw 'Owned certificate generation failed.'}
            $manifest=Get-Content -LiteralPath (Assert-PeerPath (Join-Path $certDirectory 'manifest.json')) -Raw | ConvertFrom-Json
            if($manifest.server -ine $spec.server){throw 'Generated certificate server differs.'}
            $pem=Get-Content -LiteralPath (Assert-PeerPath (Join-Path $certDirectory 'trusted-root.pem')) -Raw
            $der=[Convert]::FromBase64String(($pem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s',''))
            $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($der)
            try {
                if($certificate.HasPrivateKey -or (Get-PeerSHA256 $der) -cne $manifest.certificates.'trusted-root'.sha256){throw 'Generated public root differs from manifest.'}
                $result.public_root=[ordered]@{marker=$marker;certificate=[Convert]::ToBase64String($der);sha256=Get-PeerSHA256 $der;thumbprint=$certificate.Thumbprint}
            } finally {$certificate.Dispose()}
            $publicLDS=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($spec.tls.root_certificate))
            try {
                if($publicLDS.HasPrivateKey -or $publicLDS.Thumbprint -ne $spec.tls.root_thumbprint -or $publicLDS.Subject -cne "CN=AD SDK LDS root $fixtureId"){throw 'Upstream public root differs.'}
                $rootPEM="-----BEGIN CERTIFICATE-----`r`n"+[Convert]::ToBase64String($publicLDS.RawData,[Base64FormattingOptions]::InsertLineBreaks)+"`r`n-----END CERTIFICATE-----`r`n"
                [IO.File]::WriteAllText((Assert-PeerPath (Join-Path $runRoot 'upstream-root.pem')),$rootPEM,[Text.Encoding]::ASCII)
            } finally {$publicLDS.Dispose()}
            $result.manifest=$manifest
            $state.phase='certificates-ready';Save-PeerOwner
        }
        'Trust' {
            if($role -ne 'client' -or $state.trust){throw 'Unexpected TLS peer trust operation.'}
            $public=$PublicRoot | ConvertFrom-Json
            $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($public.certificate))
            $store=[Security.Cryptography.X509Certificates.X509Store]::new('Root',[Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            try {
                if($public.marker -cne $marker -or $certificate.HasPrivateKey -or $certificate.Thumbprint -ne $public.thumbprint -or $certificate.Subject -cne 'CN=AD SDK TLS fixture trusted-root' -or $certificate.Issuer -cne $certificate.Subject -or (Get-PeerSHA256 $certificate.RawData) -cne $public.sha256){throw 'Unexpected temporary public root.'}
                $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                if($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$certificate.Thumbprint,$false).Count){throw 'Temporary public root already exists; refusing ownership.'}
                $state.trust=[pscustomobject]@{marker=$marker;thumbprint=$certificate.Thumbprint;sha256=$public.sha256;attempted=$true;cleaned=$false}
                Save-PeerOwner
                $store.Add($certificate)
                if($store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$certificate.Thumbprint,$false).Count -ne 1){throw 'Temporary root installation was not confirmed.'}
                $result.thumbprint=$certificate.Thumbprint
            } finally {$store.Dispose();$certificate.Dispose()}
        }
        'Start' {
            if($role -ne 'member' -or $Case -cnotmatch '^(valid|expired|wrong-host|untrusted)-(ldaps|starttls)$' -or @($state.cases | Where-Object name -ceq $Case).Count){throw 'Unexpected or repeated TLS peer case.'}
            $leaf=$Matches[1];$mode=$Matches[2]
            $binary=Assert-PeerPath (Join-Path $runRoot 'tls-peer.exe')
            if((Get-FileHash -LiteralPath $binary).Hash -ne $PeerHash){throw 'TLS peer executable hash differs.'}
            $caseRoot=Assert-PeerPath (Join-Path $runRoot $Case)
            $null=New-Item -ItemType Directory -Path $caseRoot
            $entry=[pscustomobject][ordered]@{name=$Case;marker=$marker;pid=0;started='';port=0;firewall="ADSDK-LDS-TLS-$RunId-$Case";phase='reserved';process_stopped=$false}
            $state.cases+=@($entry);Save-PeerOwner
            $cert=Assert-PeerPath (Join-Path $runRoot "certificates\$leaf.pem")
            $key=Assert-PeerPath (Join-Path $runRoot "certificates\$leaf-key.pem")
            $arguments=@('serve','-mode',$mode,'-listen','10.77.23.20:0','-cert',$cert,'-key',$key,'-ready',"$caseRoot\ready.json",'-result',"$caseRoot\peer.json",'-connections','2','-timeout','150s','-connection-timeout','45s','-upstream',"$($spec.server):$($spec.ssl_port)",'-upstream-ca',"$runRoot\upstream-root.pem",'-upstream-name',$spec.server)
            $quoted=@($arguments | ForEach-Object {if($_ -match '["\r\n]'){throw 'Invalid nonsecret peer argument.'};'"'+$_+'"'}) -join ' '
            $process=Start-Process -FilePath $binary -ArgumentList $quoted -WindowStyle Hidden -PassThru -RedirectStandardOutput "$caseRoot\stdout.log" -RedirectStandardError "$caseRoot\stderr.log"
            try {$entry.pid=$process.Id;$entry.started=$process.StartTime.ToUniversalTime().ToString('o');Save-PeerOwner} finally {$process.Dispose()}
            $readyPath=Assert-PeerPath (Join-Path $caseRoot 'ready.json')
            $deadline=[DateTime]::UtcNow.AddSeconds(15)
            while(-not (Test-Path -LiteralPath $readyPath) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
            if(-not (Test-Path -LiteralPath $readyPath)){throw 'TLS peer readiness deadline exceeded.'}
            $ready=Get-Content -LiteralPath (Assert-PeerPath $readyPath) -Raw | ConvertFrom-Json
            if($ready.pid -ne $entry.pid -or $ready.mode -cne $mode -or $ready.address -cnotmatch '^10\.77\.23\.20:([1-9][0-9]{0,4})$'){throw 'TLS peer readiness identity/address differs.'}
            $entry.port=[int]$Matches[1]
            if($entry.port -gt 65535){throw 'Invalid TLS peer port.'}
            Save-PeerOwner
            if(@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -ceq $entry.firewall).Count){throw 'TLS peer firewall name exists.'}
            New-NetFirewallRule -Name $entry.firewall -DisplayName $entry.firewall -Description $marker -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 10.77.23.20 -LocalPort $entry.port -RemoteAddress 10.77.23.11 -Program $binary -Profile Any | Out-Null
            $entry.phase='ready';Save-PeerOwner
            $result.ready=$ready;$result.port=$entry.port
        }
        'Collect' {
            $entries=@($state.cases | Where-Object name -ceq $Case)
            if($role -ne 'member' -or $entries.Count -ne 1){throw 'TLS peer case ownership missing.'}
            $path=Assert-PeerPath (Join-Path $runRoot "$Case\peer.json")
            $deadline=[DateTime]::UtcNow.AddSeconds(160)
            while(-not (Test-Path -LiteralPath $path) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 200}
            if(Test-Path -LiteralPath $path) {
                if((Get-Item -LiteralPath (Assert-PeerPath $path)).Length -gt 1048576){throw 'TLS peer result exceeds its bound.'}
                $result.peer=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            } else {throw 'TLS peer result deadline exceeded.'}
            Remove-PeerFirewall $entries[0]
            Stop-OwnedPeer $entries[0]
            $entries[0].phase='collected';Save-PeerOwner
        }
        'Cleanup' {
            $cleanup=@()
            foreach($entry in @($state.cases)) {
                try {Remove-PeerFirewall $entry} catch {$cleanup+=@(Get-PeerError $_)}
                try {Stop-OwnedPeer $entry} catch {$cleanup+=@(Get-PeerError $_)}
                Save-PeerOwner
            }
            try {Remove-PeerTrust} catch {$cleanup+=@(Get-PeerError $_)}
            $result.cleanup_errors=$cleanup
            if($cleanup.Count){throw 'TLS peer cleanup could not be confirmed.'}
            $state.phase='cleaned';Save-PeerOwner
            $result.private_pem_retained_in_guest=($role -eq 'member')
        }
    }
    $result.passed=$true
} catch {$result.error=[ordered]@{line=$_.InvocationInfo.ScriptLineNumber;errors=@(Get-PeerError $_)}}
$result | ConvertTo-Json -Depth 20
