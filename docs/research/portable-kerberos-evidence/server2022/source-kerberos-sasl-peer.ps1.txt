#Requires -Version 5.1
# Functions only. Dot-source with kerberos-fixture.ps1 inside the owned DC1.
# The relay handles opaque tokens in memory; evidence contains counts only.

function Get-KerberosSASLPeerDirectory([string]$RunId,[string]$CaseId) {
    $null=Get-KerberosFixtureNames $RunId
    if ($CaseId -cnotmatch '\A[a-z0-9][a-z0-9-]{5,63}\z') {throw 'Invalid SASL peer case identity.'}
    return Assert-KerberosFixturePath (Join-Path (Join-Path (Get-KerberosFixtureDirectory $RunId) 'sasl-peer') $CaseId)
}

function Assert-KerberosSASLPeerRecord($State,[string]$RunId,[string]$CaseId,[string]$Directory,[string]$Server) {
    if ($State.schema_version -ne 1 -or $State.run_id -cne $RunId -or $State.case_id -cne $CaseId -or $State.server -cne $Server -or
        $State.directory -cne $Directory -or $State.binary_sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        $State.binary -cne (Join-Path $Directory 'peer.exe') -or $State.firewall_name -cne "adsdk-sasl-$RunId-$CaseId" -or
        $State.scenario -cnotin @('pass','tampered','reordered','truncated-prefix','truncated-body')) {throw 'SASL peer ownership record changed.'}
}

function Assert-KerberosSASLPeerRule($Rule,[string]$Name,[string]$Binary) {
    if ($Rule.Name -cne $Name -or $Rule.DisplayName -cne $Name -or $Rule.Group -cne $Name -or $Rule.Direction -ne 'Inbound' -or $Rule.Action -ne 'Allow') {
        throw 'SASL peer firewall ownership changed.'
    }
    $ports=@($Rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $addresses=@($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $applications=@($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    if ($ports.Count -ne 1 -or $ports[0].LocalPort -cne '31389' -or $ports[0].Protocol -notin @('TCP',6) -or
        $applications.Count -ne 1 -or $applications[0].Program -ine $Binary -or $addresses.Count -ne 1 -or
        @($addresses[0].LocalAddress).Count -ne 1 -or @($addresses[0].LocalAddress)[0] -cne '10.77.23.10' -or
        (@($addresses[0].RemoteAddress | Sort-Object) -join ',') -cne '10.77.23.20,10.77.23.30') {throw 'SASL peer firewall scope changed.'}
}

function Save-KerberosSASLPeerState($State) {
    $path=Assert-KerberosFixturePath (Join-Path $State.directory 'owner.json')
    [IO.File]::WriteAllText($path,($State|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
}

function New-KerberosSASLPeer([string]$RunId,[string]$ExpectedServer,[string]$CaseId,[string]$Scenario,[byte[]]$Binary,[string]$BinarySHA256) {
    $root=Get-KerberosFixtureState $RunId $ExpectedServer
    Assert-KerberosPolicyLease $root
    if ($root.server -cnotmatch '\Aadsdk(16|19|22|25)dc1\.ad\.sdk\.test\z' -or $Scenario -cnotin @('pass','tampered','reordered','truncated-prefix','truncated-body') -or
        -not $Binary -or $Binary.Length -gt 32MB -or $BinarySHA256 -cnotmatch '\A[0-9a-f]{64}\z') {throw 'Invalid owned DC1 peer binary or scenario.'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$actual=([BitConverter]::ToString($sha.ComputeHash($Binary))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
    if ($actual -cne $BinarySHA256) {throw 'SASL peer binary provenance mismatch.'}
    $directory=Get-KerberosSASLPeerDirectory $RunId $CaseId
    $ruleName="adsdk-sasl-$RunId-$CaseId"
    if ((Test-Path -LiteralPath $directory) -or @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -ceq $ruleName}).Count -ne 0 -or
        @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -eq 31389}).Count -ne 0) {throw 'Peer path, firewall name or port is already in use.'}
    $null=New-Item -ItemType Directory -Path $directory
    Protect-KerberosFixtureDirectory $directory
    $state=[pscustomobject]@{
        schema_version=1;run_id=$RunId;case_id=$CaseId;server=$root.server;directory=$directory;scenario=$Scenario
        binary=(Join-Path $directory 'peer.exe');binary_sha256=$BinarySHA256;firewall_name=$ruleName;pid=$null;start_ticks=$null;phase='prepared'
    }
    Save-KerberosSASLPeerState $state
    [IO.File]::WriteAllBytes($state.binary,$Binary)
    if ((Get-FileHash -LiteralPath $state.binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $BinarySHA256) {throw 'Written peer binary hash differs.'}
    $null=New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Group $ruleName -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol TCP -LocalPort 31389 -LocalAddress '10.77.23.10' -RemoteAddress @('10.77.23.20','10.77.23.30') -Program $state.binary -ErrorAction Stop
    $rule=Get-NetFirewallRule -Name $ruleName -ErrorAction Stop
    Assert-KerberosSASLPeerRule $rule $ruleName $state.binary
    $state.phase='firewall-created';Save-KerberosSASLPeerState $state
    $arguments=@('-listen','10.77.23.10:31389','-scenario',$Scenario,'-run-id',$RunId,'-ready',(Join-Path $directory 'ready.json'),'-output',(Join-Path $directory 'result.json'))
    $process=Start-Process -FilePath $state.binary -ArgumentList $arguments -WorkingDirectory $directory -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $directory 'stdout.txt') -RedirectStandardError (Join-Path $directory 'stderr.txt')
    $state.pid=$process.Id;$state.start_ticks=$process.StartTime.ToUniversalTime().Ticks;$state.phase='started';Save-KerberosSASLPeerState $state
    $ready=Join-Path $directory 'ready.json'
    for ($attempt=0;$attempt -lt 100;$attempt++) {
        if (Test-Path -LiteralPath $ready) {break}
        if ($process.HasExited) {throw 'Owned SASL peer exited before readiness.'}
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $ready)) {throw 'Owned SASL peer readiness timed out.'}
    $proof=Get-Content -LiteralPath $ready -Raw | ConvertFrom-Json
    if ($proof.run_id -cne $RunId -or $proof.scenario -cne $Scenario -or $proof.listen -cne '10.77.23.10:31389') {throw 'Owned SASL peer readiness identity differs.'}
    $state.phase='ready';Save-KerberosSASLPeerState $state
    return $state
}

function Remove-KerberosSASLPeer([string]$RunId,[string]$ExpectedServer,[string]$CaseId) {
    $root=Get-KerberosFixtureState $RunId $ExpectedServer
    $directory=Get-KerberosSASLPeerDirectory $RunId $CaseId
    $state=Get-Content -LiteralPath (Join-Path $directory 'owner.json') -Raw | ConvertFrom-Json
    Assert-KerberosSASLPeerRecord $state $RunId $CaseId $directory $root.server
    $allowed=@('owner.json','peer.exe','ready.json','result.json','stdout.txt','stderr.txt')
    foreach ($file in @(Get-ChildItem -LiteralPath $directory -Force)) {
        if ($file.PSIsContainer -or $file.Name -cnotin $allowed -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            -not $file.FullName.StartsWith($directory+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected peer file or reparse point; refusing cleanup.'}
    }
    if (Test-Path -LiteralPath $state.binary) {
        if ((Get-FileHash -LiteralPath $state.binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $state.binary_sha256) {throw 'Owned peer binary changed before cleanup.'}
    }
    if ($state.pid) {
        $process=Get-Process -Id $state.pid -ErrorAction SilentlyContinue
        if ($process) {
            if ($process.Path -ine $state.binary -or $process.StartTime.ToUniversalTime().Ticks -ne [long]$state.start_ticks) {throw 'Recorded peer PID was reused by another process.'}
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            $process.WaitForExit(5000) | Out-Null
            if (-not $process.HasExited) {throw 'Owned peer process did not exit.'}
        }
    }
    $rules=@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -ceq $state.firewall_name})
    if ($rules.Count -gt 1) {throw 'Ambiguous peer firewall ownership.'}
    if ($rules.Count -eq 1) {
        Assert-KerberosSASLPeerRule $rules[0] $state.firewall_name $state.binary
        Remove-NetFirewallRule -Name $state.firewall_name -ErrorAction Stop
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop | Where-Object {$_.Name -ceq $state.firewall_name}).Count -ne 0 -or
        @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -eq 31389}).Count -ne 0) {throw 'Owned peer firewall or listener remains.'}
    $evidence=[ordered]@{run_id=$RunId;case_id=$CaseId;owner=$state;files=@{};result=$null;verified=$false;processes_remaining=0;firewall_rules_remaining=0}
    foreach ($file in @(Get-ChildItem -LiteralPath $directory -Force)) {
        $evidence.files[$file.Name]=@{sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant();length=$file.Length}
        if ($file.Name -cne 'peer.exe') {
            if ($file.Length -gt 128KB) {throw 'Count-only peer evidence exceeds its bound; retain files for inspection.'}
            $evidence.files[$file.Name].bytes_base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))
        }
        if ($file.Name -ceq 'result.json') {$evidence.result=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json}
    }
    # All final absolute targets were checked against the exact owned directory.
    foreach ($name in $allowed) {
        $target=Assert-KerberosFixturePath (Join-Path $directory $name)
        if (Test-Path -LiteralPath $target) {Remove-Item -LiteralPath $target -Force}
    }
    if (@(Get-ChildItem -LiteralPath $directory -Force).Count -ne 0) {throw 'Peer directory is not empty.'}
    Remove-Item -LiteralPath $directory
    $parent=Assert-KerberosFixturePath ([IO.Path]::GetDirectoryName($directory))
    if (@(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) {Remove-Item -LiteralPath $parent}
    $evidence.verified=(-not (Test-Path -LiteralPath $directory))
    return [pscustomobject]$evidence
}
