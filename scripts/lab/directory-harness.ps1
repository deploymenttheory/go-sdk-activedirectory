#Requires -Version 5.1
# Functions only. This file performs no directory, process or VM operation when loaded.

function Assert-DirectoryPlainPath([string]$Path,[bool]$MustExist=$true) {
    $full=[IO.Path]::GetFullPath($Path)
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) { throw 'Required harness path does not exist.' }
    $cursor=$full
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Harness paths must not traverse reparse points.' }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}

function Write-DirectoryNewJSON([string]$Path,$Value) {
    Write-DirectoryNewText $Path (($Value | ConvertTo-Json -Depth 16)+"`n")
}

function Write-DirectoryNewText([string]$Path,[string]$Value) {
    $full=Assert-DirectoryPlainPath $Path $false
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Value)
    $stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}

function Read-DirectoryFixture([string]$Path) {
    $full=Assert-DirectoryPlainPath $Path
    $fixture=Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json
    $allowed=@('schema_version','purpose','fixture_id','domain_dns','domain_guid','server','client_computer','server_version','trust_partners')
    foreach ($property in $fixture.PSObject.Properties.Name) { if ($property -notin $allowed) { throw 'Unknown fixture-manifest property; credentials and arbitrary payloads are not accepted.' } }
    foreach ($property in $allowed) { if (-not $fixture.PSObject.Properties[$property]) { throw "Fixture manifest is missing $property." } }
    foreach ($property in @('purpose','fixture_id','domain_dns','domain_guid','server','client_computer','server_version')) {if ($fixture.$property -isnot [string]) {throw 'Fixture identity fields must be strings.'}}
    if ($fixture.trust_partners -isnot [Array]) {throw 'trust_partners must be an array, including when empty.'}
    if ($fixture.schema_version -ne 1 -or $fixture.purpose -cne 'go-sdk-activedirectory-isolated-lab' -or $fixture.fixture_id -notmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z') { throw 'Unrecognized isolated fixture identity.' }
    if ($fixture.server_version -notin @('2016','2019','2022','2025')) { throw 'Unknown server version label.' }
    Assert-DirectoryDNSName $fixture.server; Assert-DirectoryDNSName $fixture.domain_dns
    if ($fixture.client_computer -notmatch '\A[A-Za-z0-9][A-Za-z0-9-]{0,14}\z') { throw 'Invalid expected client computer identity.' }
    $parsed=[guid]::Empty
    if (-not [guid]::TryParse($fixture.domain_guid,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'A provisioned domain GUID is required.' }
    $seen=@{}
    foreach ($partner in @($fixture.trust_partners)) {
        foreach ($property in $partner.PSObject.Properties.Name) { if ($property -notin @('dns_name','server','domain_guid')) { throw 'Unknown trust-partner manifest property.' } }
        foreach ($property in @('dns_name','server','domain_guid')) { if (-not $partner.PSObject.Properties[$property]) { throw 'Incomplete trust-partner identity.' } }
        foreach ($property in @('dns_name','server','domain_guid')) {if ($partner.$property -isnot [string]) {throw 'Trust-partner identity fields must be strings.'}}
        Assert-DirectoryDNSName $partner.dns_name; Assert-DirectoryDNSName $partner.server
        if ($partner.dns_name -ieq $fixture.domain_dns -or $seen.ContainsKey($partner.dns_name)) { throw 'Self or duplicate trust partner is not allowed.' }
        $seen[$partner.dns_name]=$true
        if (-not [guid]::TryParse($partner.domain_guid,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'A provisioned partner-domain GUID is required.' }
    }
    return $fixture
}

function Assert-DirectoryDNSName([string]$Name) {
    if ($Name.Length -gt 253 -or $Name -notmatch '\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z') { throw 'Harness targets must be explicit ASCII DNS names without ports or command syntax.' }
}

function New-DirectoryRun([string]$ArtifactRoot,[string]$FixtureID,[string]$FixtureHash) {
    $root=Assert-DirectoryPlainPath $ArtifactRoot
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Artifact root must be an existing directory.' }
    $run='directory-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N')
    $path=[IO.Path]::GetFullPath((Join-Path $root $run))
    if (-not $path.StartsWith($root.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Run path escaped its artifact root.' }
    $null=New-Item -ItemType Directory -Path $path -ErrorAction Stop
    Write-DirectoryNewJSON (Join-Path $path 'owner.json') ([ordered]@{schema_version=1;purpose='go-sdk-activedirectory-directory-run';run_id=$run;fixture_id=$FixtureID;fixture_sha256=$FixtureHash})
    return [pscustomobject]@{ID=$run;Path=$path}
}

function Assert-DirectoryRun([string]$Path,[string]$RunID,[string]$FixtureID) {
    $full=Assert-DirectoryPlainPath $Path
    $marker=Assert-DirectoryPlainPath (Join-Path $full 'owner.json')
    $owner=Get-Content -LiteralPath $marker -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($owner.purpose -cne 'go-sdk-activedirectory-directory-run' -or $owner.run_id -cne $RunID -or $owner.fixture_id -cne $FixtureID -or (Split-Path -Leaf $full) -cne $RunID) { throw 'Directory artifact ownership mismatch.' }
    return $full
}

function ConvertTo-DirectoryHashMap($Object,[ValidateSet('source','harness')][string]$Kind) {
    $result=[ordered]@{}
    foreach ($property in ($Object.PSObject.Properties | Sort-Object Name)) {
        $name=$property.Name
        if ($name -notmatch '\A[A-Za-z0-9_.-]+\z' -or $property.Value -notmatch '\A[0-9a-fA-F]{64}\z') {throw 'Invalid prepared snapshot hash entry.'}
        if ($Kind -eq 'source' -and $name -notin @('go.mod','go.sum') -and $name -notlike '*.go') {throw 'Unexpected source snapshot file.'}
        if ($Kind -eq 'harness' -and $name -notin @('directory-harness.ps1','reference-directory.ps1','test-directory.ps1')) {throw 'Unexpected harness snapshot file.'}
        $result[$name]=[string]$property.Value
    }
    if ($Kind -eq 'source' -and (-not $result.Contains('go.mod') -or -not $result.Contains('go.sum'))) {throw 'Prepared source lacks module pins.'}
    if ($Kind -eq 'harness' -and $result.Count -ne 3) {throw 'Prepared harness is incomplete.'}
    return $result
}

function ConvertTo-DirectoryProcessArgument([string]$Value) {
    # Windows CommandLineToArgvW quoting; no shell is involved.
    $builder=[Text.StringBuilder]::new();$null=$builder.Append('"');$slashes=0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++;continue }
        if ($character -eq '"') { $null=$builder.Append(('\'*(2*$slashes+1)));$null=$builder.Append('"') }
        else { if ($slashes) {$null=$builder.Append(('\'*$slashes))};$null=$builder.Append($character) }
        $slashes=0
    }
    if ($slashes) {$null=$builder.Append(('\'*(2*$slashes)))}
    $null=$builder.Append('"');return $builder.ToString()
}

function Invoke-DirectoryProcess([string]$Executable,[string[]]$Arguments,[string]$WorkingDirectory,[int]$TimeoutSeconds,[hashtable]$Environment=@{}) {
    $executablePath=Assert-DirectoryPlainPath $Executable
    $working=Assert-DirectoryPlainPath $WorkingDirectory
    if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 900) { throw 'Invalid harness process timeout.' }
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$executablePath;$start.WorkingDirectory=$working
    $start.Arguments=(@($Arguments | ForEach-Object { ConvertTo-DirectoryProcessArgument $_ }) -join ' ')
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    foreach ($key in $Environment.Keys) { $start.EnvironmentVariables[$key]=[string]$Environment[$key] }
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    try {
        if (-not $process.Start()) { throw 'Could not start owned harness process.' }
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        $finished=$process.WaitForExit($TimeoutSeconds*1000)
        if (-not $finished) { $process.Kill();$null=$process.WaitForExit(5000) }
        $code=$null;if ($finished) {$code=$process.ExitCode}
        # A killed child must not make stream draining an unbounded wait.
        $out='';$err=''
        $captured=$true
        try {if ($stdout.Wait(1000)) {$out=$stdout.Result} else {$captured=$false}} catch {$captured=$false}
        try {if ($stderr.Wait(1000)) {$err=$stderr.Result} else {$captured=$false}} catch {$captured=$false}
        return [pscustomobject]@{ExitCode=$code;TimedOut=(-not $finished -or -not $captured);Stdout=$out;Stderr=$err}
    } finally { $process.Dispose() }
}

function Invoke-DirectoryTrustVerification([string]$Executable,[string]$WorkingDirectory,[string]$Partner,[string]$Trusting,[string]$Trusted) {
    Assert-DirectoryDNSName $Partner;Assert-DirectoryDNSName $Trusting;Assert-DirectoryDNSName $Trusted
    if ($Trusting -ieq $Trusted) { throw 'A domain cannot be its own positive trust fixture.' }
    $hash=(Get-FileHash -LiteralPath (Assert-DirectoryPlainPath $Executable) -Algorithm SHA256).Hash
    # Verification only. Never reset, repair, create or remove a trust.
    $result=Invoke-DirectoryProcess $Executable @('trust',$Trusting,"/Domain:$Trusted",'/Verify') $WorkingDirectory 60
    return [ordered]@{partner=$Partner;trusting_domain=$Trusting;trusted_domain=$Trusted;method='netdom trust /verify';exit_code=$result.ExitCode;timed_out=$result.TimedOut;executable_sha256=$hash;timestamp=[DateTime]::UtcNow.ToString('o')}
}

function Add-DirectoryFact([System.Collections.IDictionary]$Facts,[string]$Key,$Values) {
    $key=$Key.ToLowerInvariant();$result=[Collections.Generic.List[string]]::new()
    foreach ($value in @($Values)) {
        if ($null -eq $value -or [string]$value -eq '') { continue }
        $text=[string]$value
        if (-not $key.EndsWith('.binary',[StringComparison]::Ordinal)) {$text=$text.ToLowerInvariant()}
        $result.Add($text)
    }
    $result.Sort([StringComparer]::Ordinal)
    $Facts[$key]=[string[]]$result.ToArray()
}

function ConvertTo-DirectoryBinary($Value) {
    if ($null -eq $Value) {return $null}
    if ($Value -is [guid]) {return [Convert]::ToBase64String($Value.ToByteArray())}
    if ($Value -is [Security.Principal.SecurityIdentifier]) {
        $bytes=New-Object byte[] $Value.BinaryLength;$Value.GetBinaryForm($bytes,0);return [Convert]::ToBase64String($bytes)
    }
    if ($Value -is [byte[]]) {return [Convert]::ToBase64String($Value)}
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        $items=@($Value)
        if (-not $items.Count) {return $null}
        if ($items.Count -eq 1) {return ConvertTo-DirectoryBinary $items[0]}
        if (@($items | Where-Object {$_ -isnot [byte]}).Count -eq 0) {return [Convert]::ToBase64String([byte[]]$items)}
    }
    throw 'Unexpected binary reference type.'
}

function Get-DirectoryTrustPairs([uint32]$Direction,[string]$Source,[string]$Partner) {
    Assert-DirectoryDNSName $Source;Assert-DirectoryDNSName $Partner
    if ($Direction -lt 1 -or $Direction -gt 3 -or $Source -ieq $Partner) {throw 'Invalid positive trust direction or partner.'}
    if ($Direction -band 2) {Write-Output -NoEnumerate @($Source,$Partner)}
    if ($Direction -band 1) {Write-Output -NoEnumerate @($Partner,$Source)}
}

function ConvertTo-DirectoryMask($Value) {
    if ($null -eq $Value) {return $null}
    if ([long]$Value -lt 0) {return [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$Value),0)}
    return [uint32]$Value
}
