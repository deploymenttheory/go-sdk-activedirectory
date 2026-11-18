#Requires -Version 7.0
function Assert-KerberosClientFileManifest($Manifest,[string]$RunId) {
    if($RunId -cnotmatch '\A[a-z0-9][a-z0-9-]{5,39}\z' -or $Manifest.run_id -cne $RunId -or -not $Manifest.source_and_host_digests_verified){throw 'Credential transfer identity is not verified.'}
    $names=@('client.keytab','tgt-only.ccache','password.ccache','keytab.ccache','expiry-probe-2m.ccache')
    if(@($Manifest.files).Count -ne $names.Count){throw 'Unexpected credential inventory.'}
    foreach($name in $names){
        $entry=@($Manifest.files|Where-Object name -CEQ $name)
        if($entry.Count -ne 1 -or $entry[0].sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $entry[0].bytes -le 0 -or $entry[0].bytes -gt 16MB){throw 'Unexpected credential name, size or digest.'}
    }
}

function Assert-KerberosClientFilePath([string]$Path,[string]$Root) {
    $full=[IO.Path]::GetFullPath($Path);$rootFull=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    if(-not $full.StartsWith($rootFull+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Client file escaped its owned root.'}
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)){
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Client file crosses a reparse point.'}
    }
    return $full
}
