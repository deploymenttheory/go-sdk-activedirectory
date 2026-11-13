[CmdletBinding()]
param()
# Offline contract test. All directory/module/system commands below are mocks.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$global:objectSyncCollectorTestState = @{ SyncCalls=0; GUID=[guid]'00112233-4455-6677-8899-aabbccddeeff'; ObjectDN='CN=Fixture,DC=example,DC=test' }


function Import-Module { param($Name,$ErrorAction) }
function Get-Module { param($Name) [pscustomobject]@{ Version=[version]'1.0.1.0' } }
function Get-CimInstance { param($ClassName,$ErrorAction) [pscustomobject]@{ Caption='mock'; Version='1'; BuildNumber='1' } }
function Get-ADRootDSE {
    param($Server,$ErrorAction)
    [pscustomobject]@{ dsServiceName='CN=NTDS Settings,CN=Server'; serverName='CN=Server'; dnsHostName=$Server; namingContexts=@('DC=example,DC=test') }
}
function Get-ADObject {
    param($Server,$Partition,$Identity,$Properties,$ErrorAction)
    switch ($Identity) {
        'CN=NTDS Settings,CN=Server' { [pscustomobject]@{'msDS-Behavior-Version'=10}; break }
        'CN=Server' { [pscustomobject]@{serverReference='CN=DC,DC=example,DC=test'}; break }
        'CN=DC,DC=example,DC=test' { [pscustomobject]@{operatingSystem='mock';operatingSystemVersion='1';'msDS-RevealedList'=@('S:10:unicodePwd:'+$global:objectSyncCollectorTestState.ObjectDN)}; break }
        default {
            if ($Identity -ne $global:objectSyncCollectorTestState.ObjectDN) { throw 'Incorrect fixture DN (including marker parsing).' }
            [pscustomobject]@{DistinguishedName=$global:objectSyncCollectorTestState.ObjectDN;ObjectGUID=$global:objectSyncCollectorTestState.GUID;description=@('one','two');displayName='fixture'}
        }
    }
}
function Sync-ADObject {
    param($Source,$Destination,$Object,[switch]$PasswordOnly,$ErrorAction)
    if ($Source -ne 'dc1.example.test:389' -or $Destination -ne 'dc2.example.test:389' -or $Object -ne $global:objectSyncCollectorTestState.ObjectDN) { throw 'Wrong reference target.' }
    $global:objectSyncCollectorTestState.SyncCalls++
}
$directory = Join-Path ([IO.Path]::GetTempPath()) ('object-sync-contract-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($directory) | Out-Null
try {
    foreach ($mode in @('observe','apply','password')) {
        $path = Join-Path $directory ($mode+'.json')
        $arguments = @{SourceHost='dc1.example.test';SourcePort=389;DestinationHost='dc2.example.test';DestinationPort=389;Partition='DC=example,DC=test';ObjectDN=$global:objectSyncCollectorTestState.ObjectDN;Revision=('a'*40);RunID='offline';OutputPath=$path}
        if ($mode -ne 'observe') { $arguments.ApplyReferenceSync=$true }
        if ($mode -eq 'password') { $arguments.PasswordOnly=$true }
        & (Join-Path $PSScriptRoot 'collect-object-sync.ps1') @arguments
        $proof = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($proof.destination_after.guid -ne [Convert]::ToBase64String($global:objectSyncCollectorTestState.GUID.ToByteArray())) { throw 'GUID byte order changed.' }
        if ($mode -eq 'observe' -and ($proof.applied -or $global:objectSyncCollectorTestState.SyncCalls -ne 0)) { throw 'Read-only collector wrote.' }
        if ($mode -eq 'password' -and -not $proof.secret_cache_observed) { throw 'Cache marker was not observed.' }
        if ($mode -ne 'password' -and @($proof.destination_after.attributes.description).Count -ne 2) { throw 'Multivalue projection truncated.' }
        try { & (Join-Path $PSScriptRoot 'collect-object-sync.ps1') @arguments; throw 'Overwrite accepted.' } catch { if ($_.Exception.Message -eq 'Overwrite accepted.') { throw } }
    }
    if ($global:objectSyncCollectorTestState.SyncCalls -ne 2) { throw 'Reference write repeated.' }
    'Object-sync collector offline contract passed.'
} finally {
    # Only remove explicitly named files in the uniquely owned temp directory.
    foreach ($name in @('observe.json','apply.json','password.json')) {
        $path = Join-Path $directory $name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    [IO.Directory]::Delete($directory)
    Remove-Variable -Name objectSyncCollectorTestState -Scope Global
}
