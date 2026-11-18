#Requires -Version 5.1
# Offline ownership regressions. All directory and filesystem mutations are mocks.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'portable-directory-fixture.ps1')
. (Join-Path $PSScriptRoot 'portable-tls-negative-fixture.ps1')
function Import-Module {}
function Assert-PortableTlsFixtureIdentity {return 'dc1.ad.sdk.test'}
$script:removed=0;$script:created=0;$script:scenario='existing'
$script:fixtureGuid=[guid]'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
function Get-ADObject {
    param($Server,$Identity,$Properties,$LDAPFilter,$SearchBase,$SearchScope,$ErrorAction)
    if($script:scenario -eq 'absent'){return @()}
    if($SearchBase){return [pscustomobject]@{ObjectClass='contact';description='unowned';ObjectGUID=[guid]::NewGuid();DistinguishedName='CN=unowned,OU=sdk-portable-sdk03-fixture,DC=ad,DC=sdk,DC=test'}}
    return [pscustomobject]@{ObjectGUID=$script:fixtureGuid;DistinguishedName='OU=sdk-portable-sdk03-fixture,DC=ad,DC=sdk,DC=test';description=if($script:scenario -eq 'changed'){'changed'}else{'sdk-portable-parent:sdk03-fixture'};ObjectClass='organizationalUnit'}
}
function New-ADOrganizationalUnit {$script:created++;throw 'Unexpected directory creation'}
function Remove-ADObject {$script:removed++}
function Remove-ADOrganizationalUnit {$script:removed++}
function Assert-FixtureThrows([scriptblock]$Action) {
    $failed=$false
    try {& $Action | Out-Null} catch {$failed=$true}
    if(-not $failed){throw 'Expected refusal did not occur.'}
}
Assert-FixtureThrows {Get-PortableDirectoryFixtureDn 'unsafe,ou=other'}
Assert-FixtureThrows {New-PortableDirectoryFixture 'sdk03-fixture' 'dc1.ad.sdk.test'}
if($script:created -ne 0){throw 'Existing fixture name reached create.'}
$script:scenario='changed'
Assert-FixtureThrows {Remove-PortableDirectoryFixture 'sdk03-fixture' 'dc1.ad.sdk.test' $script:fixtureGuid.ToString()}
$script:scenario='children'
Assert-FixtureThrows {Remove-PortableDirectoryFixture 'sdk03-fixture' 'dc1.ad.sdk.test' $script:fixtureGuid.ToString()}
if($script:removed -ne 0){throw 'Changed ownership or unowned child reached a delete.'}
$script:scenario='absent'
$absent=Remove-PortableDirectoryFixture 'sdk03-fixture' 'dc1.ad.sdk.test' ''
if(-not $absent.verified -or $script:removed -ne 0){throw 'Lost-response reconciliation did not confirm absence without a mutation.'}
# A lexical path inside the owned root is still refused if any parent is a junction.
function Test-Path {return $true}
function Get-Item {return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint}}
Assert-FixtureThrows {Assert-PortableTlsPeerRoot 'sdk03-fixture' 'C:\adsdk-qualification\sdk03-fixture'}
Assert-FixtureThrows {Assert-PortableTlsPeerRoot 'sdk03-fixture' 'C:\unowned'}
'PASS: fixture creation, GUID/marker ownership, unowned descendants, lost-response absence and reparse-point refusal'
