#Requires -Version 5.1
# Offline ownership and policy-restoration tests; no AD, Hyper-V or secrets.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$source=Join-Path $PSScriptRoot 'kerberos-fixture.ps1'
$null=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Kerberos fixture helper does not parse.'}
. $source
function Assert-Rejected([scriptblock]$Operation,[string]$Description) {
    $rejected=$false
    try {& $Operation | Out-Null} catch {$rejected=$true}
    if(-not $rejected){throw "Accepted unsafe fixture input: $Description"}
}
function Copy-FixtureValue($Value) {return $Value|ConvertTo-Json -Depth 12|ConvertFrom-Json}
$run='sdk04-offline-ownership'
$names=Get-KerberosFixtureNames $run
if($names.sam.Length -gt 20 -or $names.sam -cne (Get-KerberosFixtureNames $run).sam -or $names.upn -cne ($names.sam+'@AD.SDK.TEST')){throw 'Fixture identity derivation is not stable/bounded.'}
foreach($bad in @('../outside','UPPERCASE','short',('a'*41),"bad`nrun")){Assert-Rejected {Get-KerberosFixtureNames $bad} 'invalid run identity'}
Assert-Rejected {Assert-KerberosFixturePath 'C:\adsdk-kerberos-other\state.json'} 'sibling path prefix'
Assert-Rejected {Assert-KerberosFixturePath 'C:\adsdk-kerberos\..\outside.json'} 'path traversal'
$parentGuid=[guid]::NewGuid();$clientGuid=[guid]::NewGuid()
$script:fixtureState=[pscustomobject]@{schema_version=1;run_id=$run;server='adsdk25dc1.ad.sdk.test';parent_dn=$names.parent_dn;client_dn=$names.client_dn;sam=$names.sam;upn=$names.upn;parent_guid=$parentGuid.ToString();client_guid=$clientGuid.ToString();policy_applied=$true}
$script:fixtureParent=[pscustomobject]@{ObjectClass='organizationalUnit';DistinguishedName=$names.parent_dn;ObjectGUID=$parentGuid;description="sdk-kerberos-parent:$run"}
$script:fixtureClient=[pscustomobject]@{ObjectClass='user';DistinguishedName=$names.client_dn;ObjectGUID=$clientGuid;description="sdk-kerberos-client:$run";sAMAccountName=$names.sam}
Assert-KerberosOwnedObjects $script:fixtureState $script:fixtureParent @($script:fixtureClient)
$changed=Copy-FixtureValue $script:fixtureParent;$changed.ObjectGUID=[guid]::NewGuid().ToString()
Assert-Rejected {Assert-KerberosOwnedObjects $script:fixtureState $changed @($script:fixtureClient)} 'changed parent GUID'
$changed=Copy-FixtureValue $script:fixtureParent;$changed.description='unowned'
Assert-Rejected {Assert-KerberosOwnedObjects $script:fixtureState $changed @($script:fixtureClient)} 'changed parent marker'
$changed=Copy-FixtureValue $script:fixtureClient;$changed.ObjectGUID=[guid]::NewGuid().ToString()
Assert-Rejected {Assert-KerberosOwnedObjects $script:fixtureState $script:fixtureParent @($changed)} 'changed client GUID'
$changed=Copy-FixtureValue $script:fixtureClient;$changed.DistinguishedName='CN=client,DC=ad,DC=sdk,DC=test'
Assert-Rejected {Assert-KerberosOwnedObjects $script:fixtureState $script:fixtureParent @($changed)} 'client outside owned OU'
$changed=Copy-FixtureValue $script:fixtureClient;$changed.ObjectClass='group'
Assert-Rejected {Assert-KerberosOwnedObjects $script:fixtureState $script:fixtureParent @($changed)} 'unowned child class'
Assert-Rejected {Assert-KerberosOwnedObjects $script:fixtureState $script:fixtureParent @($script:fixtureClient,$script:fixtureClient)} 'additional descendants'
$baseline=@(
    [pscustomobject]@{name='LdapEnforceChannelBinding';present=$false;kind=$null;value=$null},
    [pscustomobject]@{name='LDAPServerIntegrity';present=$true;kind='DWord';value=1},
    [pscustomobject]@{name='LDAPServerEnforceIntegrity';present=$false;kind=$null;value=$null}
)
$script:strictSettings=@([pscustomobject]@{name='LdapEnforceChannelBinding';value=2},[pscustomobject]@{name='LDAPServerIntegrity';value=2},[pscustomobject]@{name='LDAPServerEnforceIntegrity';value=1})
$applied=@($script:strictSettings|ForEach-Object {[pscustomobject]@{name=$_.name;present=$true;kind='DWord';value=$_.value}})
Assert-KerberosPolicyTransition $baseline $applied $script:strictSettings
$partial=Copy-FixtureValue $baseline;$partial[0].present=$true;$partial[0].kind='DWord';$partial[0].value=2
Assert-KerberosPolicyTransition $baseline $partial $script:strictSettings
$changed=Copy-FixtureValue $applied;$changed[1].value=0
Assert-Rejected {Assert-KerberosPolicyTransition $baseline $changed $script:strictSettings} 'unrelated policy change'
$changed=Copy-FixtureValue $baseline;$changed[0].name='LDAPServerIntegrity'
Assert-Rejected {Assert-KerberosPolicySnapshot $changed} 'duplicate baseline names'
$changed=Copy-FixtureValue $baseline;$changed[1].kind='QWord'
Assert-Rejected {Assert-KerberosPolicySnapshot $changed} 'changed baseline type'
$changed=Copy-FixtureValue $baseline;$changed[2].value=1
Assert-Rejected {Assert-KerberosPolicySnapshot $changed} 'value on an absent baseline'
$temporaryRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tmp'))
$fixture=[IO.Path]::GetFullPath((Join-Path $temporaryRoot ('kerberos-fixture-test-'+[guid]::NewGuid().ToString('N'))))
if(-not $fixture.StartsWith($temporaryRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Offline fixture escaped tmp root.'}
$null=New-Item -ItemType Directory -Path $fixture
$script:leasePath=Join-Path $fixture 'policy-owner.json'
$script:fixtureState|Add-Member -NotePropertyName policy_baseline -NotePropertyValue $baseline
$script:currentSnapshot=Copy-FixtureValue $applied
$script:policyWrites=0;$script:directoryWrites=0
function Get-KerberosFixtureState {param($RunId,$ExpectedServer);return $script:fixtureState}
function Get-KerberosPolicyLeasePath {return $script:leasePath}
function Get-KerberosPolicySnapshot {return $script:currentSnapshot}
function Get-KerberosDesiredStrictPolicy {return $script:strictSettings}
function Save-KerberosFixtureState {param($State)}
function New-ItemProperty {
    [CmdletBinding()]param($LiteralPath,$Name,$PropertyType,$Value,[switch]$Force)
    $script:policyWrites++
    $item=$script:currentSnapshot|Where-Object {$_.name -ceq $Name}
    $item.present=$true;$item.kind=$PropertyType;$item.value=$Value
}
function Remove-ItemProperty {
    [CmdletBinding()]param($LiteralPath,$Name)
    $script:policyWrites++
    $item=$script:currentSnapshot|Where-Object {$_.name -ceq $Name}
    $item.present=$false;$item.kind=$null;$item.value=$null
}
function Write-TestLease([string]$Identity=$run) {
    @{run_id=$Identity;server=$script:fixtureState.server;parent_guid=$script:fixtureState.parent_guid}|ConvertTo-Json|Set-Content -LiteralPath $script:leasePath -Encoding utf8
}
try {
    Write-TestLease
    $result=Restore-KerberosFixturePolicy $run $script:fixtureState.server
    if(-not $result.verified -or $script:policyWrites -ne 3 -or (Test-Path $script:leasePath)){throw 'Exact owned policy restoration did not complete.'}
    Assert-KerberosPolicyTransition $baseline $script:currentSnapshot @()
    if($script:currentSnapshot[0].present -or $script:currentSnapshot[2].present -or $script:currentSnapshot[1].value -ne 1){throw 'Absent defaults were replaced with disabled values.'}
    $script:policyWrites=0
    $null=Restore-KerberosFixturePolicy $run $script:fixtureState.server
    if($script:policyWrites -ne 0){throw 'Already-restored policy was rewritten.'}
    Write-TestLease 'another-fixture'
    $script:currentSnapshot=Copy-FixtureValue $applied
    Assert-Rejected {Restore-KerberosFixturePolicy $run $script:fixtureState.server} 'another fixture policy lease'
    if($script:policyWrites -ne 0){throw 'A foreign lease caused policy writes.'}
    Write-TestLease
    $script:currentSnapshot[1].value=0
    Assert-Rejected {Restore-KerberosFixturePolicy $run $script:fixtureState.server} 'policy modified outside owned fixture'
    if($script:policyWrites -ne 0){throw 'Unexpected policy state caused restoration writes.'}
    function Get-ADObject {
        [CmdletBinding()]param($Server,$LDAPFilter,$SearchBase,$SearchScope,$Identity,$Properties)
        if($SearchBase){return $script:unownedChild}
        return $script:fixtureParent
    }
    function Remove-ADObject {[CmdletBinding()]param($Server,$Identity,[switch]$Confirm);$script:directoryWrites++}
    function Remove-ADOrganizationalUnit {[CmdletBinding()]param($Server,$Identity,[switch]$Confirm);$script:directoryWrites++}
    $script:unownedChild=Copy-FixtureValue $script:fixtureClient;$script:unownedChild.description='unowned'
    Assert-Rejected {Remove-KerberosDirectoryFixture $run $script:fixtureState.server} 'unowned descendant before any mutation'
    if($script:directoryWrites -ne 0 -or $script:policyWrites -ne 0){throw 'Directory preflight failure caused mutations.'}
    Write-Output 'PASS: Kerberos GUID/marker/path ownership, foreign leases, partial policy application, exact absent-value restoration, and no-write preflight guards.'
} finally {
    $resolved=[IO.Path]::GetFullPath($fixture)
    if(-not $resolved.StartsWith($temporaryRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing unsafe offline cleanup.'}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
