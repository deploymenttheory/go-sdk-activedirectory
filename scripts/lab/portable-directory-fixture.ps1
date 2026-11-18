#Requires -Version 5.1
# Functions only. Run on the verified owned DC through PowerShell Direct.

function Get-PortableDirectoryFixtureDn([string]$RunId) {
    if ($RunId -cnotmatch '\A[a-z0-9][a-z0-9-]{5,47}\z') {throw 'Invalid directory fixture identity.'}
    return "OU=sdk-portable-$RunId,DC=ad,DC=sdk,DC=test"
}

function New-PortableDirectoryFixture([string]$RunId,[string]$ExpectedServer) {
    Import-Module ActiveDirectory
    $server=Assert-PortableTlsFixtureIdentity $RunId $ExpectedServer
    $dn=Get-PortableDirectoryFixtureDn $RunId
    $existing=@(Get-ADObject -Server $server -LDAPFilter "(distinguishedName=$dn)" -ErrorAction Stop)
    if ($existing.Count -ne 0) {throw 'Directory fixture must have a fresh distinguished name.'}
    $parent=New-ADOrganizationalUnit -Server $server -Name "sdk-portable-$RunId" -Path 'DC=ad,DC=sdk,DC=test' -Description "sdk-portable-parent:$RunId" -ProtectedFromAccidentalDeletion $false -PassThru -ErrorAction Stop
    $verified=Get-ADObject -Server $server -Identity $parent.ObjectGUID -Properties description -ErrorAction Stop
    if ($verified.DistinguishedName -cne $dn -or $verified.description -cne "sdk-portable-parent:$RunId" -or $verified.ObjectClass -cne 'organizationalUnit') {
        throw 'Independent directory fixture ownership verification failed.'
    }
    return [pscustomobject]@{run_id=$RunId;dn=$dn;guid=$parent.ObjectGUID.ToString();marker="sdk-portable-parent:$RunId";server=$server}
}

function Remove-PortableDirectoryFixture([string]$RunId,[string]$ExpectedServer,[string]$ExpectedGuid) {
    Import-Module ActiveDirectory
    $server=Assert-PortableTlsFixtureIdentity $RunId $ExpectedServer
    $dn=Get-PortableDirectoryFixtureDn $RunId
    if ($ExpectedGuid) {
        $guid=[guid]$ExpectedGuid
        $parent=Get-ADObject -Server $server -Identity $guid -Properties description -ErrorAction Stop
    } else {
        # Recover only this fresh marker and exact DN if the outer session lost
        # the create response. Inspect actual state before any cleanup write.
        $found=@(Get-ADObject -Server $server -LDAPFilter "(distinguishedName=$dn)" -Properties description -ErrorAction Stop)
        if($found.Count -eq 0){return [pscustomobject]@{run_id=$RunId;parent_dn=$dn;live_owned_objects_remaining=0;verified=$true;never_created_or_already_absent=$true}}
        if($found.Count -ne 1){throw 'Ambiguous fixture parent during reconciliation.'}
        $parent=$found[0];$guid=$parent.ObjectGUID
    }
    if ($parent.DistinguishedName -cne $dn -or $parent.description -cne "sdk-portable-parent:$RunId" -or $parent.ObjectClass -cne 'organizationalUnit') {
        throw 'Refusing cleanup of a directory fixture with changed ownership.'
    }
    $removed=@()
    # Reconcile actual state after the client stops. Never infer that a submitted
    # mutation failed, or repeat the client mutation after a lost response.
    foreach ($child in @(Get-ADObject -Server $server -SearchBase $dn -SearchScope OneLevel -LDAPFilter '(objectClass=*)' -Properties description -ErrorAction Stop)) {
        if ($child.ObjectClass -cne 'contact' -or $child.description -cne "sdk-portable-owned:$RunId") {
            throw 'An unowned directory object prevents fixture cleanup.'
        }
        $childGuid=$child.ObjectGUID
        Remove-ADObject -Server $server -Identity $childGuid -Confirm:$false -ErrorAction Stop
        $removed+=@{guid=$childGuid.ToString();dn=$child.DistinguishedName}
    }
    $remaining=@(Get-ADObject -Server $server -SearchBase $dn -SearchScope Subtree -LDAPFilter '(objectClass=*)' -ErrorAction Stop | Where-Object {$_.ObjectGUID -ne $guid})
    if ($remaining.Count -ne 0) {throw 'Live fixture descendants remain after independent reconciliation.'}
    Remove-ADOrganizationalUnit -Server $server -Identity $guid -Confirm:$false -ErrorAction Stop
    $hex=($guid.ToByteArray() | ForEach-Object {'\'+$_.ToString('x2')}) -join ''
    $live=@(Get-ADObject -Server $server -LDAPFilter "(objectGUID=$hex)" -ErrorAction Stop)
    if ($live.Count -ne 0) {throw 'Owned fixture parent remains live after removal.'}
    return [pscustomobject]@{
        run_id=$RunId;parent_guid=$guid.ToString();parent_dn=$dn;live_owned_objects_remaining=0
        reconciled_contacts=$removed;tombstones_retained=$true;verified=$true;verified_utc=[DateTime]::UtcNow.ToString('o')
    }
}
