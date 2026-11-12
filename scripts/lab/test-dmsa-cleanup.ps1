#Requires -Version 5.1
# Execute the actual cleanup helper against mocks, with no live directory.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'dmsa-capture.ps1')

foreach($case in @('success','lost-create-response','foreign-object','lookup-fails','delete-fails')) {
    $attempts=[Collections.Generic.List[string]]::new()
    $first=[guid]'11111111-1111-1111-1111-111111111111'
    $second=[guid]'22222222-2222-2222-2222-222222222222'
    $ledger=@(
        [pscustomobject]@{guid=$first.ToString();dn='CN=first,OU=fixture,DC=test';class='user'},
        [pscustomobject]@{guid=$second.ToString();dn='OU=fixture,DC=test';class='organizationalUnit'}
    )
    if($case -eq 'lost-create-response') {$ledger[0].guid=''}
    function Get-ADObject($Identity,$Server,$Properties,$ErrorAction) {
        $isFirst=($Identity -eq $first -or $Identity -eq $ledger[0].dn)
        if($case -eq 'lookup-fails' -and $isFirst) {throw [InvalidOperationException]::new('Synthetic lookup failure.')}
        $index=if($isFirst){0}else{1}
        $marker=if($case -eq 'foreign-object' -and $isFirst){'foreign'}else{'owned'}
        [pscustomobject]@{ObjectGUID=$(if($isFirst){$first}else{$second});DistinguishedName=$ledger[$index].dn;ObjectClass=$ledger[$index].class;Description=$marker}
    }
    function Remove-ADObject($Identity,$Server,$Confirm,$ErrorAction) {
        $attempts.Add($Identity.ToString())
        if($case -eq 'delete-fails' -and $Identity -eq $first) {throw [InvalidOperationException]::new('Synthetic deletion failure.')}
    }
    $failure=$null
    try {Remove-DmsaOwnedFixtures $ledger 'owned' 'synthetic-dc'} catch {$failure=$_.Exception}
    if(-not $attempts.Contains($second.ToString())) {throw "$case skipped independent cleanup."}
    if($case -in @('success','lost-create-response')) {
        if($failure -or $attempts.Count -ne 2) {throw "$case did not remove both owned objects."}
    } else {
        if($null -eq $failure -or $failure.InnerExceptions.Count -ne 1) {throw "$case lost its cleanup failure."}
    }
    if($case -in @('foreign-object','lookup-fails') -and $attempts.Contains($first.ToString())) {throw "$case attempted an unverified deletion."}
    Write-Output "$case`: passed"
}
'DMSA cleanup offline regressions passed; no migration was executed.'
