#Requires -Version 7.0
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'kerberos-outer-guards.ps1')
$owner=[pscustomobject]@{schema_version=1;purpose='sdk-kerberos-client';run_id='sdk05-owned-test';profile_id='11111111-1111-4111-8111-111111111111';member_vm_id='22222222-2222-4222-8222-222222222222'}
Assert-KerberosOuterOwner $owner $owner.run_id $owner.profile_id $owner.member_vm_id
foreach($field in @('purpose','run_id','profile_id','member_vm_id')){
    $bad=$owner|ConvertTo-Json|ConvertFrom-Json;$bad.$field='foreign'
    $rejected=$false;try{Assert-KerberosOuterOwner $bad $owner.run_id $owner.profile_id $owner.member_vm_id}catch{$rejected=$true}
    if(-not$rejected){throw 'Foreign owner accepted.'}
}
$expected=@{'client.keytab'=('a'*64);'password.ccache'=('b'*64)}
$actual=@($expected.Keys|ForEach-Object{[pscustomobject]@{name=$_;directory=$false;reparse=$false;sha256=$expected[$_]}})
Assert-KerberosOuterPrivateFiles $actual $expected
foreach($kind in @('digest','directory','reparse','duplicate','missing')){
    $bad=@($actual|ForEach-Object{$_|ConvertTo-Json|ConvertFrom-Json})
    switch($kind){digest{$bad[0].sha256=('c'*64)}directory{$bad[0].directory=$true}reparse{$bad[0].reparse=$true}duplicate{$bad[0].name=$bad[1].name}missing{$bad=@($bad[0])}}
    $rejected=$false;try{Assert-KerberosOuterPrivateFiles $bad $expected}catch{$rejected=$true}
    if(-not$rejected){throw 'Changed private file was accepted.'}
}
Write-Output 'PASS: foreign owner, changed digest, reparse, directory, duplicate and missing-file cleanup guards; no lab access.'
