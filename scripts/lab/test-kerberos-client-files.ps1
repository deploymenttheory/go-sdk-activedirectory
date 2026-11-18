#Requires -Version 7.0
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'kerberos-client-files-core.ps1')
$run='sdk05-offline-transfer'
$files=@('client.keytab','tgt-only.ccache','password.ccache','keytab.ccache','expiry-probe-2m.ccache')|ForEach-Object {[pscustomobject]@{name=$_;sha256=('a'*64);bytes=100}}
$manifest=[pscustomobject]@{run_id=$run;source_and_host_digests_verified=$true;files=$files}
Assert-KerberosClientFileManifest $manifest $run
foreach($mutation in @('digest','duplicate','oversize','foreign-run')){
    $copy=$manifest|ConvertTo-Json -Depth 6|ConvertFrom-Json
    switch($mutation){digest{$copy.files[0].sha256='invalid'}duplicate{$copy.files[0].name=$copy.files[1].name}oversize{$copy.files[0].bytes=16MB+1}foreign-run{$copy.run_id='sdk05-foreign'}}
    $rejected=$false;try{Assert-KerberosClientFileManifest $copy $run}catch{$rejected=$true}
    if(-not $rejected){throw 'Unsafe transfer manifest was accepted.'}
}
$rejected=$false;try{Assert-KerberosClientFilePath 'C:\outside\credential' 'C:\owned'}catch{$rejected=$true}
if(-not $rejected){throw 'Escaped credential path was accepted.'}
Write-Output 'PASS: strict five-file ownership, digest, size, duplicate and path guards; no VM access.'
