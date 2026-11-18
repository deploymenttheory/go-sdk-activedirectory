#Requires -Version 7.0
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'kerberos-qualification-core.ps1')
. (Join-Path $PSScriptRoot 'kerberos-auth-cases.ps1')
. (Join-Path $PSScriptRoot 'kerberos-sasl-cases.ps1')
function Assert-QualificationRejected([scriptblock]$Action,[string]$Name) {
    $rejected=$false;try{& $Action}catch{$rejected=$true}
    if(-not $rejected){throw "Qualification guard accepted $Name."}
}
$credential=[PSCredential]::new('client@AD.SDK.TEST',(ConvertTo-SecureString 'offline-test-only-credential' -AsPlainText -Force))
$context=@{
    server='adsdk25dc1.ad.sdk.test';sam='client';realm='AD.SDK.TEST';run_id='sdk05-offline-run';source_revision=('a'*40)
    windows_credential_root='C:\owned';linux_credential_root='/home/adsdk/acceptance/mit-sdk05-offline-run'
    windows_ca='C:\owned\root.pem';linux_ca='/home/adsdk/acceptance/root-sdk05-offline-run.pem'
    client_credential=$credential;contact=[pscustomobject]@{contact_dn='CN=probe,OU=sasl,OU=sdk-kerberos-sdk05-offline-run,DC=ad,DC=sdk,DC=test';contact_guid='11111111-1111-4111-8111-111111111111'}
    member_session='offline';linux_script={param($Action,$Command,[byte[]]$InputBytes) throw 'Simulated SSH transport failure.'}
}
$cases=@((Get-KerberosAuthQualificationCases)+(Get-KerberosSASLQualificationCases))
if($cases.Count -ne 84 -or @($cases.case_id|Sort-Object -Unique).Count -ne 84){throw 'The combined case matrix is incomplete.'}
if(@($cases|Where-Object {(Get-KerberosQualificationEvidenceScope $_) -ceq 'live-ad'}).Count -ne 68 -or
    @($cases|Where-Object {(Get-KerberosQualificationEvidenceScope $_) -ceq 'local-config'}).Count -ne 12 -or
    @($cases|Where-Object {(Get-KerberosQualificationEvidenceScope $_) -ceq 'local-credential'}).Count -ne 4){throw 'Local refusals were promoted into live AD evidence.'}
foreach($case in $cases){
    Assert-KerberosQualificationCase $case
    $invocation=Get-KerberosQualificationInvocation $case
    if($invocation.binary -notin @('engine','public')){throw 'Unreviewed binary selection.'}
    $bytes=New-KerberosQualificationInput $context $case '/owned/fresh-result.json'
    try{
        $inputObject=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
        if($inputObject.source_revision -cne $context.source_revision -or $inputObject.run_id -cne $context.run_id){throw 'Input provenance changed.'}
        if($case.transport -ceq 'ldap' -and $inputObject.ca_file -cne ''){throw 'Plain SASL case incorrectly includes TLS trust.'}
        if($case.source -ceq 'password'){
            $actual=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($inputObject.password_base64))
            if($actual -cne $credential.GetNetworkCredential().Password){throw 'Exact stdin password bytes changed.'}
        }
        if($case.kind -ceq 'sasl' -and $inputObject.fixture_guid -cne $context.contact.contact_guid){throw 'Owned contact identity was not supplied.'}
    }finally{[Array]::Clear($bytes,0,$bytes.Length)}
}
$bad=[pscustomobject]@{case_id='../escape';client='linux';source='cache';cache_name='password.ccache';transport='ldap';protection='seal';kind='sasl'}
Assert-QualificationRejected {Assert-KerberosQualificationCase $bad} 'a shell/path case identity'
$valid=@($cases|Where-Object case_id -CEQ 'auth-windows-ldaps-password')[0]
$process=[pscustomobject]@{exit_code=0}
$report=[pscustomobject]@{source_revision=$context.source_revision;run_id=$context.run_id;toolchain='go1.27.4';platform='windows/amd64';success=$true}
Assert-KerberosQualificationResult $context $valid $process $report
$report.source_revision=('b'*40)
Assert-QualificationRejected {Assert-KerberosQualificationResult $context $valid $process $report} 'a mismatched source label'
$digests=@('client.keytab','tgt-only.ccache','password.ccache','keytab.ccache','expiry-probe-2m.ccache')|ForEach-Object {[pscustomobject]@{name=$_;sha256=('a'*64)}}
Assert-KerberosQualificationCredentialDigests $digests $digests
$changed=@($digests|ForEach-Object {[pscustomobject]@{name=$_.name;sha256=$_.sha256}});$changed[0].sha256=('b'*64)
Assert-QualificationRejected {Assert-KerberosQualificationCredentialDigests $digests $changed} 'a modified caller-owned keytab'
Assert-QualificationRejected {Assert-KerberosQualificationCredentialDigests $digests @($digests[0],$digests[0],$digests[2],$digests[3],$digests[4])} 'a duplicated credential inventory entry'
function Invoke-Command {throw 'Simulated Windows process setup failure.'}
$bytes=[byte[]](1,2,3)
Assert-QualificationRejected {Invoke-KerberosQualificationWindows $context 'owned.exe' '' '' $bytes} 'a simulated Windows setup failure'
if(@($bytes|Where-Object {$_ -ne 0}).Count -ne 0){throw 'Windows setup failure retained caller stdin bytes.'}
$bytes=[byte[]](1,2,3)
Assert-QualificationRejected {Invoke-KerberosQualificationLinux $context '/home/adsdk/acceptance/owned-test' '' '' $bytes} 'a simulated SSH setup failure'
if(@($bytes|Where-Object {$_ -ne 0}).Count -ne 0){throw 'SSH setup failure retained caller stdin bytes.'}
Write-Output 'PASS: 84 combined cases, strict source/request mapping and stdin ownership guards; no lab mutation.'
