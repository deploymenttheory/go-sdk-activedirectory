#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'kerberos-auth-cases.ps1')
$cases=@(Get-KerberosAuthQualificationCases)
if($cases.Count -ne 40){throw 'Authentication case count changed without reviewing the matrix.'}
$unique=@($cases.case_id | Sort-Object -Unique)
if($unique.Count -ne $cases.Count){throw 'Case identities are not unique.'}
foreach($case in $cases){
    foreach($field in @('case_id','client','kind','source','cache_name','transport','protection','cbt_fault','expected','spn_override','ticket_lifetime_seconds')){
        if($null -eq $case.PSObject.Properties[$field]){throw "Missing nonsecret descriptor field: $field"}
    }
    foreach($forbidden in @('username','realm','password','password_base64','keytab_path','cache_path','ca_file','credential','secret')){
        if($null -ne $case.PSObject.Properties[$forbidden]){throw "Credential material appeared in case descriptors: $forbidden"}
    }
    if($case.client -notin @('windows','linux') -or $case.transport -notin @('ldaps','starttls') -or $case.protection -ne 'none'){throw 'Authentication case selects an unreviewed transport.'}
    if($case.kind -eq 'engine' -and ($case.expected -ne 'cbt-refused' -or $case.cbt_fault -notin @('missing','tampered'))){throw 'CBT fault case has no genuine-refusal assertion.'}
    if($case.expected -eq 'success' -and $case.cbt_fault -ne ''){throw 'Positive authentication contains a fault injection.'}
}
foreach($client in @('windows','linux')){
    foreach($transport in @('ldaps','starttls')){
        $cell=@($cases|Where-Object{$_.client -eq $client -and $_.transport -eq $transport})
        if(@($cell|Where-Object{$_.expected -eq 'success'}).Count -ne 5){throw 'Credential-source positive cell is incomplete.'}
        if(@($cell|Where-Object{$_.expected -eq 'cbt-refused'}).Count -ne 2){throw 'CBT negative cell is incomplete.'}
        if(@($cell|Where-Object{$_.expected -eq 'kerberos-expired'}).Count -ne 1){throw 'Real expired-cache case is absent.'}
        if(@($cell|Where-Object{$_.expected -eq 'invalid-config'}).Count -ne 1){throw 'Explicit wrong-SPN case is absent.'}
        $expiry=@($cell|Where-Object{$_.expected -eq 'service-context-expired'})
        if($expiry.Count -ne 1 -or $expiry[0].kind -ne 'engine-expiry' -or $expiry[0].ticket_lifetime_seconds -ne 10 -or $expiry[0].cache_name -ne 'tgt-only.ccache'){throw 'Actual fresh service-context expiry case is absent.'}
    }
}
Write-Output 'PASS: 40 nonsecret authentication descriptors cover both operating systems, TLS transports and real context expiry.'
