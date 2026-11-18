#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'kerberos-sasl-cases.ps1')
$cases=@(Get-KerberosSASLQualificationCases)
if($cases.Count -ne 44 -or @($cases.case_id|Sort-Object -Unique).Count -ne 44){throw 'SASL case matrix is incomplete or ambiguous.'}
foreach($case in $cases) {
    if($case.case_id -cnotmatch '\A[a-z0-9][a-z0-9-]{5,63}\z'){throw 'Unsafe case identity.'}
    foreach($forbidden in @('password','password_base64','credential','username','realm','keytab_path','cache_path','secret')) {
        if($null -ne $case.PSObject.Properties[$forbidden]){throw 'Credential material appeared in a case descriptor.'}
    }
}
foreach($client in @('windows','linux')) {
    foreach($protection in @('sign','seal')) {
        $cell=@($cases|Where-Object {$_.client -ceq $client -and $_.transport -ceq 'ldap' -and $_.protection -ceq $protection})
        foreach($source in @('password','keytab','cache')){if(@($cell|Where-Object {$_.source -ceq $source -and $_.sasl_fault -ceq ''}).Count -ne 1){throw 'A protected credential-source cell is missing.'}}
        foreach($fault in @('pass','tampered','reordered','truncated-prefix','truncated-body')){if(@($cell|Where-Object {$_.sasl_fault -ceq $fault}).Count -ne 1){throw 'A live protected-stream valid control or fault is missing.'}}
    }
    if(@($cases|Where-Object {$_.client -ceq $client -and $_.protection -ceq 'default'}).Count -ne 1){throw 'Plain LDAP default sealing is absent.'}
    if(@($cases|Where-Object {$_.client -ceq $client -and $_.sasl_fault -ceq 'selected-sign'}).Count -ne 1){throw 'Exact selected-layer refusal is absent.'}
    if(@($cases|Where-Object {$_.client -ceq $client -and $_.transport -cne 'ldap' -and $_.expected -ceq 'invalid-config' -and $_.kind -ceq 'public'}).Count -ne 4){throw 'Local AD compatibility refusal cells are absent.'}
}
Write-Output 'PASS: 36 live SASL cases and 8 explicitly local AD compatibility refusals cover both clients.'
