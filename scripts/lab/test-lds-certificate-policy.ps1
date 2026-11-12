#Requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'lds-certificate-policy.ps1')
$script:checks=0
function Assert-Policy([bool]$Condition,[string]$Name) {
    if(-not $Condition){throw "Certificate policy regression: $Name"}
    $script:checks++
}

# Public XML captured from the real DC2 CAPI2 log. Result message text is
# deliberately present in mutations below to prove it never enters output.
$eventXML=@'
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-CAPI2' Guid='{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}'/><EventID>30</EventID><Version>0</Version><Level>4</Level><Task>30</Task><Opcode>0</Opcode><Keywords>0x4000000000000001</Keywords><TimeCreated SystemTime='2026-11-12T16:49:23.2648695Z'/><EventRecordID>124</EventRecordID><Correlation ActivityID='{bb2e5a9d-72b7-0000-805b-2ebbb772dd01}'/><Execution ProcessID='768' ThreadID='1164'/><Channel>Microsoft-Windows-CAPI2/Operational</Channel><Computer>ADSDK25DC2.ad.sdk.test</Computer><Security UserID='S-1-5-21-4110171594-518791390-1835339366-500'/></System><UserData><CertVerifyCertificateChainPolicy><Policy type='CERT_CHAIN_POLICY_SSL' constant='4'/><Certificate fileRef='4E48A8BE066D77BA183160D42E994DCA4C09F243.cer' subjectName='AD SDK TLS fixture valid'/><CertificateChain chainRef='{E1FC79F8-486B-4331-BCED-1BE80E703B97}'/><Flags value='0'/><SSLAdditionalPolicyInfo authType='server' serverName='ADSDK25MEM.ad.sdk.test'><IgnoreFlags value='0'/></SSLAdditionalPolicyInfo><Status chainIndex='-1' elementIndex='-1'/><EventAuxInfo ProcessName='lsass.exe' impersonateToken='S-1-5-21-4110171594-518791390-1835339366-500'/><CorrelationAuxInfo TaskId='{E98FF166-8E34-4696-BBE6-B702BE1BC704}' SeqNumber='1'/><Result value='0'/></CertVerifyCertificateChainPolicy></UserData></Event>
'@
$sid='S-1-5-21-4110171594-518791390-1835339366-500'
$thumbprint='4E48A8BE066D77BA183160D42E994DCA4C09F243'
$sha256='a1b2c3d4'*8
$capture=[pscustomobject]@{LSASSPID=768;OwnerSID=$sid}
$window=[pscustomobject]@{StartRecordID=[long]120;EndRecordID=[long]130;StartedUTC=[DateTime]::Parse('2026-11-12T16:49:23Z').ToUniversalTime();EndedUTC=[DateTime]::Parse('2026-11-12T16:49:24Z').ToUniversalTime();RequestProcessID=999;RequestProcessStartedUTC='2026-11-12T16:49:22Z'}
function Test-XMLProof([string[]]$Events,[uint32]$Expected=0) {
    Test-LDSCertificatePolicyEvents -Events $Events -Capture $capture -Window $window -Thumbprint $thumbprint -SHA256 $sha256 -ServerName 'ADSDK25MEM.ad.sdk.test' -ExpectedResult $Expected
}
$proof=Test-XMLProof @($eventXML)
Assert-Policy $proof.passed 'actual Windows SSL policy event accepted'
$serialized=$proof | ConvertTo-Json -Depth 8
$roundtrip=$serialized | ConvertFrom-Json
Assert-Policy ($roundtrip.result -is [string] -and $roundtrip.result -ceq '0' -and $roundtrip.expected_result -ceq '0') 'result is normalized hexadecimal text'
Assert-Policy ($roundtrip.certificate_thumbprint -ceq $thumbprint -and $roundtrip.certificate_sha256 -ceq $sha256 -and $roundtrip.server_name -ceq 'adsdk25mem.ad.sdk.test') 'public certificate mapping and hostname serialization'
Assert-Policy ($roundtrip.lsass_pid -eq 768 -and $roundtrip.request_process_id -eq 999 -and $roundtrip.impersonated_sid -ceq $sid) 'request process is separate from LSASS emitter'
Assert-Policy (-not $serialized.Contains('subjectName') -and -not $serialized.Contains('AD SDK TLS fixture valid')) 'certificate subjects are excluded'

foreach($entry in @(@('valid','0'),@('expired','800B0101'),@('wrong-host','800B010F'),@('untrusted','800B0109'))) {
    foreach($transport in @('ldaps','starttls')) {
        $expected=Get-LDSCertificatePolicyResult "$($entry[0])-$transport"
        $xml=$eventXML.Replace("<Result value='0'/>","<Result value='$($entry[1])'>PRIVATE LOCALIZED MESSAGE</Result>")
        $proof=Test-XMLProof @($xml) $expected
        Assert-Policy ($proof.passed -and $proof.result -ceq $entry[1]) "$($entry[0]) $transport policy status"
        Assert-Policy (-not ($proof | ConvertTo-Json).Contains('PRIVATE LOCALIZED MESSAGE')) 'event message excluded'
    }
}
$mutations=@(
    @('request PID cannot substitute for LSASS',"ProcessID='768'","ProcessID='999'",'missing_event'),
    @('wrong emitter name',"ProcessName='lsass.exe'","ProcessName='powershell.exe'",'missing_event'),
    @('wrong event security SID',"UserID='$sid'","UserID='S-1-5-18'",'missing_event'),
    @('wrong impersonated SID',"impersonateToken='$sid'","impersonateToken='S-1-5-18'",'missing_event'),
    @('wrong certificate',"$thumbprint.cer",('F'*40+'.cer'),'missing_event'),
    @('wrong server name',"serverName='ADSDK25MEM.ad.sdk.test'","serverName='other.ad.sdk.test'",'missing_event'),
    @('before time window','16:49:23.2648695Z','16:49:22.9999999Z','missing_event'),
    @('after time window','16:49:23.2648695Z','16:49:24.0000001Z','missing_event'),
    @('start record excluded','<EventRecordID>124','<EventRecordID>120','missing_event'),
    @('beyond end record','<EventRecordID>124','<EventRecordID>131','missing_event'),
    @('wrong provider',"Name='Microsoft-Windows-CAPI2'","Name='other'",'missing_event'),
    @('wrong event ID','<EventID>30','<EventID>11','missing_event'),
    @('wrong policy type',"type='CERT_CHAIN_POLICY_SSL'","type='CERT_CHAIN_POLICY_BASE'",'unexpected_policy'),
    @('wrong policy constant',"constant='4'","constant='1'",'unexpected_policy'),
    @('nonzero flags',"<Flags value='0'","<Flags value='80'",'unexpected_policy'),
    @('nonzero ignore flags',"<IgnoreFlags value='0'","<IgnoreFlags value='1000'",'unexpected_policy'),
    @('client auth policy',"authType='server'","authType='client'",'unexpected_policy'),
    @('unexpected failure',"<Result value='0'","<Result value='800B010F'",'unexpected_policy'),
    @('malformed result',"<Result value='0'","<Result value='not-a-number'",'invalid_event'),
    @('missing flags',"<Flags value='0'/>",'','invalid_event')
)
foreach($mutation in $mutations) {
    $proof=Test-XMLProof @($eventXML.Replace($mutation[1],$mutation[2]))
    Assert-Policy (-not $proof.passed -and $proof.inconclusive_reason -ceq $mutation[3]) $mutation[0]
}
$proof=Test-XMLProof @()
Assert-Policy (-not $proof.passed -and $proof.inconclusive_reason -ceq 'missing_event') 'missing event fails inconclusively'
$proof=Test-XMLProof @($eventXML,$eventXML.Replace('<EventRecordID>124','<EventRecordID>125'))
Assert-Policy (-not $proof.passed -and $proof.matching_event_count -eq 2 -and $proof.inconclusive_reason -ceq 'ambiguous_events') 'duplicate successful events are ambiguous'
$contradictory=$eventXML.Replace('<EventRecordID>124','<EventRecordID>125').Replace("<Result value='0'","<Result value='800B0109'")
$proof=Test-XMLProof @($eventXML,$contradictory)
Assert-Policy (-not $proof.passed -and $proof.matching_event_count -eq 2 -and $proof.inconclusive_reason -ceq 'ambiguous_events') 'success plus failure remains ambiguous before status filtering'
$proof=Test-XMLProof @($eventXML,$eventXML.Replace("<Flags value='0'","<Flags value='80'"))
Assert-Policy (-not $proof.passed -and $proof.matching_event_count -eq 2) 'flags do not hide a contradictory event'
$proof=Test-XMLProof @($eventXML,$eventXML.Replace("ProcessID='768'","ProcessID='999'"))
Assert-Policy $proof.passed 'unrelated request PID event does not pollute LSASS evidence'
$proof=Test-XMLProof @('<broken')
Assert-Policy (-not $proof.passed -and $proof.inconclusive_reason -ceq 'invalid_event') 'malformed XML fails closed'
$proof=Test-XMLProof @('<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///missing">]>'+$eventXML)
Assert-Policy (-not $proof.passed -and $proof.inconclusive_reason -ceq 'invalid_event') 'DTD prohibited'
$proof=Test-XMLProof @('x'*65537)
Assert-Policy (-not $proof.passed -and $proof.inconclusive_reason -ceq 'invalid_event') 'XML size bounded'
$proof=Test-XMLProof (@($eventXML)*257)
Assert-Policy (-not $proof.passed -and $proof.inconclusive_reason -ceq 'event_limit') 'event count bounded'
$window.EndRecordID=119
$proof=Test-XMLProof @($eventXML)
Assert-Policy (-not $proof.passed -and $proof.inconclusive_reason -ceq 'invalid_window') 'event log reset detected'
$window.EndRecordID=130
$proof=Test-XMLProof @($eventXML.Replace('<EventRecordID>124','<EventRecordID>130').Replace('16:49:23.2648695Z','16:49:24.0000000Z'))
Assert-Policy $proof.passed 'closed upper time and record bounds'

# Exercise actual enable/restore functions without touching the machine log.
function Get-LDSCAPIEnabled {if($null -ne $script:fakeLog.Readback){return $script:fakeLog.Readback};return $script:fakeLog.Enabled}
function New-FakeCapture([bool]$Enabled,[int]$FailAt=0) {
    $script:fakeLog=[pscustomobject]@{Enabled=$Enabled;Saves=0;FailAt=$FailAt;Readback=$null}
    $configuration=[pscustomobject]@{IsEnabled=$Enabled;Disposed=$false}
    $configuration | Add-Member ScriptMethod SaveChanges {
        $script:fakeLog.Saves++
        # Model a partial write followed by failure, which still needs restore.
        $script:fakeLog.Enabled=$this.IsEnabled
        if($script:fakeLog.Saves -eq $script:fakeLog.FailAt){throw 'Simulated event-log write failure.'}
    }
    $configuration | Add-Member ScriptMethod Dispose {$this.Disposed=$true}
    [pscustomobject]@{Configuration=$configuration;OriginalEnabled=$Enabled;LSASSPID=768;OwnerSID=$sid}
}
foreach($original in @($false,$true)) {
    $state=New-FakeCapture $original
    Enable-LDSCertificatePolicyCapture $state
    Assert-Policy $script:fakeLog.Enabled 'logging enabled before operation'
    $restored=Restore-LDSCertificatePolicyCapture $state
    Assert-Policy ($restored -and $script:fakeLog.Enabled -eq $original -and $state.Configuration.Disposed) 'original logging state restored and configuration disposed'
}
$state=New-FakeCapture $false 1
$failed=$false
try {Enable-LDSCertificatePolicyCapture $state} catch {$failed=$true}
$restored=Restore-LDSCertificatePolicyCapture $state
Assert-Policy ($failed -and $restored -and -not $script:fakeLog.Enabled -and $state.Configuration.Disposed) 'partial enable failure still restores original disabled state'
$state=New-FakeCapture $false 2
Enable-LDSCertificatePolicyCapture $state
$failed=$false
try {$null=Restore-LDSCertificatePolicyCapture $state} catch {$failed=$true}
Assert-Policy ($failed -and $state.Configuration.Disposed) 'restore write failure cannot report restoration'
$state=New-FakeCapture $false
Enable-LDSCertificatePolicyCapture $state
$script:fakeLog.Readback=$true
$failed=$false
try {$null=Restore-LDSCertificatePolicyCapture $state} catch {$failed=$true}
Assert-Policy ($failed -and $state.Configuration.Disposed) 'restore readback mismatch cannot report restoration'

# Exercise the closed-window orchestration and settle/query order with wrappers.
$script:trace=[Collections.Generic.List[string]]::new()
function Get-LDSCAPICursor {$script:trace.Add('cursor');return [long]130}
function Start-Sleep([int]$Milliseconds) {$script:trace.Add("settle:$Milliseconds")}
function Get-LDSCAPIEvents([long]$StartRecord,[long]$EndRecord) {
    $script:trace.Add("query:${StartRecord}:$EndRecord")
    Assert-Policy ($null -ne $liveWindow.EndedUTC -and $liveWindow.EndRecordID -eq 130) 'window closed before event query'
    $eventXML.Replace('2026-11-12T16:49:23.2648695Z',$liveWindow.StartedUTC.ToString('o'))
}
$liveWindow=[pscustomobject]@{StartRecordID=[long]120;EndRecordID=$null;StartedUTC=[DateTime]::UtcNow.AddSeconds(-1);EndedUTC=$null;RequestProcessID=999;RequestProcessStartedUTC=$null}
$case=[pscustomobject]@{name='valid-ldaps';certificate_thumbprint=$thumbprint;certificate_sha256=$sha256}
$proof=Complete-LDSCertificatePolicyWindow $capture $liveWindow $case 'ADSDK25MEM.ad.sdk.test'
Assert-Policy ($proof.passed -and ($script:trace -join ',') -ceq 'settle:2000,cursor,query:120:130') 'complete waits then closes record window before collecting all events'

Write-Host "Passed $script:checks CAPI2 certificate-policy assertions. No event-log or VM changes."
