#Requires -Version 5.1
# Lab-only CAPI2 evidence. Loading this file does not change event logging.
# Windows performs WinLDAP certificate checks in LSASS; the requesting client
# PID is context, not the emitter PID. No event messages or certificate subjects
# are copied into the public proof.

function New-LDSCAPIConfiguration {
    [Diagnostics.Eventing.Reader.EventLogConfiguration]::new('Microsoft-Windows-CAPI2/Operational')
}
function Get-LDSCAPIEnabled {
    $configuration=New-LDSCAPIConfiguration
    try {return [bool]$configuration.IsEnabled} finally {$configuration.Dispose()}
}
function Get-LDSCAPICursor {
    $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Microsoft-Windows-CAPI2/Operational',[Diagnostics.Eventing.Reader.PathType]::LogName,'*')
    $query.ReverseDirection=$true
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    $record=$null
    try {
        $record=$reader.ReadEvent([TimeSpan]::FromSeconds(1))
        if($null -eq $record){return [long]0}
        return [long]$record.RecordId
    } finally {if($record){$record.Dispose()};$reader.Dispose()}
}
function Get-LDSCAPIEvents([long]$StartRecord,[long]$EndRecord) {
    if($StartRecord -lt 0 -or $EndRecord -lt $StartRecord){throw 'Invalid CAPI2 record window.'}
    $filter="*[System[(EventID=30) and (EventRecordID > $StartRecord) and (EventRecordID <= $EndRecord)]]"
    $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new('Microsoft-Windows-CAPI2/Operational',[Diagnostics.Eventing.Reader.PathType]::LogName,$filter)
    $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query)
    $deadline=[Diagnostics.Stopwatch]::StartNew()
    $events=[Collections.Generic.List[string]]::new()
    try {
        while($true) {
            if($deadline.Elapsed.TotalSeconds -gt 5){throw 'CAPI2 query exceeded its deadline.'}
            $record=$reader.ReadEvent([TimeSpan]::FromSeconds(1))
            if($null -eq $record){break}
            try {
                if($events.Count -ge 256){throw 'CAPI2 query exceeded its record bound.'}
                $xml=$record.ToXml()
                if($xml.Length -gt 65536){throw 'CAPI2 event exceeded its size bound.'}
                $events.Add($xml)
            } finally {$record.Dispose()}
        }
        return $events.ToArray()
    } finally {$reader.Dispose();$deadline.Stop()}
}
function New-LDSCertificatePolicyCapture([string]$OwnerSID) {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if($identity.User.Value -cne $OwnerSID){throw 'CAPI2 capture identity differs.'}
    } finally {$identity.Dispose()}
    $processes=@(Get-Process -Name lsass -ErrorAction Stop)
    try {
        if($processes.Count -ne 1 -or $processes[0].ProcessName -ine 'lsass' -or $processes[0].Id -le 0){throw 'CAPI2 emitter identity is ambiguous.'}
        $emitterID=[int]$processes[0].Id
    } finally {foreach($item in $processes){$item.Dispose()}}
    $configuration=New-LDSCAPIConfiguration
    try {
        return [pscustomobject]@{Configuration=$configuration;OriginalEnabled=[bool]$configuration.IsEnabled;LSASSPID=$emitterID;OwnerSID=$OwnerSID}
    } catch {$configuration.Dispose();throw}
}
function Enable-LDSCertificatePolicyCapture($Capture) {
    $Capture.Configuration.IsEnabled=$true
    $Capture.Configuration.SaveChanges()
    if(-not (Get-LDSCAPIEnabled)){throw 'CAPI2 logging was not enabled.'}
}
function Restore-LDSCertificatePolicyCapture($Capture) {
    try {
        # Always write the saved setting, including when enable failed midway.
        $Capture.Configuration.IsEnabled=$Capture.OriginalEnabled
        $Capture.Configuration.SaveChanges()
        if((Get-LDSCAPIEnabled) -ne $Capture.OriginalEnabled){throw 'CAPI2 logging restoration differs.'}
        return $true
    } finally {$Capture.Configuration.Dispose()}
}
function Start-LDSCertificatePolicyWindow {
    $record=Get-LDSCAPICursor
    [pscustomobject]@{StartRecordID=$record;StartedUTC=[DateTime]::UtcNow;EndRecordID=$null;EndedUTC=$null;RequestProcessID=$null;RequestProcessStartedUTC=$null}
}
function Get-LDSCertificatePolicyResult([string]$CaseName) {
    switch -Regex ($CaseName) {
        '^valid-(ldaps|starttls)$' {return [uint32]0}
        '^expired-(ldaps|starttls)$' {return [Convert]::ToUInt32('800B0101',16)}
        '^wrong-host-(ldaps|starttls)$' {return [Convert]::ToUInt32('800B010F',16)}
        '^untrusted-(ldaps|starttls)$' {return [Convert]::ToUInt32('800B0109',16)}
        default {throw 'Unexpected certificate policy case.'}
    }
}
function Get-LDSCAPIValue($Node,[string]$XPath,$Namespaces,[string]$Attribute='') {
    $selected=$Node.SelectSingleNode($XPath,$Namespaces)
    if($null -eq $selected){return $null}
    if($Attribute -ne ''){return $selected.GetAttribute($Attribute)}
    return $selected.InnerText
}
function ConvertFrom-LDSCAPIHex([string]$Value) {
    if($Value -cnotmatch '^(0x)?[0-9A-Fa-f]{1,8}$'){throw 'Invalid CAPI2 numeric field.'}
    [Convert]::ToUInt32(($Value -replace '^0x',''),16)
}
function Test-LDSCertificatePolicyEvents {
    param([string[]]$Events,$Capture,$Window,[string]$Thumbprint,[string]$SHA256,[string]$ServerName,[uint32]$ExpectedResult)
    if($Thumbprint -notmatch '^[0-9a-f]{40}$' -or $SHA256 -notmatch '^[0-9a-f]{64}$' -or $ServerName -ine 'ADSDK25MEM.ad.sdk.test'){throw 'Invalid certificate policy expectation.'}
    $proof=[ordered]@{
        passed=$false;result=$null;expected_result=$ExpectedResult.ToString('X')
        certificate_thumbprint=$null;certificate_sha256=$null
        certificate_sha256_source='case_manifest_matched_thumbprint';server_name=$null
        lsass_pid=$Capture.LSASSPID;impersonated_sid=$Capture.OwnerSID
        started_utc=$Window.StartedUTC.ToUniversalTime().ToString('o');ended_utc=$Window.EndedUTC.ToUniversalTime().ToString('o')
        start_record_id=$Window.StartRecordID;end_record_id=$Window.EndRecordID
        matching_event_count=0;event_record_id=$null;event_time_utc=$null
        policy_constant=$null;flags=$null;ignore_flags=$null;auth_type=$null;emitter_process_name=$null
        request_process_id=$Window.RequestProcessID;request_process_started_utc=$Window.RequestProcessStartedUTC
        inconclusive_reason=$null
    }
    if($Window.EndRecordID -lt $Window.StartRecordID -or $Window.EndedUTC -lt $Window.StartedUTC){$proof.inconclusive_reason='invalid_window';return [pscustomobject]$proof}
    if(@($Events).Count -gt 256){$proof.inconclusive_reason='event_limit';return [pscustomobject]$proof}
    $matches=[Collections.Generic.List[object]]::new()
    try {
        foreach($eventXML in $Events) {
            if($eventXML.Length -gt 65536){throw 'CAPI2 event exceeded its size bound.'}
            $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=65536
            $xmlTextReader=[IO.StringReader]::new($eventXML);$reader=$null
            try {
                $reader=[Xml.XmlReader]::Create($xmlTextReader,$settings)
                $document=[Xml.XmlDocument]::new();$document.XmlResolver=$null;$document.Load($reader)
            } finally {if($reader){$reader.Dispose()};$xmlTextReader.Dispose()}
            $ns=[Xml.XmlNamespaceManager]::new($document.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
            $system=$document.SelectSingleNode('/e:Event/e:System',$ns)
            $policy=$document.SelectSingleNode('/e:Event/e:UserData/e:CertVerifyCertificateChainPolicy',$ns)
            if($null -eq $system -or $null -eq $policy){continue}
            if((Get-LDSCAPIValue $system 'e:Provider' $ns 'Name') -cne 'Microsoft-Windows-CAPI2' -or (Get-LDSCAPIValue $system 'e:Channel' $ns) -cne 'Microsoft-Windows-CAPI2/Operational' -or (Get-LDSCAPIValue $system 'e:EventID' $ns) -ne '30'){continue}
            $record=[long](Get-LDSCAPIValue $system 'e:EventRecordID' $ns)
            $time=[DateTime]::Parse((Get-LDSCAPIValue $system 'e:TimeCreated' $ns 'SystemTime'),[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
            if($record -le $Window.StartRecordID -or $record -gt $Window.EndRecordID -or $time -lt $Window.StartedUTC -or $time -gt $Window.EndedUTC){continue}
            if((Get-LDSCAPIValue $system 'e:Execution' $ns 'ProcessID') -ne [string]$Capture.LSASSPID -or (Get-LDSCAPIValue $policy 'e:EventAuxInfo' $ns 'ProcessName') -ine 'lsass.exe'){continue}
            if((Get-LDSCAPIValue $system 'e:Security' $ns 'UserID') -cne $Capture.OwnerSID -or (Get-LDSCAPIValue $policy 'e:EventAuxInfo' $ns 'impersonateToken') -cne $Capture.OwnerSID){continue}
            if((Get-LDSCAPIValue $policy 'e:Certificate' $ns 'fileRef') -ine "$Thumbprint.cer" -or (Get-LDSCAPIValue $policy 'e:SSLAdditionalPolicyInfo' $ns 'serverName') -ine $ServerName){continue}
            # Count every event with this context BEFORE checking policy/result.
            # A success plus a contradictory failure must remain ambiguous.
            $matches.Add([pscustomobject]@{Policy=$policy;Namespaces=$ns;Record=$record;Time=$time})
        }
        $proof.matching_event_count=$matches.Count
        if($matches.Count -ne 1){$proof.inconclusive_reason=if($matches.Count -eq 0){'missing_event'}else{'ambiguous_events'};return [pscustomobject]$proof}
        $match=$matches[0];$policy=$match.Policy;$ns=$match.Namespaces
        $proof.event_record_id=$match.Record;$proof.event_time_utc=$match.Time.ToString('o')
        $proof.certificate_thumbprint=$Thumbprint.ToUpperInvariant();$proof.certificate_sha256=$SHA256.ToLowerInvariant();$proof.server_name=$ServerName.ToLowerInvariant()
        $proof.emitter_process_name=Get-LDSCAPIValue $policy 'e:EventAuxInfo' $ns 'ProcessName'
        $proof.policy_constant=ConvertFrom-LDSCAPIHex (Get-LDSCAPIValue $policy 'e:Policy' $ns 'constant')
        $proof.flags=ConvertFrom-LDSCAPIHex (Get-LDSCAPIValue $policy 'e:Flags' $ns 'value')
        $proof.ignore_flags=ConvertFrom-LDSCAPIHex (Get-LDSCAPIValue $policy 'e:SSLAdditionalPolicyInfo/e:IgnoreFlags' $ns 'value')
        $proof.auth_type=Get-LDSCAPIValue $policy 'e:SSLAdditionalPolicyInfo' $ns 'authType'
        $result=ConvertFrom-LDSCAPIHex (Get-LDSCAPIValue $policy 'e:Result' $ns 'value')
        $proof.result=$result.ToString('X')
        $proof.passed=((Get-LDSCAPIValue $policy 'e:Policy' $ns 'type') -ceq 'CERT_CHAIN_POLICY_SSL' -and $proof.policy_constant -eq 4 -and $proof.flags -eq 0 -and $proof.ignore_flags -eq 0 -and $proof.auth_type -ceq 'server' -and $result -eq $ExpectedResult)
        if(-not $proof.passed){$proof.inconclusive_reason='unexpected_policy'}
    } catch {$proof.inconclusive_reason='invalid_event';$proof.passed=$false}
    return [pscustomobject]$proof
}
function Complete-LDSCertificatePolicyWindow($Capture,$Window,$Case,[string]$ServerName) {
    $Window.EndedUTC=[DateTime]::UtcNow
    # Allow asynchronous event delivery without expanding the operation's time
    # window. Do not stop at the first match and miss a contradictory event.
    Start-Sleep -Milliseconds 2000
    $Window.EndRecordID=Get-LDSCAPICursor
    $events=@(Get-LDSCAPIEvents $Window.StartRecordID $Window.EndRecordID)
    Test-LDSCertificatePolicyEvents -Events $events -Capture $Capture -Window $Window -Thumbprint $Case.certificate_thumbprint -SHA256 $Case.certificate_sha256 -ServerName $ServerName -ExpectedResult (Get-LDSCertificatePolicyResult $Case.name)
}
