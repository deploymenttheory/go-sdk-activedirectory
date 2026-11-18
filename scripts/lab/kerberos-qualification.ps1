#Requires -Version 7.0
<#
.SYNOPSIS
Collects the complete Kerberos authentication and SASL matrix for one prepared profile.
.DESCRIPTION
Use the tracked account/TLS/reference entry points first. This script consumes
their four public manifests and protected client credential. It never changes
VM power, private switches, clocks, passwords, keytabs or FILE caches. A strict
policy lease, narrow contact fixture and fault relays are independently retired
in finally. Credentials travel only through in-memory process/SSH stdin.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('2016','2019','2022','2025')][string]$ServerVersion,
    [Parameter(Mandatory)][ValidatePattern('\A[a-z0-9][a-z0-9-]{5,39}\z')][string]$RunId,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceRevision,
    [Parameter(Mandatory)][string]$SourceProvenance,
    [Parameter(Mandatory)][string]$WindowsEngine,
    [Parameter(Mandatory)][string]$LinuxEngine,
    [Parameter(Mandatory)][string]$WindowsPublic,
    [Parameter(Mandatory)][string]$LinuxPublic,
    [Parameter(Mandatory)][string]$WindowsPeer,
    [ValidatePattern('\A[0-9a-f]{40}\z')][string]$PeerSourceRevision=$SourceRevision,
    [string]$PeerSourceProvenance='',
    [ValidateSet('All','Auth','SASL')][string]$Scope='All',
    [ValidateSet('windows','linux')][string[]]$Clients=@('windows','linux'),
    [string[]]$CaseFilter=@(),
    [string]$LabRoot='H:\ad-sdk-lab'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V
. (Join-Path $PSScriptRoot 'kerberos-qualification-core.ps1')
. (Join-Path $PSScriptRoot 'kerberos-auth-cases.ps1')
. (Join-Path $PSScriptRoot 'kerberos-sasl-cases.ps1')
$preparedRoot=[IO.Path]::GetFullPath((Join-Path (Join-Path $LabRoot 'portable-kerberos') $RunId))
$profileRoot=[IO.Path]::GetFullPath((Join-Path $LabRoot "server$ServerVersion"))
$profile=Get-Content -LiteralPath (Join-Path $profileRoot 'state.json') -Raw|ConvertFrom-Json
if(-not $profile.configured -or $profile.domain -cne 'ad.sdk.test'){throw 'Expected configured isolated AD DS profile.'}
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if($switch.SwitchType -ne 'Private' -or $switch.Name -cne $profile.switch_name -or $switch.Notes -cne "ad-sdk-lab:$($profile.id)"){throw 'Private switch ownership changed.'}
$machines=@{}
foreach($machine in @($profile.machines)) {
    $vm=Get-VM -Id ([guid]$machine.id);$nics=@(Get-VMNetworkAdapter -VM $vm)
    if($vm.Name -cne $machine.name -or $vm.Notes -cne "ad-sdk-lab:$($profile.id)" -or $vm.State -ne 'Running' -or
        $nics.Count -ne 1 -or $nics[0].SwitchId.ToString() -cne $profile.switch_id){throw 'Windows VM ownership, power or network state changed.'}
    $machines[$machine.role]=$machine
}
foreach($role in @('dc1','dc2','member')){if(-not $machines.ContainsKey($role)){throw 'Prepared profile lacks a required Windows VM.'}}
$linuxScript=Join-Path $PSScriptRoot 'portable-linux.ps1'
$linux=(& $linuxScript Status).manifest
if($linux.server_version -cne $ServerVersion -or $linux.switch_id -cne $profile.switch_id){throw 'Linux client must already be on this private profile.'}
$prepare=Get-Content -LiteralPath (Join-Path $preparedRoot 'prepare.json') -Raw|ConvertFrom-Json
$reference=Get-Content -LiteralPath (Join-Path $preparedRoot 'mit-reference.json') -Raw|ConvertFrom-Json
$transfer=Get-Content -LiteralPath (Join-Path $preparedRoot 'credential-transfer.json') -Raw|ConvertFrom-Json
$tls=Get-Content -LiteralPath (Join-Path $preparedRoot 'tls-prepare.json') -Raw|ConvertFrom-Json
$server=($machines.dc1.name+'.ad.sdk.test').ToLowerInvariant()
if($prepare.run_id -cne $RunId -or $prepare.server -cne $server -or $transfer.run_id -cne $RunId -or -not $transfer.source_and_host_digests_verified -or
    $reference.principal -cne $prepare.upn -or $reference.directory -cne "/home/adsdk/acceptance/mit-$RunId"){throw 'Prepared credential manifests do not identify this fixture.'}
$proof=Get-Content -LiteralPath $SourceProvenance -Raw|ConvertFrom-Json
if($proof.source_revision -cne $SourceRevision -or $proof.go_version -cne 'go1.27.4' -or -not $proof.runtime_byte_identical){throw 'Exact latest-Go runtime/build provenance is required.'}
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ').ToLowerInvariant()
$capture=[IO.Path]::GetFullPath((Join-Path $preparedRoot "qualification-$stamp"))
if(-not $capture.StartsWith($preparedRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $capture)){throw 'Capture must be fresh within the prepared fixture.'}
$null=New-Item -ItemType Directory -Path $capture
$saved=Import-Clixml -LiteralPath (Join-Path $profileRoot 'credential.clixml')
$admin=[PSCredential]::new("$($profile.netbios)\Administrator",$saved.Password)
$client=Import-Clixml -LiteralPath (Join-Path (Join-Path $preparedRoot 'secrets') 'client.clixml')
if($client.UserName -ine $prepare.upn){throw 'Protected client credential identity differs from the prepared account.'}
$context=@{
    run_id=$RunId;source_revision=$SourceRevision;capture=$capture;stamp=$stamp;server=$server;sam=$prepare.sam;realm='AD.SDK.TEST'
    windows_credential_root="C:\adsdk-kerberos-client\$RunId";linux_credential_root="/home/adsdk/acceptance/mit-$RunId"
    windows_ca="C:\adsdk-kerberos-client\$RunId\root.pem";linux_ca="/home/adsdk/acceptance/root-$RunId.pem"
    windows_work="C:\adsdk-kerberos-client\$RunId\qualification-$stamp";client_credential=$client;admin_credential=$admin
    linux_script=$linuxScript;remote_binaries=@{};contact=$null;dc_session=$null;member_session=$null
    policy_started=$false;contact_started=$false
    windows_allowed=[Collections.Generic.List[string]]::new();linux_files=[Collections.Generic.List[string]]::new();peer_cases=[Collections.Generic.List[string]]::new()
    common_source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'kerberos-fixture.ps1'))
    write_source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'kerberos-write-fixture.ps1'))
    peer_source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'kerberos-sasl-peer.ps1'))
    peer_bytes=[IO.File]::ReadAllBytes($WindowsPeer);peer_sha256=(Get-FileHash -LiteralPath $WindowsPeer -Algorithm SHA256).Hash.ToLowerInvariant()
}
$allCases=@()
if($Scope -cin @('All','Auth')){$allCases+=@(Get-KerberosAuthQualificationCases)}
if($Scope -cin @('All','SASL')){$allCases+=@(Get-KerberosSASLQualificationCases)}
foreach($case in $allCases){Assert-KerberosQualificationCase $case}
if(@($allCases.case_id|Sort-Object -Unique).Count -ne $allCases.Count){throw 'Case identities are not unique.'}
$selected=@($allCases|Where-Object {$_.client -cin $Clients -and ($CaseFilter.Count -eq 0 -or $_.case_id -cin $CaseFilter)})
if($selected.Count -eq 0){throw 'No cases match this explicit selection.'}
foreach($filter in $CaseFilter){if(@($selected|Where-Object case_id -CEQ $filter).Count -ne 1){throw 'A requested case filter is absent or ambiguous.'}}
$manifest=[ordered]@{
    schema_version=1;run_id=$RunId;source_revision=$SourceRevision;sdk_base_revision=$proof.sdk_base_revision;runtime_byte_identical=$proof.runtime_byte_identical
    server_version=$ServerVersion;profile_id=$profile.id;scope=$Scope;clients=$Clients;case_filter=$CaseFilter
    full_expected_case_set=($Scope -ceq 'All' -and @($Clients|Sort-Object -Unique).Count -eq 2 -and $CaseFilter.Count -eq 0)
    expected_cases=$selected.Count;started_utc=[DateTime]::UtcNow.ToString('o');binaries=@{};passed=$false;cleanup_verified=$false
    runner_source_sha256=@{}
}
foreach($name in @('prepare.json','mit-reference.json','credential-transfer.json','tls-prepare.json')){
    Save-KerberosQualificationBytes $context ('prepared-'+$name) ([IO.File]::ReadAllBytes((Join-Path $preparedRoot $name)))
}
Save-KerberosQualificationBytes $context 'source-provenance.json' ([IO.File]::ReadAllBytes($SourceProvenance))
if($PeerSourceProvenance){
    $peerProof=Get-Content -LiteralPath $PeerSourceProvenance -Raw|ConvertFrom-Json
    if($peerProof.source_revision -cne $PeerSourceRevision -or $peerProof.go_version -cne 'go1.27.4'){throw 'Peer fixture source label or toolchain differs.'}
    Save-KerberosQualificationBytes $context 'peer-source-provenance.json' ([IO.File]::ReadAllBytes($PeerSourceProvenance))
}
foreach($name in @('kerberos-qualification.ps1','kerberos-qualification-core.ps1','kerberos-auth-cases.ps1','kerberos-sasl-cases.ps1','kerberos-fixture.ps1','kerberos-write-fixture.ps1','kerberos-sasl-peer.ps1')){
    $source=Join-Path $PSScriptRoot $name
    $manifest.runner_source_sha256[$name]=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-KerberosQualificationBytes $context ('source-'+$name+'.txt') ([IO.File]::ReadAllBytes($source))
}
$inputs=@{'windows-engine'=$WindowsEngine;'linux-engine'=$LinuxEngine;'windows-public'=$WindowsPublic;'linux-public'=$LinuxPublic;'windows-peer'=$WindowsPeer}
foreach($name in $inputs.Keys){
    $file=Get-Item -LiteralPath $inputs[$name]
    if($file.PSIsContainer -or $file.Length -gt 32MB){throw 'Expected bounded compiled binaries.'}
    $manifest.binaries[$name]=@{sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$file.Length}
}
$manifest.binaries['windows-peer'].source_revision=$PeerSourceRevision
$completed=[Collections.Generic.List[object]]::new();$failures=[Collections.Generic.List[string]]::new();$cleanupFailures=[Collections.Generic.List[string]]::new();$policy=$null;$directoryCleanup=$null
try {
    $context.dc_session=New-PSSession -VMId ([guid]$machines.dc1.id) -Credential $admin
    $context.member_session=New-PSSession -VMId ([guid]$machines.member.id) -Credential $admin
    if('windows' -cin $Clients){Invoke-Command -Session $context.member_session -ArgumentList $context.windows_work -ScriptBlock {
        param($directory)
        if(Test-Path -LiteralPath $directory){throw 'Windows work directory must be fresh.'}
        for($parent=[IO.Path]::GetDirectoryName($directory);$parent;$parent=[IO.Path]::GetDirectoryName($parent)){
            if((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Windows work path crosses a reparse point.'}
        }
        $null=New-Item -ItemType Directory -Path $directory
    }}
    foreach($kind in @('engine','public')){
        if('windows' -cin $Clients){
        $windowsName=$kind+'.exe';$context.windows_allowed.Add($windowsName)
        $windowsPath=Join-Path $context.windows_work $windowsName
        Copy-Item -LiteralPath $inputs['windows-'+$kind] -Destination $windowsPath -ToSession $context.member_session
        $actual=Invoke-Command -Session $context.member_session -ArgumentList $windowsPath -ScriptBlock {param($path) (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
        if($actual -cne $manifest.binaries['windows-'+$kind].sha256){throw 'Windows binary transfer digest differs.'}
        $context.remote_binaries['windows-'+$kind]=$windowsPath
        }
        if('linux' -cin $Clients){
        $linuxName='q-'+$stamp+'-'+$kind
        $upload=& $linuxScript Upload -LocalFile $inputs['linux-'+$kind] -RemoteName $linuxName
        if(-not $upload.remote_digest_verified -or $upload.sha256 -cne $manifest.binaries['linux-'+$kind].sha256){throw 'Linux binary transfer digest differs.'}
        $context.remote_binaries['linux-'+$kind]='/home/adsdk/acceptance/'+$linuxName;$context.linux_files.Add($linuxName)
        }
    }
    Invoke-KerberosQualificationDC $context 'param($run,$server) $null=Get-KerberosFixtureState $run $server;if(Test-Path -LiteralPath (Get-KerberosPolicyLeasePath)){throw "A policy lease is already held; no shared baseline mutation is allowed."}' @($RunId,$server)
    $context.policy_started=$true
    $policy=Invoke-KerberosQualificationDC $context 'param($run,$server) Set-KerberosFixtureStrictPolicy $run $server' @($RunId,$server)
    Save-KerberosQualificationJSON $context 'strict-policy.json' $policy
    foreach($case in $selected){
        if($case.kind -cin @('sasl','engine-sasl-tls-refusal') -and $null -eq $context.contact){
            $context.contact_started=$true
            $preparedContact=Invoke-KerberosQualificationDC $context 'param($run,$server,[PSCredential]$admin) $root=Get-KerberosFixtureState $run $server;$directory=Get-KerberosFixtureDirectory $run;$journal=Assert-KerberosFixturePath (Join-Path $directory "write-fixture.json");if(Test-Path -LiteralPath $journal){$old=Get-KerberosWriteState $root;if($old.phase -cne "cleaned"){throw "Previous write fixture is not independently clean."};$archive=Assert-KerberosFixturePath (Join-Path $directory ("write-fixture-before-qualification-"+[DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")+".json"));if(Test-Path -LiteralPath $archive){throw "Archive exists."};$hash=(Get-FileHash -LiteralPath $journal -Algorithm SHA256).Hash;Move-Item -LiteralPath $journal -Destination $archive;if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -cne $hash){throw "Archived bytes differ."}};New-KerberosWriteFixture $run $server $admin' @($RunId,$server,$admin)
            $context.contact=$preparedContact;Save-KerberosQualificationJSON $context 'contact-prepare.json' $preparedContact
        }
        $completed.Add((Invoke-KerberosQualificationCase $context $case))
    }
    $manifest.passed=($completed.Count -eq $selected.Count)
} catch {$failures.Add($_.Exception.Message)}
finally {
    if($context.dc_session){
        foreach($caseId in $context.peer_cases){
            try {
                $peerCleanup=Invoke-KerberosQualificationDC $context 'param($run,$server,$case) $directory=Get-KerberosSASLPeerDirectory $run $case;if(Test-Path -LiteralPath $directory){Remove-KerberosSASLPeer $run $server $case}else{[pscustomobject]@{verified=$true;already_absent=$true}}' @($RunId,$server,$caseId)
                Save-KerberosQualificationJSON $context ($caseId+'-peer-final-reconcile.json') $peerCleanup
                if(-not $peerCleanup.verified){throw 'Peer cleanup did not verify.'}
            } catch {$failures.Add($_.Exception.Message);$cleanupFailures.Add($_.Exception.Message)}
        }
        try {
            if($context.policy_started){
            $directoryCleanup=Invoke-KerberosQualificationDC $context 'param($run,$server,[PSCredential]$admin,$contactStarted) $contact=$null;$problem=$null;try{if($contactStarted){$journal=Join-Path (Get-KerberosFixtureDirectory $run) "write-fixture.json";if(Test-Path -LiteralPath $journal){$contact=Remove-KerberosWriteFixture $run $server $admin}}}catch{$problem=$_.Exception.Message}finally{$policy=Restore-KerberosFixturePolicy $run $server};[pscustomobject]@{contact=$contact;policy=$policy;problem=$problem;verified=($null -eq $problem -and $policy.verified -and ($null -eq $contact -or $contact.verified))}' @($RunId,$server,$admin,$context.contact_started)
            }else{$directoryCleanup=[pscustomobject]@{verified=$true;no_policy_or_contact_mutation_started=$true}}
            Save-KerberosQualificationJSON $context 'directory-policy-cleanup.json' $directoryCleanup
            if(-not $directoryCleanup.verified){throw 'Directory or exact policy baseline cleanup failed.'}
        } catch {$failures.Add($_.Exception.Message);$cleanupFailures.Add($_.Exception.Message)}
    }
    if($context.member_session -and 'windows' -cin $Clients){
        try {
            $windowsCleanup=Invoke-Command -Session $context.member_session -ArgumentList $context.windows_work,@($context.windows_allowed) -ScriptBlock {
                param($directory,[string[]]$allowed)
                if(-not (Test-Path -LiteralPath $directory)){return [pscustomobject]@{verified=$true;already_absent=$true}}
                $directory=[IO.Path]::GetFullPath($directory)
                if($directory -cnotmatch '\AC:\\adsdk-kerberos-client\\[a-z0-9-]+\\qualification-[a-z0-9]+\z'){throw 'Windows cleanup target escaped the owned workspace.'}
                foreach($file in @(Get-ChildItem -LiteralPath $directory -Force)){
                    if($file.PSIsContainer -or $file.Name -cnotin $allowed -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $file.FullName.StartsWith($directory+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected Windows work file; no deletion allowed.'}
                }
                foreach($file in @(Get-ChildItem -LiteralPath $directory -Force)){Remove-Item -LiteralPath $file.FullName -Force}
                Remove-Item -LiteralPath $directory
                [pscustomobject]@{verified=(-not (Test-Path -LiteralPath $directory))}
            }
            Save-KerberosQualificationJSON $context 'windows-files-cleanup.json' $windowsCleanup
        } catch {$failures.Add($_.Exception.Message);$cleanupFailures.Add($_.Exception.Message)}
    }
    try {
        $paths=@()
        foreach($name in $context.linux_files){if($name -cnotmatch '\Aq-[a-z0-9._-]{1,125}\z'){throw 'Linux cleanup filename is not owned.'};$paths+=('/home/adsdk/acceptance/'+$name)}
        if($paths.Count -ne 0){$removed=& $linuxScript Exec -Command ('rm -f -- '+($paths -join ' '));if($removed.exit_code -ne 0){throw 'Linux owned file cleanup failed.'}}
        Save-KerberosQualificationJSON $context 'linux-files-cleanup.json' ([pscustomobject]@{verified=$true;owned_file_names=@($context.linux_files)})
    } catch {$failures.Add($_.Exception.Message);$cleanupFailures.Add($_.Exception.Message)}
    foreach($session in @($context.dc_session,$context.member_session)){if($session){Remove-PSSession -Session $session}}
}
$manifest.cases=$completed.ToArray();$manifest.failures=$failures.ToArray();$manifest.finished_utc=[DateTime]::UtcNow.ToString('o')
$manifest.cleanup_failures=$cleanupFailures.ToArray()
$manifest.cleanup_verified=($cleanupFailures.Count -eq 0 -and $null -ne $directoryCleanup -and $directoryCleanup.verified)
$manifest.passed=($manifest.passed -and $manifest.cleanup_verified)
Save-KerberosQualificationJSON $context 'manifest.json' $manifest
[pscustomobject]@{capture=$capture;passed=$manifest.passed;cases=$completed.Count;expected=$selected.Count;cleanup_verified=$manifest.cleanup_verified}
if(-not $manifest.passed){throw 'Qualification failed; fresh records and independent cleanup results were retained.'}
