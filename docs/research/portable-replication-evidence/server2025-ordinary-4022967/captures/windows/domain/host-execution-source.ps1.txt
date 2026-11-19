#Requires -Version 7.0
[CmdletBinding()]
param([ValidateSet('portable','native')][string]$Backend='portable',[ValidateSet('2016','2019','2022','2025')][string]$ServerVersion='2025',[string]$RunId='',[switch]$ResumeStaged,[ValidateSet('server','domain','forest','site')][string]$Scope='server',[switch]$ExplicitServers,[ValidatePattern('^[0-9a-f]{40}$')][string]$Revision='d52ac60a8300fdab43d7bc6db718c369efbdc80e',[string]$ActorFixture='')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=$PSScriptRoot;$lab='H:\ad-sdk-lab';$revision=$Revision
if($ActorFixture-and$Backend-cne'portable'){throw 'Ordinary actor qualification requires the portable public path.'}
$run=if($RunId){$RunId}else{('sdk07-p'+$ServerVersion.Substring(2)+'-')+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ').ToLowerInvariant()}
if($run-cnotmatch'\Asdk07-p(16|19|22|25)-[a-z0-9-]{10,25}\z'-or-not$run.StartsWith(('sdk07-p'+$ServerVersion.Substring(2)+'-'),[StringComparison]::Ordinal)){throw 'RPC run/profile differs.'}
$lane=$Backend+'-password';$capture=Join-Path (Join-Path (Join-Path $lab 'portable-replication') $run) ('windows-'+$lane)
if(Test-Path -LiteralPath $capture){throw 'Fresh RPC capture required; inspect existing results instead of replay.'}
$null=New-Item -ItemType Directory -Path $capture
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $capture 'host-execution-source.ps1.txt')
$profile=Get-Content -LiteralPath "$lab\server$ServerVersion\state.json" -Raw|ConvertFrom-Json
if($profile.server_version-cne$ServerVersion-or$profile.domain-cne'ad.sdk.test'){throw 'RPC lab profile differs.'}
Import-Module Hyper-V
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if($switch.SwitchType-ne'Private'-or$switch.Notes-cne('ad-sdk-lab:'+$profile.id)){throw 'Owned private switch differs.'}
$vms=@{}
foreach($entry in $profile.machines){$vm=Get-VM -Id ([guid]$entry.id);$nics=@(Get-VMNetworkAdapter -VM $vm);if($vm.Name-cne$entry.name-or$vm.Notes-cne('ad-sdk-lab:'+$profile.id)-or$vm.State-ne'Running'-or$nics.Count-ne1-or$nics[0].SwitchId.ToString()-cne$profile.switch_id){throw 'Owned RPC VM differs.'};$vms[$entry.role]=$vm}
$vm=$vms.member
$binaryRoot=Join-Path $root ('sdk07-live\'+$revision.Substring(0,7));$binary=Join-Path $binaryRoot 'portablereplication-windows-amd64.exe'
$build=Get-Content -LiteralPath (Join-Path $binaryRoot 'binary-manifest.json') -Raw|ConvertFrom-Json
$entries=@($build.binaries|Where-Object platform -CEQ 'windows/amd64');if($entries.Count-ne1){throw 'Ambiguous RPC binary.'};$expected=$entries[0].sha256
if(-not$build.complete-or$build.source_revision-cne$revision-or(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$expected){throw 'Canonical public RPC binary differs.'}
foreach($name in @('binary-manifest.json','source-provenance.json')){Copy-Item -LiteralPath (Join-Path $binaryRoot $name) -Destination (Join-Path $capture $name)}
$controller=Join-Path $binaryRoot 'source\scripts\lab\kerberos-qualification-core.ps1';$controllerHash=(Get-FileHash -LiteralPath $controller -Algorithm SHA256).Hash.ToLowerInvariant()
Copy-Item -LiteralPath $controller -Destination (Join-Path $capture 'protected-stdin-source.ps1.txt')
$sourceHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$saved=Import-Clixml -LiteralPath "$lab\server$ServerVersion\credential.clixml";$admin=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
$server='adsdk'+$ServerVersion.Substring(2)+'dc1.ad.sdk.test'
if($ExplicitServers-and$Scope-cne'server'){throw 'Explicit server list is a separate server-scope selection.'}
$selectedHosts=@($server,$server.Replace('dc1.','dc2.'))
$identities=@(Invoke-Command -VMId $vms.dc1.Id -Credential $admin -ArgumentList (,$selectedHosts) -ScriptBlock {
    param([string[]]$selectedHosts)
    $ErrorActionPreference='Stop';$env:ADPS_LoadDefaultDrive='0';Import-Module ActiveDirectory
    foreach($server in $selectedHosts){
    $r=Get-ADRootDSE -Server $server -ErrorAction Stop
    if($r.dnsHostName-ine$server-or$r.defaultNamingContext-cne'DC=ad,DC=sdk,DC=test'-or$r.rootDomainNamingContext-cne'DC=ad,DC=sdk,DC=test'){throw 'Reference RPC directory differs.'}
    $dsa=Get-ADObject -Server $server -Identity $r.dsServiceName -ErrorAction Stop
    $parent=Get-ADObject -Server $server -Identity $r.serverName -Properties serverReference -ErrorAction Stop
    $computer=Get-ADComputer -Server $server -Identity $parent.serverReference -Properties servicePrincipalName,dNSHostName -ErrorAction Stop
    if($computer.dNSHostName-ine$server){throw 'Reference computer host differs.'}
    $registered=@($computer.servicePrincipalName)
    $rpc=@($registered|Where-Object {$_-ieq('RPC/'+$dsa.ObjectGUID.ToString()+'._msdcs.ad.sdk.test')-or$_-ieq('RPC/'+$dsa.ObjectGUID.ToString()+'.msdcs.ad.sdk.test')})
    $ldap=@($registered|Where-Object {$_-ieq('ldap/'+$server)})
    if($rpc.Count-ne1-or$ldap.Count-ne1){throw 'Select unambiguous actually registered RPC and LDAP identities.'}
    $controller=Get-ADDomainController -Server $server -Identity $server -ErrorAction Stop
    [pscustomobject]@{server=$server;dsa_guid=$dsa.ObjectGUID.ToString();dsa_dn=$dsa.DistinguishedName;computer_guid=$computer.ObjectGUID.ToString();registered_spns=$registered;selected_ldap=$ldap[0];selected_epm=$rpc[0];selected_drs=$ldap[0];site=$controller.Site}
    }
})
if($identities.Count-ne2){throw 'Both explicitly selected DC identity observations are required.'}
$identity=@($identities|Where-Object server -CEQ $server)[0]
$identities|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $capture 'independent-service-identities.json') -Encoding utf8
$session=$null;$inputBytes=$null;$secret=$null;$actor=$null
try{
    $qualificationCredential=$admin;$qualificationUsername='Administrator';$credentialSource='existing explicitly selected protected lab Administrator, read-only diagnostics';$actorGuid=$null
    if($ActorFixture){
        $loader=Join-Path $root 'sdk07-ordinary-input.ps1';. $loader
        $actor=Read-Sdk07OrdinaryActor -RunId $ActorFixture -ServerVersion $ServerVersion -ProfileId $profile.id
        $qualificationCredential=$actor.credential;$qualificationUsername=$actor.username;$actorGuid=$actor.client_guid
        $credentialSource='explicit marker-owned ordinary actor; no privileged group grant'
        Copy-Item -LiteralPath $loader -Destination (Join-Path $capture 'ordinary-actor-input-source.ps1.txt')
    }
    $session=New-PSSession -VMId $vm.Id -Credential $admin
    $remote='C:\adsdk-replication-client\'+$run+'-'+$lane
    $owner=@{schema_version=1;purpose='sdk-replication-collector';run_id=$run;profile_id=$profile.id;member_id=$vm.Id.ToString();source_revision=$build.source_revision;binary_sha256=$expected}
    if($ResumeStaged){
        if(Test-Path -LiteralPath (Join-Path $capture ('windows-'+$lane+'-execution-intent.json'))){throw 'SDK execution was already attempted; reconcile instead of retrying.'}
        $staged=Invoke-Command -Session $session -ArgumentList $remote,$owner,$expected -ScriptBlock {
            param($path,$expectedOwner,$hash)
            $owner=Get-Content -LiteralPath (Join-Path $path 'owner.json') -Raw|ConvertFrom-Json
            foreach($key in @('purpose','run_id','profile_id','member_id','source_revision','binary_sha256')){if($owner.$key-cne$expectedOwner[$key]){throw 'Staged owner differs.'}}
            $files=@(Get-ChildItem -LiteralPath $path -Force)
            if($files.Count-ne2-or@($files|Where-Object {$_.PSIsContainer-or$_.Name-cnotin@('owner.json','replication.exe')-or($_.Attributes-band[IO.FileAttributes]::ReparsePoint)}).Count){throw 'Unexpected staged files or prior result.'}
            $binary=Join-Path $path 'replication.exe'
            if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$hash){throw 'Staged binary differs.'}
            if(@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath-and$_.ExecutablePath.Equals($binary,[StringComparison]::OrdinalIgnoreCase)}).Count){throw 'Collector is already running.'}
            [pscustomobject]@{binary=$binary;sha256=$hash;bytes=(Get-Item -LiteralPath $binary).Length;pre_execution_resume=$true}
        }
    }else{
    Invoke-Command -Session $session -ArgumentList $remote,$owner -ScriptBlock {
        param($path,$owner)
        for($p=$path;$p;$p=[IO.Path]::GetDirectoryName($p)){if((Test-Path -LiteralPath $p)-and((Get-Item -LiteralPath $p -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Unsafe collector path.'}}
        if(Test-Path -LiteralPath $path){throw 'Existing collector directory requires reconciliation, not replay.'}
        $null=New-Item -ItemType Directory -Path $path -Force
        $owner|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $path 'owner.json') -Encoding utf8
        $stream=[IO.File]::Open((Join-Path $path 'collector.part'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);$stream.Dispose()
    }
    $all=[IO.File]::ReadAllBytes($binary)
    # Bounded public-binary staging. A failed acknowledgement is reconciled;
    # the loop never blindly repeats a chunk or an SDK mutation.
    for($offset=0;$offset-lt$all.Length;){
        $size=[Math]::Min(128KB,$all.Length-$offset);$chunk=[byte[]]::new($size);[Array]::Copy($all,$offset,$chunk,0,$size)
        $next=Invoke-Command -Session $session -ArgumentList $remote,$offset,$chunk -ScriptBlock {
            param($path,[long]$offset,[byte[]]$bytes)
            $file=Join-Path $path 'collector.part';$item=Get-Item -LiteralPath $file -Force
            if($item.Attributes-band[IO.FileAttributes]::ReparsePoint-or$item.Length-ne$offset){throw 'Binary chunk prestate differs; reconcile.'}
            $stream=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            try{$null=$stream.Seek($offset,[IO.SeekOrigin]::Begin);$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
            (Get-Item -LiteralPath $file).Length
        }
        if($next-ne($offset+$size)){throw 'Binary chunk acknowledgement differs.'};$offset+=$size
    }
    $all=$null
    $staged=Invoke-Command -Session $session -ArgumentList $remote,$expected -ScriptBlock {
        param($path,$expected)
        $part=Join-Path $path 'collector.part';if((Get-FileHash -LiteralPath $part -Algorithm SHA256).Hash.ToLowerInvariant()-cne$expected){throw 'Staged binary hash differs.'}
        $file=Join-Path $path 'replication.exe';if(Test-Path -LiteralPath $file){throw 'Unexpected final binary.'}
        Move-Item -LiteralPath $part -Destination $file
        [pscustomobject]@{binary=$file;sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $file).Length}
    }
    $staged|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $capture ('windows-'+$lane+'-binary-transfer.json')) -Encoding utf8
    }
    $plain=$qualificationCredential.GetNetworkCredential().Password;$secret=[Text.Encoding]::UTF8.GetBytes($plain);$plain=$null
    $input=@{backend=$Backend;endpoint=($server+':389');transport='ldap-seal';source='password';password_base64=[Convert]::ToBase64String($secret);username=$qualificationUsername;realm='AD.SDK.TEST';domain='ADSDK';ldap_spn=$identity.selected_ldap;kind='all';scope=$Scope;partition_dn='DC=ad,DC=sdk,DC=test';run_id=$run;source_revision=$revision;result=($remote+'\result.json')}
    switch($Scope){domain{$input.domain_dns='ad.sdk.test'}forest{$input.forest_dns='ad.sdk.test'}site{$input.site_name=$identity.site}}
    if($ExplicitServers){$input.servers=@($selectedHosts|ForEach-Object{@{Host=$_;Port=389}})}
    if($Backend-ceq'portable'){$input.service_principals=@{};foreach($selected in $identities){$input.service_principals[$selected.server]=@{ldap=$selected.selected_ldap;endpoint_mapper=$selected.selected_epm;drs=$selected.selected_drs}}}
    $inputBytes=[Text.Encoding]::UTF8.GetBytes(($input|ConvertTo-Json -Depth 8 -Compress));$input=$null
    [Array]::Clear($secret,0,$secret.Length);$secret=$null
    @{run_id=$run;source_revision=$revision;backend=$Backend;member_id=$vm.Id.ToString();binary_sha256=$expected;credential_source=$credentialSource;actor_fixture=$ActorFixture;actor_guid=$actorGuid;credential_transport='encrypted PSDirect and process stdin only';process_controller_sha256=$controllerHash;host_source_sha256=$sourceHash;phase='before-public-sdk-call';created_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $capture ('windows-'+$lane+'-execution-intent.json')) -Encoding utf8
    . $controller
    $process=Invoke-KerberosQualificationWindows @{member_session=$session} $staged.binary '' '' $inputBytes
    $process|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $capture 'process.json') -Encoding utf8
    $exists=Invoke-Command -Session $session -ArgumentList ($remote+'\result.json') -ScriptBlock {param($path);Test-Path -LiteralPath $path}
    if($exists){Copy-Item -LiteralPath ($remote+'\result.json') -Destination (Join-Path $capture 'result.json') -FromSession $session}
    [pscustomobject]@{run_id=$run;capture=$capture;backend=$Backend;exit_code=$process.exit_code;result_present=$exists;source_revision=$revision}|ConvertTo-Json
}finally{
    if($inputBytes){[Array]::Clear($inputBytes,0,$inputBytes.Length)}
    if($secret){[Array]::Clear($secret,0,$secret.Length)}
    if($session){Remove-PSSession $session}
    $admin=$null;$saved=$null;$actor=$null;$qualificationCredential=$null
}
