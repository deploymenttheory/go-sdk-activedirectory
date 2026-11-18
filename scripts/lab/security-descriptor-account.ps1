#Requires -Version 7.0
# Host orchestration only. No guest power/network changes or SDK runtime gateway.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare','Cleanup')][string]$Action,
    [ValidateSet('2016','2019','2022','2025')][string]$ServerVersion='2025',
    [string]$LabRoot='H:\ad-sdk-lab',
    [Parameter(Mandatory)][string]$RunId
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$helper=Join-Path $PSScriptRoot 'security-descriptor-fixture.ps1'
. $helper
$names=Get-DescriptorFixtureNames $RunId
Import-Module Hyper-V
$lab=[IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
$profileRoot=Join-Path $lab ('server'+$ServerVersion)
$profile=Get-Content -LiteralPath (Join-Path $profileRoot 'state.json') -Raw|ConvertFrom-Json
if ([IO.Path]::GetFullPath($profile.root) -cne $profileRoot -or $profile.server_version -cne $ServerVersion -or
    $profile.domain -cne 'ad.sdk.test' -or $profile.netbios -cne 'ADSDK') {throw 'Descriptor lab profile identity differs.'}
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if ($switch.SwitchType -ne 'Private' -or $switch.Name -cne ('ad-sdk-'+$ServerVersion) -or $switch.Notes -cne ('ad-sdk-lab:'+$profile.id)) {throw 'Descriptor lab switch isolation differs.'}
$dc=@($profile.machines|Where-Object role -CEQ dc1)
if ($dc.Count -ne 1) {throw 'Descriptor lab DC role is ambiguous.'}
$vm=Get-VM -Id ([guid]$dc[0].id)
$nics=@(Get-VMNetworkAdapter -VM $vm)
if ($vm.Name -cne $dc[0].name -or $vm.Notes -cne ('ad-sdk-lab:'+$profile.id) -or $vm.State -ne 'Running' -or
    $nics.Count -ne 1 -or $nics[0].SwitchId.ToString() -cne $profile.switch_id) {throw 'Descriptor DC VM identity differs.'}
$server=($dc[0].name+'.ad.sdk.test').ToLowerInvariant()
$captureRoot=Join-Path $lab 'portable-security-descriptors'
$capture=[IO.Path]::GetFullPath((Join-Path $captureRoot $RunId))
if (-not $capture.StartsWith($captureRoot+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Descriptor capture escaped its root.'}
for ($cursor=$capture;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
    if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Descriptor capture traverses a reparse point.'}
}
$manifestPath=Join-Path $capture 'fixture.json'
$secrets=Join-Path $capture 'secrets'
$secretPath=Join-Path $secrets 'actor.clixml'
$sourceBytes=[IO.File]::ReadAllBytes($helper)
$sourceHash=(Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant()
$hostHash=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$password=$null;$credential=$null;$session=$null

function Save-HostDescriptorManifest($Value) {
    [IO.File]::WriteAllText($manifestPath,($Value|ConvertTo-Json -Depth 18),[Text.UTF8Encoding]::new($false))
}

if ($Action -ceq 'Prepare') {
    if (Test-Path -LiteralPath $capture) {throw 'Fresh descriptor capture required.'}
    $null=New-Item -ItemType Directory -Path $secrets -Force
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)|Select-Object -Unique) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $secrets -AclObject $acl
    # Retain executed public sources and digests BEFORE any remote AD mutation.
    [IO.File]::WriteAllBytes((Join-Path $capture 'fixture-source.ps1'),$sourceBytes)
    [IO.File]::WriteAllBytes((Join-Path $capture 'account-source.ps1'),[IO.File]::ReadAllBytes($PSCommandPath))
    $manifest=[pscustomobject]@{
        schema_version=1;purpose='sdk-portable-descriptor-fixture';run_id=$RunId;profile_id=$profile.id;server=$server;server_version=$ServerVersion
        dc_vm_id=$vm.Id.ToString();phase='planned';fixture_source_sha256=$sourceHash;account_source_sha256=$hostHash
        private_file='secrets/actor.clixml';private_file_sha256=$null;state=$null;cleanup=$null;replicated_cleanup=$null;private_file_retired=$false
    }
    Save-HostDescriptorManifest $manifest
    $random=[byte[]]::new(48);$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try {$rng.GetBytes($random)} finally {$rng.Dispose()}
    try {$text='Sdk6!'+[Convert]::ToBase64String($random)+'a9';$password=ConvertTo-SecureString -String $text -AsPlainText -Force} finally {[Array]::Clear($random,0,$random.Length);$text=$null}
    $credential=[PSCredential]::new($names.upn,$password)
    $credential|Export-Clixml -LiteralPath $secretPath -NoClobber
    $manifest.private_file_sha256=(Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.phase='private-recorded';Save-HostDescriptorManifest $manifest
} else {
    $manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.purpose -cne 'sdk-portable-descriptor-fixture' -or $manifest.run_id -cne $RunId -or
        $manifest.profile_id -cne $profile.id -or $manifest.server -cne $server -or $manifest.server_version -cne $ServerVersion -or
        $manifest.dc_vm_id -cne $vm.Id.ToString() -or $manifest.private_file -cne 'secrets/actor.clixml') {throw 'Descriptor cleanup host identity differs.'}
    # Cleanup executes the exact helper retained at preparation, never an
    # unreviewed replacement downloaded or selected from another directory.
    $sourceBytes=[IO.File]::ReadAllBytes((Join-Path $capture 'fixture-source.ps1'))
    $sourceHash=(Get-FileHash -LiteralPath (Join-Path $capture 'fixture-source.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceHash -cne $manifest.fixture_source_sha256) {throw 'Retained descriptor helper source changed.'}
    if ((Test-Path -LiteralPath $secretPath) -and (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.private_file_sha256) {throw 'Owned DPAPI file changed; no cleanup mutation allowed.'}
}

$saved=Import-Clixml -LiteralPath (Join-Path $profileRoot 'credential.clixml')
$admin=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
try {
    $session=New-PSSession -VMId $vm.Id -Credential $admin
    $result=Invoke-Command -Session $session -ArgumentList $sourceBytes,$sourceHash,$Action,$RunId,$server,$password,$admin -ScriptBlock {
        param([byte[]]$source,[string]$expected,[string]$action,[string]$run,[string]$server,[SecureString]$password,[PSCredential]$admin)
        $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$actual=([BitConverter]::ToString($sha.ComputeHash($source))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
        if ($actual -cne $expected) {throw 'Executed descriptor fixture source differs.'}
        . ([scriptblock]::Create([Text.UTF8Encoding]::new($false,$true).GetString($source)))
        if ($action -ceq 'Prepare') {New-DescriptorDirectoryFixture $run $server $password $admin}
        else {Remove-DescriptorDirectoryFixture $run $server}
    }
    if ($Action -ceq 'Prepare') {
        $manifest.state=$result;$manifest.phase='ready';Save-HostDescriptorManifest $manifest
        $matching=@($result.accounts|Where-Object id -CEQ matching);$stale=@($result.accounts|Where-Object id -CEQ stale)
        [pscustomobject]@{run_id=$RunId;capture=$capture;server=$server;credential_file=$secretPath;username=$names.sam;actor_guid=$result.actor_guid;
            fixture_ou=$names.parent_dn;fixture_guid=$result.parent_guid;matching_guid=$matching[0].guid;stale_guid=$stale[0].guid;reader_dn=$names.actor_dn;reader_guid=$result.actor_guid}
    } else {
        if (-not $result.verified -or $result.live_owned_objects_remaining -ne 0) {throw 'Descriptor fixture local cleanup incomplete.'}
        $manifest.cleanup=$result;$manifest.phase='local-removed';Save-HostDescriptorManifest $manifest
        $replicated=Invoke-Command -Session $session -ArgumentList $RunId,$server,$admin,$result.state,$names -ScriptBlock {
            param($run,$server,[PSCredential]$credential,$state,$names)
            $ErrorActionPreference='Stop';Import-Module ActiveDirectory
            $servers=@($server,$server.Replace('dc1.','dc2.'));$observations=@();$verified=$false
            $guids=@($state.parent_guid,$state.actor_guid)+@($state.accounts|ForEach-Object {$_.guid})
            for ($attempt=0;$attempt -lt 15;$attempt++) {
                $observations=@(foreach ($dc in $servers) {
                    $filter='(|(description=sdk06-descriptor-parent:'+$run+')(description=sdk06-descriptor-actor:'+$run+')(description=sdk06-descriptor-gmsa:'+$run+':matching)(description=sdk06-descriptor-gmsa:'+$run+':stale)'
                    foreach ($sam in @($names.sam,$names.matching_sam,$names.stale_sam)) {$filter+='(sAMAccountName='+$sam+')'}
                    foreach ($id in $guids) {if ($id) {$hex=([guid]$id).ToByteArray()|ForEach-Object {'\'+$_.ToString('x2')};$filter+='(objectGUID='+($hex -join '')+')'}}
                    $filter+=')'
                    $objects=@(Get-ADObject -Server $dc -Credential $credential -SearchBase 'DC=ad,DC=sdk,DC=test' -LDAPFilter $filter -ErrorAction Stop)
                    [pscustomobject]@{server=$dc;live_owned_objects_remaining=$objects.Count;checked_utc=[DateTime]::UtcNow.ToString('o')}
                })
                if (@($observations|Where-Object live_owned_objects_remaining -NE 0).Count -eq 0) {$verified=$true;break}
                Start-Sleep -Seconds 2
            }
            [pscustomobject]@{run_id=$run;verified=$verified;observations=$observations;tombstones_retained=$true}
        }
        $manifest.replicated_cleanup=$replicated;Save-HostDescriptorManifest $manifest
        if (-not $replicated.verified) {throw 'Independent two-DC descriptor cleanup incomplete; protected private file retained.'}
        if (Test-Path -LiteralPath $secretPath) {
            if ((Get-Item -LiteralPath $secretPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint -or
                (Get-FileHash -LiteralPath $secretPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.private_file_sha256) {throw 'DPAPI file identity changed before retirement.'}
            Remove-Item -LiteralPath $secretPath -Force
        }
        $manifest.private_file_retired=-not(Test-Path -LiteralPath $secretPath);$manifest.phase='cleaned';Save-HostDescriptorManifest $manifest
        $manifest|Select-Object run_id,phase,cleanup,replicated_cleanup,private_file_retired
    }
} finally {
    if ($session) {
        try {
            $journal='C:\adsdk-descriptor-fixtures\'+$RunId
            $files=Invoke-Command -Session $session -ArgumentList $journal -ScriptBlock {
                param($path)
                if (Test-Path -LiteralPath $path) {Get-ChildItem -LiteralPath $path -File|Where-Object {$_.Name -match '\A(event-[0-9]{4}|state)\.json\z'}|Select-Object Name,FullName}
            }
            foreach ($file in $files) {
                $destination=Join-Path $capture $file.Name
                if ($file.Name -ceq 'state.json') {$destination=Join-Path $capture ('guest-state-'+$Action.ToLowerInvariant()+'.json')}
                if (Test-Path -LiteralPath $destination) {
                    $remote=Invoke-Command -Session $session -ArgumentList $file.FullName -ScriptBlock {param($path);(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
                    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -cne $remote) {throw 'Existing public journal changed; capture not overwritten.'}
                } else {Copy-Item -LiteralPath $file.FullName -Destination $destination -FromSession $session}
            }
        } finally {Remove-PSSession $session}
    }
    if ($password) {$password.Dispose()};$credential=$null;$admin=$null;$saved=$null
}
