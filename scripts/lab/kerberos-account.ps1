# Host-side preparation for one existing private AD lab profile.
# Prepare creates a dedicated marker-owned account and a DPAPI-protected host
# credential; it leaves DC policies unchanged. Validate also applies strict
# policy and verifies exact policy/account cleanup. Registry readback does not
# prove enforcement. Run through the approved PowerShell Direct lab workflow.
#Requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Validate','Prepare')][string]$Action='Validate',
    [ValidateSet('2016','2019','2022','2025')][string]$ServerVersion='2025',
    [string]$LabRoot='H:\ad-sdk-lab',
    [string]$RunId=('sdk04-'+$ServerVersion+'-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')).ToLowerInvariant()
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($RunId -cnotmatch '\A[a-z0-9][a-z0-9-]{5,39}\z'){throw 'Invalid account fixture run identity.'}
$helper=Join-Path $PSScriptRoot 'kerberos-fixture.ps1'
. $helper
$names=Get-KerberosFixtureNames $RunId
Import-Module Hyper-V
$profileRoot=[IO.Path]::GetFullPath((Join-Path $LabRoot ('server'+$ServerVersion)))
$labProfile=Get-Content -LiteralPath (Join-Path $profileRoot 'state.json') -Raw|ConvertFrom-Json
if([IO.Path]::GetFullPath($labProfile.root)-cne$profileRoot-or$labProfile.server_version-cne$ServerVersion-or$labProfile.domain-cne'ad.sdk.test'){throw 'Owned lab profile identity differs.'}
$switch=Get-VMSwitch -Id ([guid]$labProfile.switch_id)
if($switch.SwitchType-ne'Private'-or$switch.Name-cne('ad-sdk-'+$ServerVersion)-or$switch.Notes-cne("ad-sdk-lab:"+$labProfile.id)){throw 'Owned lab private switch differs.'}
$dc=$labProfile.machines|Where-Object {$_.role -ceq 'dc1'}
$vm=Get-VM -Id ([guid]$dc.id)
$nics=@(Get-VMNetworkAdapter -VM $vm)
if($vm.Name -cne $dc.name -or $vm.Notes -cne "ad-sdk-lab:$($labProfile.id)" -or $vm.State -ne 'Running' -or $nics.Count -ne 1 -or $nics[0].SwitchId.ToString() -cne $labProfile.switch_id){throw 'Owned DC identity mismatch.'}
$server="$($dc.name).$($labProfile.domain)".ToLowerInvariant()
$saved=Import-Clixml -LiteralPath (Join-Path $profileRoot 'credential.clixml')
$admin=[PSCredential]::new(($labProfile.netbios+'\Administrator'),$saved.Password)
$root=[IO.Path]::GetFullPath((Join-Path $LabRoot 'portable-kerberos'))
$capture=[IO.Path]::GetFullPath((Join-Path $root $RunId))
if(-not $capture.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path $capture)){throw 'Credential fixture storage must be fresh and owned.'}
for($cursor=$root;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)){
    if((Test-Path -LiteralPath $cursor)-and((Get-Item -LiteralPath $cursor -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Credential paths cannot traverse reparse points.'}
}
$secrets=Join-Path $capture 'secrets'
$null=New-Item -ItemType Directory -Path $secrets -Force
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
$identities=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)|Select-Object -Unique
foreach($sid in $identities){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit, ObjectInherit','None','Allow'))}
Set-Acl -LiteralPath $secrets -AclObject $acl
$random=[byte[]]::new(48);$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
try{$rng.GetBytes($random)}finally{$rng.Dispose()}
$passwordText='Sdk4!'+[Convert]::ToBase64String($random)+'a9'
[Array]::Clear($random,0,$random.Length)
$password=ConvertTo-SecureString -String $passwordText -AsPlainText -Force
$passwordText=$null
$credential=[PSCredential]::new($names.upn,$password)
$credentialFile=Join-Path $secrets 'client.clixml'
$credential|Export-Clixml -LiteralPath $credentialFile
$sourceCopy=Join-Path $capture 'kerberos-fixture.ps1'
Copy-Item -LiteralPath $helper -Destination $sourceCopy
$session=$null;$newAttempted=$false;$prepared=$null
$codeRoot="C:\adsdk-kerberos-code\$RunId"
try{
    $session=New-PSSession -VMId $vm.Id -Credential $admin
    Invoke-Command -Session $session -ArgumentList $codeRoot -ScriptBlock {
        param($directory)
        $ErrorActionPreference='Stop'
        if($directory -cnotmatch '\AC:\\adsdk-kerberos-code\\[a-z0-9][a-z0-9-]{5,39}\z' -or(Test-Path -LiteralPath $directory)){throw 'Fresh code path required.'}
        foreach($path in @('C:\adsdk-kerberos-code',$directory)){if((Test-Path -LiteralPath $path)-and((Get-Item -LiteralPath $path -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Code path cannot be a reparse point.'}}
        $null=New-Item -ItemType Directory -Path $directory -Force
        $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit, ObjectInherit','None','Allow'))}
        Set-Acl -LiteralPath $directory -AclObject $acl
    }
    $guestSource=Join-Path $codeRoot 'kerberos-fixture.ps1'
    Copy-Item -LiteralPath $helper -Destination $guestSource -ToSession $session
    $expectedHash=(Get-FileHash $helper -Algorithm SHA256).Hash
    Invoke-Command -Session $session -ArgumentList $guestSource,$expectedHash -ScriptBlock {param($source,$expected);if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash-cne$expected){throw 'Guest helper source digest differs.'}}
    $newAttempted=$true
    $prepared=Invoke-Command -Session $session -ArgumentList $guestSource,$RunId,$server,$password -ScriptBlock {
        param($source,$run,$expected,[SecureString]$secret)
        $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
        # Every fixture command selects its DC explicitly; avoid an ambient
        # AD provider drive lookup in this temporary PowerShell Direct session.
        $env:ADPS_LoadDefaultDrive='0'
        . $source
        New-KerberosDirectoryFixture $run $expected $secret
    }
    $prepared|Add-Member -NotePropertyName server_version -NotePropertyValue $ServerVersion
    $prepared|ConvertTo-Json -Depth 12|Set-Content (Join-Path $capture 'prepare.json') -Encoding utf8
    if($Action -ceq 'Validate'){
        $policy=Invoke-Command -Session $session -ArgumentList $guestSource,$RunId,$server -ScriptBlock {param($source,$run,$expected);$ErrorActionPreference='Stop';. $source;Set-KerberosFixtureStrictPolicy $run $expected}
        $policy|ConvertTo-Json -Depth 8|Set-Content (Join-Path $capture 'strict-policy-readback.json') -Encoding utf8
    }
    [pscustomobject]@{run_id=$RunId;action=$Action;server_version=$ServerVersion;server=$server;principal=$names.upn;client_guid=$prepared.client_guid;client_kvno=$prepared.client_kvno;capture=$capture;credential_file=$credentialFile;policy_applied=($Action-ceq'Validate')}
}finally{
    if($session){
        try{
            if($Action -ceq 'Validate' -or -not $prepared){
                if($newAttempted){
                    $cleanup=Invoke-Command -Session $session -ArgumentList $guestSource,$RunId,$server -ScriptBlock {
                        param($source,$run,$expected)
                        $ErrorActionPreference='Stop';. $source
                        $directory=Get-KerberosFixtureDirectory $run
                        if(Test-Path -LiteralPath (Join-Path $directory 'state.json')){Remove-KerberosDirectoryFixture $run $expected}
                        else{[pscustomobject]@{run_id=$run;verified=$true;journal_never_created=$true}}
                    }
                    $cleanup|ConvertTo-Json -Depth 12|Set-Content (Join-Path $capture 'cleanup.json') -Encoding utf8
                    if(-not $cleanup.verified){throw 'Independent account/policy cleanup not verified.'}
                }
                if(Test-Path -LiteralPath $credentialFile){Remove-Item -LiteralPath $credentialFile -Force}
            }
        }finally{Remove-PSSession $session}
    }
    $password=$null;$credential=$null
}
