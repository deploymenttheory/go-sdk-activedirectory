#Requires -Version 7.0
<#
.SYNOPSIS
Produces and transfers independent MIT credentials for a prepared lab account.
.DESCRIPTION
Run through the approved lab workflow after kerberos-account.ps1 Prepare and
after moving the owned Linux client to the same private profile. MIT tools are
lab reference tools, never SDK runtime dependencies. Generate sends the dedicated
password through pinned SSH stdin. Export transfers credentials in memory to the
existing private host directory; retained JSON contains metadata only.
VerifyExpiry proves that the same MIT-issued TGT bytes have really expired.
No clock, global Kerberos configuration or directory policy is changed here.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Generate','Export','VerifyExpiry')][string]$Action,
    [Parameter(Mandatory)][string]$RunId,
    [ValidateSet('2016','2019','2022','2025')][string]$ServerVersion='2025',
    [string]$LabRoot='H:\ad-sdk-lab'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($RunId-cnotmatch'\A[a-z0-9][a-z0-9-]{5,39}\z'){throw 'Invalid owned reference run.'}
$capture=[IO.Path]::GetFullPath((Join-Path (Join-Path $LabRoot 'portable-kerberos') $RunId))
$secretRoot=Join-Path $capture 'secrets'
for($path=$secretRoot;$path;$path=[IO.Path]::GetDirectoryName($path)){
    if((Test-Path -LiteralPath $path)-and((Get-Item -LiteralPath $path -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Reference paths cannot traverse reparse points.'}
}
if(-not(Get-Acl -LiteralPath $secretRoot).AreAccessRulesProtected){throw 'Expected protected host credential directory.'}
$prepared=Get-Content -LiteralPath (Join-Path $capture 'prepare.json') -Raw|ConvertFrom-Json
$linuxRoot=Join-Path $LabRoot 'linux-client'
$linux=Get-Content -LiteralPath (Join-Path $linuxRoot 'state.json') -Raw|ConvertFrom-Json
$expectedServer='adsdk'+$ServerVersion.Substring(2)+'dc1.ad.sdk.test'
if($prepared.run_id-cne$RunId-or$prepared.server-cne$expectedServer-or$linux.server_version-cne$ServerVersion){throw 'Reference account/Linux profile identity differs.'}
$helper=Join-Path $PSScriptRoot 'portable-linux.ps1'
$program=if($Action-ceq'Generate'){'kerberos-reference.py'}else{'kerberos-reference-export.py'}
$source=Join-Path $PSScriptRoot $program
$remoteName=$program.Replace('.py',('-'+$RunId+'.py'))
$upload=& $helper Upload -ServerVersion $ServerVersion -LabRoot $LabRoot -StorageRoot $linuxRoot -LocalFile $source -RemoteName $remoteName
if(-not$upload.remote_digest_verified){throw 'Independent MIT program upload was not verified.'}
$digest=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$sourceCopy=Join-Path $capture ($program.Replace('.py',('-'+$digest+'.py')))
if(Test-Path -LiteralPath $sourceCopy){
    if((Get-FileHash -LiteralPath $sourceCopy -Algorithm SHA256).Hash.ToLowerInvariant()-cne$digest){throw 'Retained MIT source changed.'}
}else{Copy-Item -LiteralPath $source -Destination $sourceCopy}
$request=@{run_id=$RunId;linux_owner=$linux.id}
if($Action-ceq'Generate'){
    $credential=Import-Clixml -LiteralPath (Join-Path $secretRoot 'client.clixml')
    if($credential.UserName-cne$prepared.upn){throw 'Dedicated reference credential identity differs.'}
    $plain=$credential.GetNetworkCredential().Password
    $secret=[Text.Encoding]::UTF8.GetBytes($plain);$plain=$null
    try{
        $request.principal=$prepared.upn;$request.client_kvno=[int]$prepared.client_kvno
        $request.server=$prepared.server;$request.password_base64=[Convert]::ToBase64String($secret)
    }finally{[Array]::Clear($secret,0,$secret.Length);$secret=$null;$credential=$null}
}
$inputBytes=[Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Compress));$request=$null
$response=$null;$envelope=$null
function Write-ReferencePublicRecord([string]$Path,$Value){
    $full=[IO.Path]::GetFullPath($Path)
    if(-not$full.StartsWith($capture+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Public reference record escaped its capture root.'}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 18))
    $stream=[IO.File]::Open($full,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
try{
    $command='python3 /home/adsdk/acceptance/'+$remoteName
    if($Action-ceq'VerifyExpiry'){$command+=' --expiry-only'}
    $response=& $helper Exec -ServerVersion $ServerVersion -LabRoot $LabRoot -StorageRoot $linuxRoot -Command $command -InputBytes $inputBytes
    if($response.exit_code-ne0){throw ('MIT reference '+$Action+' failed; no tool input or private payload is included in this error.')}
    $stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ').ToLowerInvariant()
    if($Action-ceq'Generate'){
        $metadata=$response.stdout|ConvertFrom-Json
        if($metadata.run_id-cne$RunId-or$metadata.principal-cne$prepared.upn-or$metadata.sdk_runtime_used){throw 'MIT generation metadata identity differs.'}
        $path=Join-Path $capture ('mit-generation-'+$stamp+'.json')
        Write-ReferencePublicRecord $path $metadata
        [pscustomobject]@{run_id=$RunId;action=$Action;metadata=$path;producer_sha256=$digest;directory=$metadata.directory;password_persisted_by_runner=$false}
        return
    }
    $envelope=$response.stdout|ConvertFrom-Json
    if($envelope.manifest.run_id-cne$RunId-or$envelope.manifest.principal-cne$prepared.upn-or$envelope.manifest.sdk_runtime_used-or$envelope.manifest.clock_changed){throw 'MIT export metadata identity differs.'}
    if($Action-ceq'VerifyExpiry'){
        if(-not$envelope.manifest.expiry_observed-or@($envelope.secret_payload.PSObject.Properties).Count-ne0){throw 'Real unchanged-ticket expiry not proved.'}
        $path=Join-Path $capture ('mit-expiry-'+$stamp+'.json')
        Write-ReferencePublicRecord $path $envelope.manifest
        [pscustomobject]@{run_id=$RunId;action=$Action;metadata=$path;real_expiry_verified=$true;clock_changed=$false}
        return
    }
    $names=@('client.keytab','tgt-only.ccache','password.ccache','keytab.ccache','expiry-probe-2m.ccache')
    if(@($envelope.secret_payload.PSObject.Properties).Count-ne$names.Count){throw 'Unexpected private credential export fields.'}
    $transferred=@()
    foreach($name in $names){
        $target=Join-Path $secretRoot $name
        $bytes=[Convert]::FromBase64String($envelope.secret_payload.$name)
        try{
            $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
            if($hash-cne$envelope.manifest.metadata.$name.sha256-or$bytes.Length-ne$envelope.manifest.metadata.$name.bytes){throw 'Reference transfer hash/size differs.'}
            if(Test-Path -LiteralPath $target){
                $item=Get-Item -LiteralPath $target -Force
                if($item.PSIsContainer-or$item.Attributes-band[IO.FileAttributes]::ReparsePoint-or(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()-cne$hash){throw 'Existing owned reference credential changed.'}
            }else{
                $stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
            }
            if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()-cne$hash){throw 'Reference host-file readback differs.'}
            $transferred+=[pscustomobject]@{name=$name;sha256=$hash;bytes=$bytes.Length;private_host_file=$target}
        }finally{[Array]::Clear($bytes,0,$bytes.Length);$bytes=$null}
    }
    $metadataPath=Join-Path $capture ('mit-reference-'+$stamp+'.json')
    Write-ReferencePublicRecord $metadataPath $envelope.manifest
    $canonical=Join-Path $capture 'mit-reference.json'
    if(-not(Test-Path -LiteralPath $canonical)){Write-ReferencePublicRecord $canonical $envelope.manifest}
    $transfer=[pscustomobject]@{run_id=$RunId;encrypted_transfer='pinnedSSH via PowerShell Direct';source_and_host_digests_verified=$true;exporter_sha256=$digest;files=$transferred}
    Write-ReferencePublicRecord (Join-Path $capture ('credential-transfer-'+$stamp+'.json')) $transfer
    $canonical=Join-Path $capture 'credential-transfer.json'
    if(-not(Test-Path -LiteralPath $canonical)){Write-ReferencePublicRecord $canonical $transfer}
    [pscustomobject]@{run_id=$RunId;action=$Action;metadata=$metadataPath;files=$names;private_host_files_verified=$true;real_expiry_verified=$envelope.manifest.expiry_observed}
}finally{[Array]::Clear($inputBytes,0,$inputBytes.Length);$inputBytes=$null;$response=$null;$envelope=$null}
