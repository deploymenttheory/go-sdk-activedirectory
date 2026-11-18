#Requires -Version 7.0
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$lab='H:\ad-sdk-lab';$version='2025'
$profile=Get-Content -LiteralPath "$lab\server$version\state.json" -Raw|ConvertFrom-Json
if($profile.id-cne'60197892-ec9f-4c19-abe8-34dc60d473e5'-or$profile.server_version-cne$version-or$profile.domain-cne'ad.sdk.test'){throw 'Owned reference profile differs.'}
Import-Module Hyper-V
$switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
if($switch.SwitchType-ne'Private'-or$switch.Name-cne'ad-sdk-2025'-or$switch.Notes-cne('ad-sdk-lab:'+$profile.id)){throw 'Reference isolation differs.'}
$machine=@($profile.machines|Where-Object role -CEQ dc1)
if($machine.Count-ne1){throw 'Ambiguous reference DC.'}
$vm=Get-VM -Id ([guid]$machine[0].id);$nics=@(Get-VMNetworkAdapter -VM $vm)
if($vm.Name-cne'ADSDK25DC1'-or$vm.Notes-cne('ad-sdk-lab:'+$profile.id)-or$vm.State-ne'Running'-or$nics.Count-ne1-or$nics[0].SwitchId.ToString()-cne$profile.switch_id){throw 'Owned reference DC changed.'}
$run=('sdk06-cas-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')).ToLowerInvariant()
$capture=[IO.Path]::GetFullPath("$lab\portable-security-descriptors\$run")
if(-not$capture.StartsWith("$lab\portable-security-descriptors\",[StringComparison]::OrdinalIgnoreCase)-or(Test-Path -LiteralPath $capture)){throw 'Fresh owned capture required.'}
for($cursor=[IO.Path]::GetDirectoryName($capture);$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)){
 if((Test-Path -LiteralPath $cursor)-and((Get-Item -LiteralPath $cursor -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Capture crosses a reparse point.'}
}
$null=New-Item -ItemType Directory -Path $capture -Force
$sourcePath=Join-Path $PSScriptRoot 'sdk06-sd-cas-guest.ps1'
$source=[IO.File]::ReadAllText($sourcePath);$hash=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $capture 'source-guest.ps1')
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $capture 'source-host.ps1')
$saved=Import-Clixml -LiteralPath "$lab\server$version\credential.clixml"
$admin=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
$session=New-PSSession -VMId $vm.Id -Credential $admin
try{
 $result=Invoke-Command -Session $session -ArgumentList $source,$hash,$run,$admin -ScriptBlock {
  param($source,$expected,$run,[PSCredential]$credential)
  $ErrorActionPreference='Stop'
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$actual=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($source)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  if($actual-cne$expected){throw 'Executed reference source differs.'}
  . ([scriptblock]::Create($source)) -RunId $run -Server 'adsdk25dc1.ad.sdk.test' -ReferenceCredential $credential
 }
 $result|Add-Member -NotePropertyName source_sha256 -NotePropertyValue $hash
 $result|ConvertTo-Json -Depth 22|Set-Content -LiteralPath (Join-Path $capture 'result.json') -Encoding utf8
 $journal='C:\adsdk-security-descriptor-reference\'+$run
 $files=Invoke-Command -Session $session -ArgumentList $journal -ScriptBlock {param($path);Get-ChildItem -LiteralPath $path -File|Where-Object Name -Match '\Aevent-[0-9]{4}\.json\z'|Select-Object Name,FullName}
 foreach($file in $files){Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $capture $file.Name) -FromSession $session}
 [pscustomobject]@{capture=$capture;run_id=$run;completed=$result.completed;cleanup_verified=$result.cleanup_verified;probe_results=@($result.probe_cases|Select-Object id,response,managed_ace_present,concurrent_ace_present,unchanged_after_rejection);failure_type=if($result.PSObject.Properties['failure_type']){$result.failure_type}else{$null};journal_count=@($files).Count}|ConvertTo-Json -Depth 8
}finally{Remove-PSSession $session;$admin=$null;$saved=$null}
