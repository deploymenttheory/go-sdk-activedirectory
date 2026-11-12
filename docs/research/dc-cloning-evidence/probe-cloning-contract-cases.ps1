#Requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$profile='H:\ad-sdk-lab\server2025'
$output='H:\ad-sdk-lab\cloning-contract-cases-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'.json'
$guest=Join-Path $PSScriptRoot 'guest-cloning-contract-cases.ps1'
foreach($path in @($output,(Join-Path $profile 'state.json'),(Join-Path $profile 'credential.clixml'),$guest)) {
    for($cursor=$path;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Fixture path traverses a reparse point.'}
    }
}
if(Test-Path -LiteralPath $output){throw 'Fixture output already exists.'}
$state=Get-Content -LiteralPath (Join-Path $profile 'state.json') -Raw | ConvertFrom-Json
if($state.id -ne '60197892-ec9f-4c19-abe8-34dc60d473e5'){throw 'Expected disposable lab identity changed.'}
$machine=@($state.machines | Where-Object role -eq 'dc1')[0]
if($machine.id -ne 'a364b1d0-7868-47f1-ab29-a5e80c97aa4b' -or $machine.name -ne 'ADSDK25DC1'){throw 'Expected controller identity changed.'}
Import-Module Hyper-V
$vm=Get-VM -Id ([guid]$machine.id)
if($vm.Name -ne $machine.name -or $vm.Notes -ne "ad-sdk-lab:$($state.id)" -or $vm.State -ne 'Running'){throw 'Owned running controller was not found.'}
$saved=Import-Clixml -LiteralPath (Join-Path $profile 'credential.clixml')
$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
$sourceHash=(Get-FileHash -LiteralPath $guest).Hash
$session=$null
try {
    $session=New-PSSession -VMId ([guid]$machine.id) -Credential $credential
    $payload=Invoke-Command -Session $session -FilePath $guest -ArgumentList $machine.name
    $data=$payload | ConvertFrom-Json
    [ordered]@{schema_version=1;lab_id=$state.id;vm_id=$machine.id;guest_script_sha256=$sourceHash;kind='reference-observation-with-owned-fixture-cleanup';observation=$data} | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $output -Encoding UTF8
    if((Get-FileHash -LiteralPath $guest).Hash -ne $sourceHash){throw 'Guest fixture source changed during execution.'}
    [pscustomobject]@{output=$output;passed=$data.passed;cases=@($data.cases).Count;generation=@($data.generation).Count;cleanup=$data.cleanup;error=$data.error;observations=@($data.cases | ForEach-Object {[pscustomobject]@{name=$_.name;count=@($_.entries).Count;error=$_.error}})} | ConvertTo-Json -Depth 6
    if(-not $data.passed){throw 'Cloning contract fixture did not fully execute and clean up; inspect its artifact.'}
} finally {if($session){Remove-PSSession -Session $session}}
