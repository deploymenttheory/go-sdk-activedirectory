#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedSourceCommit
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert-UnlinkedPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Qualification path traverses a reparse point.' }
    }
    return $full
}
$null=Assert-UnlinkedPath $ManifestPath
$build=Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if($build.source_commit -cne $ExpectedSourceCommit -or $build.status -ne 'built') { throw 'Build source identity differs.' }
$profile='H:\ad-sdk-lab\server2025'
$resultRoot=Assert-UnlinkedPath (Join-Path $build.directory 'server2025-native-resources')
if(-not $resultRoot.StartsWith('H:\ad-sdk-lab\qualifications\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $resultRoot)) { throw 'Unexpected or existing qualification output.' }
$guest=Join-Path $PSScriptRoot 'guest-cloning-native-resources.ps1'
foreach($path in @($build.test_executable,$guest,(Join-Path $profile 'state.json'),(Join-Path $profile 'credential.clixml'))) { $null=Assert-UnlinkedPath $path }
if((Get-FileHash -LiteralPath $build.test_executable).Hash -cne $build.test_executable_sha256) { throw 'Native build hash differs.' }
$state=Get-Content -LiteralPath (Join-Path $profile 'state.json') -Raw | ConvertFrom-Json
if($state.id -ne '60197892-ec9f-4c19-abe8-34dc60d473e5' -or $state.switch_id -ne '18cf982f-8c11-45cd-8581-fc2a00648deb') { throw 'Disposable lab identity differs.' }
$machine=@($state.machines | Where-Object role -eq 'dc1')[0]
if($machine.id -ne 'a364b1d0-7868-47f1-ab29-a5e80c97aa4b' -or $machine.name -ne 'ADSDK25DC1') { throw 'Controller identity differs.' }
Import-Module Hyper-V
function Assert-OwnedController {
    $current=Get-Content -LiteralPath (Join-Path $profile 'state.json') -Raw | ConvertFrom-Json
    if($current.id -ne $state.id -or $current.switch_id -ne $state.switch_id) { throw 'Lab state changed.' }
    $switch=Get-VMSwitch -Id ([guid]$state.switch_id)
    if($switch.Name -ne $state.switch_name -or $switch.Notes -ne "ad-sdk-lab:$($state.id)" -or $switch.SwitchType -ne 'Private') { throw 'Private switch ownership differs.' }
    $vm=Get-VM -Id ([guid]$machine.id)
    if($vm.Name -ne $machine.name -or $vm.Notes -ne "ad-sdk-lab:$($state.id)" -or $vm.State -ne 'Running') { throw 'Owned running controller differs.' }
    $paths=@($vm.Path)+@(Get-VMHardDiskDrive -VM $vm | ForEach-Object { $_.Path })
    if($paths.Count -lt 2) { throw 'Expected owned controller disk is missing.' }
    foreach($path in $paths) {
        $full=Assert-UnlinkedPath $path
        if(-not $full.StartsWith($profile+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Controller path or disk lies outside owned profile.' }
    }
    $adapters=@(Get-VMNetworkAdapter -VM $vm)
    if($adapters.Count -ne 1 -or $adapters[0].SwitchId.ToString() -ne $state.switch_id) { throw 'Controller network isolation differs.' }
}
Assert-OwnedController
$sourceHash=(Get-FileHash -LiteralPath $guest).Hash
$hostHash=(Get-FileHash -LiteralPath $PSCommandPath).Hash
$saved=Import-Clixml -LiteralPath (Join-Path $profile 'credential.clixml')
$credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
$null=New-Item -ItemType Directory -Path $resultRoot
$snapshot=Join-Path $resultRoot 'guest-cloning-native-resources.ps1'
Copy-Item -LiteralPath $guest -Destination $snapshot
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $resultRoot 'run-cloning-native-resources.ps1')
if((Get-FileHash -LiteralPath $snapshot).Hash -cne $sourceHash) { throw 'Guest snapshot differs.' }
$target='C:\ad-sdk-validation\'+$build.run+'-resources'
$session=$null;$created=$false;$data=$null;$failure=$null;$cleanupFailure=$null;$sessionFailure=$null;$captureFailure=$null;$rawReportSHA256=$null
try {
    Assert-OwnedController
    $session=New-PSSession -VMId ([guid]$machine.id) -Credential $credential
    Invoke-Command -Session $session -ArgumentList $target,$build.run -ScriptBlock {
        param($Directory,$Run)
        $ErrorActionPreference='Stop'
        if([IO.Path]::GetFileName($Directory) -cne ($Run+'-resources') -or -not ([IO.Path]::GetFullPath($Directory)).StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $Directory)) { throw 'Unexpected or existing guest staging directory.' }
        for($cursor=$Directory;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked guest staging directory.' } }
        $null=New-Item -ItemType Directory -Path $Directory
        [IO.File]::WriteAllText((Join-Path $Directory 'owner.txt'),$Run)
    }
    $created=$true
    Assert-OwnedController
    Copy-Item -LiteralPath $build.test_executable -Destination "$target\dccloning.test.exe" -ToSession $session
    Assert-OwnedController
    $payload=Invoke-Command -Session $session -FilePath $snapshot -ArgumentList $machine.name,"$target\dccloning.test.exe",$build.test_executable_sha256
    $data=$payload | ConvertFrom-Json
    [IO.File]::WriteAllText((Join-Path $resultRoot 'reference.json'),($data | ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
} catch { $failure=$_ }
finally {
    if($session) {
        if($created) {
            try {
                Assert-OwnedController
                $rawReportSHA256=Invoke-Command -Session $session -ArgumentList "$target\native-resources.json" -ScriptBlock {
                    param($Path)
                    $ErrorActionPreference='Stop'
                    (Get-FileHash -LiteralPath $Path).Hash
                }
                Copy-Item -FromSession $session -LiteralPath "$target\native-resources.json" -Destination (Join-Path $resultRoot 'native-resources.json')
                if((Get-FileHash -LiteralPath (Join-Path $resultRoot 'native-resources.json')).Hash -cne $rawReportSHA256) { throw 'Copied resource report hash differs; preserve guest staging.' }
            } catch { $captureFailure=$_ }
            try {
                if($captureFailure) { throw 'Resource report capture failed; guest staging is preserved.' }
                Assert-OwnedController
                Invoke-Command -Session $session -ArgumentList $target,$build.run -ScriptBlock {
                    param($Directory,$Run)
                    $ErrorActionPreference='Stop'
                    if([IO.Path]::GetFileName($Directory) -cne ($Run+'-resources') -or -not ([IO.Path]::GetFullPath($Directory)).StartsWith('C:\ad-sdk-validation\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Guest cleanup path differs.' }
                    for($cursor=$Directory;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) { if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked guest cleanup directory.' } }
                    if([IO.File]::ReadAllText((Join-Path $Directory 'owner.txt')) -cne $Run) { throw 'Guest staging ownership differs.' }
                    $running=@(Get-CimInstance Win32_Process -Filter "Name='dccloning.test.exe'" | Where-Object { $_.ExecutablePath -eq (Join-Path $Directory 'dccloning.test.exe') })
                    if($running.Count) { throw 'Owned native child is still running; staging files are preserved.' }
                    $files=@(Get-ChildItem -LiteralPath $Directory -Force)
                    foreach($file in $files) { if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Name -notin @('owner.txt','dccloning.test.exe','native-resources.json')) { throw 'Unexpected staging file is preserved.' } }
                    foreach($file in $files) { Remove-Item -LiteralPath $file.FullName -Force }
                    [IO.Directory]::Delete($Directory,$false)
                    if(Test-Path -LiteralPath $Directory) { throw 'Guest staging directory remains.' }
                }
            } catch { $cleanupFailure=$_ }
        }
        try { Remove-PSSession -Session $session } catch { $sessionFailure=$_ }
    }
}
$passed=($null -eq $failure -and $null -eq $cleanupFailure -and $null -eq $sessionFailure -and $null -eq $captureFailure -and $null -ne $data -and $data.passed)
$record=[ordered]@{
    schema_version=1;run=$build.run;timestamp=[DateTime]::UtcNow.ToString('o');source_commit=$build.source_commit
    source_archive_sha256=$build.source_archive_sha256;binary_sha256=$build.test_executable_sha256
    guest_script_sha256=$sourceHash;host_script_sha256=$hostHash;lab_id=$state.id;vm_id=$machine.id
    ownership_guards='Exact lab/VM/switch identity, owned unlinked VM/disk paths, one adapter on private owned switch before guest actions'
    staging_cleanup=($created -and $null -eq $cleanupFailure);passed=[bool]$passed
    error=$(if($failure){$failure.Exception.Message}else{$null})
    cleanup_error=$(if($cleanupFailure){$cleanupFailure.Exception.Message}else{$null})
    session_cleanup_error=$(if($sessionFailure){$sessionFailure.Exception.Message}else{$null})
    capture_error=$(if($captureFailure){$captureFailure.Exception.Message}else{$null})
    raw_resource_report_sha256=$rawReportSHA256
    reference_sha256=$(if(Test-Path -LiteralPath (Join-Path $resultRoot 'reference.json')){(Get-FileHash -LiteralPath (Join-Path $resultRoot 'reference.json')).Hash}else{$null})
}
[IO.File]::WriteAllText((Join-Path $resultRoot 'qualification.json'),($record | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
[pscustomobject]@{directory=$resultRoot;passed=$passed;iterations=$(if($data -and $data.report){$data.report.iterations_completed}else{0});error=$record.error;cleanup_error=$record.cleanup_error;guest_error=$(if($data){$data.error}else{$null})} | ConvertTo-Json -Depth 6
if(-not $passed) { throw 'Native cloning fixture qualification failed; inspect retained evidence. No automatic retry.' }
