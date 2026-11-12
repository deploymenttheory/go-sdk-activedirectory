#Requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$profile='H:\ad-sdk-lab\server2025'
$output='H:\ad-sdk-lab\cloning-program-fixture-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'.json'
foreach($path in @($output,(Join-Path $profile 'state.json'),(Join-Path $profile 'credential.clixml'))) {
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
$session=$null
try {
    $session=New-PSSession -VMId ([guid]$machine.id) -Credential $credential
    $payload=Invoke-Command -Session $session -ArgumentList $machine.name -ScriptBlock {
        param($ExpectedComputer)
        $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
        if($env:COMPUTERNAME -ne $ExpectedComputer){throw 'Guest identity mismatch.'}
        $computer=Get-CimInstance Win32_ComputerSystem -Property DomainRole
        if($computer.DomainRole -notin @(4,5)){throw 'Cloning fixture requires a domain controller.'}
        Import-Module ActiveDirectory
        $token=[guid]::NewGuid().ToString('N')
        $prefix='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
        $created=@();$cleanupErrors=@();$failure=$null
        $record=[ordered]@{timestamp=[DateTime]::UtcNow.ToString('o');fixture=$token;computer=$env:COMPUTERNAME;module=(Get-Module ActiveDirectory).Version.ToString();before=@();during=@();after=@();fixtures=@();cleanup=@();error=$null;passed=$false}
        $command=Get-Command Get-ADDCCloningExcludedApplicationList
        $assemblyPath=$command.ImplementingType.Assembly.Location
        $build=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $record.os_full_build="$($build.CurrentBuildNumber).$($build.UBR)"
        $record.module_file_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($assemblyPath).FileVersion
        $record.module_file_sha256=(Get-FileHash -LiteralPath $assemblyPath).Hash
        function Read-Exclusions {return @(Get-ADDCCloningExcludedApplicationList -ErrorAction Stop | ForEach-Object {[ordered]@{name=[string]$_.Name;type=[string]$_.Type}})}
        try {
            $record.before=Read-Exclusions
            foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
                $name="ADSDK-Cloning-$token-$view"
                $display="ADSDK & Clone <Probe> $view $token"
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
                try {
                    $existing=$base.OpenSubKey($prefix+$name,$false)
                    if($existing){$existing.Dispose();throw 'Fixture registry key already exists.'}
                    $item=$base.CreateSubKey($prefix+$name,$true)
                    try {
                        $item.SetValue('ADSDKFixture',$token,[Microsoft.Win32.RegistryValueKind]::String)
                        $created+=@([pscustomobject]@{view=$view;name=$name;display=$display})
                        $item.SetValue('DisplayName',$display,[Microsoft.Win32.RegistryValueKind]::String)
                        $item.SetValue('DisplayVersion','7.3.1',[Microsoft.Win32.RegistryValueKind]::String)
                        $item.SetValue('Publisher','AD SDK disposable qualification',[Microsoft.Win32.RegistryValueKind]::String)
                    } finally {$item.Dispose()}
                } finally {$base.Dispose()}
                $record.fixtures+=@([ordered]@{view=$view.ToString();key=$name;display_name=$display;display_version='7.3.1'})
            }
            $record.during=Read-Exclusions
        } catch {$failure=$_;$record.error=[ordered]@{type=$_.Exception.GetType().FullName;message=$_.Exception.Message}}
        finally {
            foreach($fixture in $created) {
                try {
                    if($fixture.name -cne "ADSDK-Cloning-$token-$($fixture.view)"){throw 'Fixture cleanup name mismatch.'}
                    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$fixture.view)
                    try {
                        $item=$base.OpenSubKey($prefix+$fixture.name,$false)
                        if(-not $item){throw 'Owned fixture unexpectedly disappeared.'}
                        try {
                            if($item.GetValue('ADSDKFixture') -cne $token -or $item.SubKeyCount -ne 0){throw 'Fixture ownership or child-key guard failed.'}
                            $allowed=@('ADSDKFixture','DisplayName','DisplayVersion','Publisher')
                            if(@($item.GetValueNames() | Where-Object {$_ -notin $allowed}).Count){throw 'Unrelated fixture registry values appeared.'}
                        } finally {$item.Dispose()}
                        $base.DeleteSubKey($prefix+$fixture.name,$true)
                        $remaining=$base.OpenSubKey($prefix+$fixture.name,$false)
                        if($remaining){$remaining.Dispose();throw 'Fixture registry key remains.'}
                        $record.cleanup+=@([ordered]@{view=$fixture.view.ToString();key=$fixture.name;absent=$true})
                    } finally {$base.Dispose()}
                } catch {$cleanupErrors+=@($_.Exception.Message)}
            }
            try {$record.after=Read-Exclusions} catch {$cleanupErrors+=@($_.Exception.Message)}
        }
        $before=@($record.before | ForEach-Object {"$($_.type)`t$($_.name)"} | Sort-Object)
        $after=@($record.after | ForEach-Object {"$($_.type)`t$($_.name)"} | Sort-Object)
        $record.cleanup_errors=$cleanupErrors
        $record.baseline_restored=(@(Compare-Object $before $after).Count -eq 0)
        $record.passed=($null -eq $failure -and $cleanupErrors.Count -eq 0 -and $created.Count -eq 2 -and $record.cleanup.Count -eq 2 -and $record.baseline_restored)
        $record | ConvertTo-Json -Depth 9 -Compress
    }
    $data=$payload | ConvertFrom-Json
    [ordered]@{schema_version=1;lab_id=$state.id;vm_id=$machine.id;observation=$data} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $output -Encoding UTF8
    [pscustomobject]@{output=$output;passed=$data.passed;before=@($data.before).Count;during=@($data.during).Count;after=@($data.after).Count;fixture_entries=@($data.during | Where-Object {$_.name -like "*$($data.fixture)*"});cleanup=$data.cleanup;error=$data.error;cleanup_errors=$data.cleanup_errors} | ConvertTo-Json -Depth 5
    if(-not $data.passed){throw 'Cloning program fixture did not fully qualify and clean up; inspect its artifact.'}
} finally {if($session){Remove-PSSession -Session $session}}
