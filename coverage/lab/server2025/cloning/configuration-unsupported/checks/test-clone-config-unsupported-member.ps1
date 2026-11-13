#Requires -Version 5.1
param([Parameter(Mandatory)][string]$ReportPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:checks=0
function Check([bool]$Condition,[string]$Message) { $script:checks++;if(-not $Condition){throw $Message} }
function Reject([scriptblock]$Action,[string]$Message) { $failed=$false;try{& $Action}catch{$failed=$true};Check $failed $Message }
function Import-Functions([string]$Path,[string[]]$Names) {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    Check ($errors.Count -eq 0) ('Parse: '+$Path)
    foreach($name in $Names) {
        $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
        Check ($definitions.Count -eq 1) ('Function: '+$name)
        $text=$definitions[0].Extent.Text.Replace('function '+$name+' ','function script:'+$name+' ').Replace('function '+$name+'(','function script:'+$name+'(')
        . ([scriptblock]::Create($text))
    }
}
$hostFile=Join-Path $PSScriptRoot 'run-clone-config-unsupported-member.ps1';$guestFile=Join-Path $PSScriptRoot 'guest-clone-config-unsupported-member.ps1'
Import-Functions $hostFile @('Import-HostPrimitives','Assert-MemberOwnership','Wait-MemberJob','Read-MemberOutcome','Restore-OwnedMemberOff')
Import-Functions $guestFile @('Assert-GuestIdentity','Assert-UnsupportedWire')
Import-HostPrimitives (Join-Path $PSScriptRoot 'run-clone-config-offline.ps1')
Check ($null -ne (Get-Command Write-RunState -CommandType Function)) 'Frozen primitives imported without entrypoint.'
# Host mocks replace every external operation used below. No VM call executes.
$script:writes=@();$script:shutdowns=0;$script:ownershipChecks=0;$script:waitFailure=$false;$script:waitReturnsUncertain=$false
function Write-NewHostBytes($Path,$Bytes) { $script:writes+=@($Path) }
function Write-RunState {}
function Assert-OwnedControllers { $script:ownershipChecks++ }
function Assert-UnlinkedPath([string]$Path) { return [IO.Path]::GetFullPath($Path) }
$profile='H:\ad-sdk-lab\server2025';$machine=[pscustomobject]@{id='80aa4382-c228-489c-b5f7-007c7feee3ff'}
$script:mockDisk=Join-Path $profile 'ADSDK25MEM\os.vhdx';$script:mockParent=Join-Path $profile 'base.vhdx';$script:mockGeneration=2;$script:diskCount=1
function Get-VM { param($Id);return [pscustomobject]@{Generation=$script:mockGeneration} }
function Get-VMHardDiskDrive { param($VM);for($i=0;$i -lt $script:diskCount;$i++){[pscustomobject]@{Path=$script:mockDisk}} }
function Get-VHD { param($Path);return [pscustomobject]@{VhdType='Differencing';ParentPath=$script:mockParent} }
Assert-MemberOwnership;Check ($script:ownershipChecks -eq 1) 'Exact disk accepted.'
$script:mockDisk='H:\ad-sdk-lab\server2025\ADSDK25DC1\os.vhdx';Reject {Assert-MemberOwnership} 'Different owned disk rejected.'
$script:mockDisk=Join-Path $profile 'ADSDK25MEM\os.vhdx';$script:mockParent='H:\ad-sdk-lab\other\base.vhdx';Reject {Assert-MemberOwnership} 'Foreign parent rejected.'
$script:mockParent=Join-Path $profile 'base.vhdx';$script:diskCount=2;Reject {Assert-MemberOwnership} 'Additional disk rejected.'
$script:diskCount=1;$script:mockGeneration=1;Reject {Assert-MemberOwnership} 'Wrong generation rejected.';$script:mockGeneration=2
$computer=[pscustomobject]@{Name='ADSDK25MEM';DomainRole=2;PartOfDomain=$false};$os=[pscustomobject]@{ProductType=3;BuildNumber='26100'}
Assert-GuestIdentity $computer $os;Check $true 'Standalone Server accepted.'
$computer.PartOfDomain=$true;Reject {Assert-GuestIdentity $computer $os} 'Joined guest rejected.';$computer.PartOfDomain=$false
$computer.Name='ADSDK25DC1';Reject {Assert-GuestIdentity $computer $os} 'Wrong name rejected.';$computer.Name='ADSDK25MEM'
$computer.DomainRole=3;Reject {Assert-GuestIdentity $computer $os} 'Wrong role rejected.';$computer.DomainRole=2
$os.ProductType=1;Reject {Assert-GuestIdentity $computer $os} 'Client OS rejected.';$os.ProductType=3
$os.BuildNumber='20348';Reject {Assert-GuestIdentity $computer $os} 'Wrong Server release rejected.';$os.BuildNumber='26100'
$wire=[pscustomobject]@{protocol_version=1;operation='generate_config';data=[pscustomobject]@{outcome='not_written';checks_skipped=$false;prerequisites=[pscustomobject]@{complete=$false;role=[pscustomobject]@{machine_role=2}}};error_details=[pscustomobject]@{present=$true;not_domain_controller=$true}}
$process=[pscustomobject]@{completed=$true;process_uncertain=$false;error=$null;exit_code=1}
Assert-UnsupportedWire $wire $process 0;Check $true 'Omitted directory fields accepted safely.'
Reject {Assert-UnsupportedWire $wire $process 1} 'Output publication rejected.'
$wire.data.checks_skipped=$true;Reject {Assert-UnsupportedWire $wire $process 0} 'Offline result rejected.';$wire.data.checks_skipped=$false
$wire.error_details.not_domain_controller='true';Reject {Assert-UnsupportedWire $wire $process 0} 'String error flag rejected.';$wire.error_details.not_domain_controller=$true
$wire.error_details.not_domain_controller=$false;Reject {Assert-UnsupportedWire $wire $process 0} 'Untyped error category rejected.';$wire.error_details.not_domain_controller=$true
$wire.data.prerequisites|Add-Member -NotePropertyName source_host -NotePropertyValue 'ADSDK25DC1';Reject {Assert-UnsupportedWire $wire $process 0} 'Unexpected directory observation rejected.';$wire.data.prerequisites.PSObject.Properties.Remove('source_host')
$process.completed=$false;Reject {Assert-UnsupportedWire $wire $process 0} 'Unfinished native child rejected.';$process.completed=$true
$executionID='clone-config-unsupported-server2025-59346e9-v1';$resultRoot=Join-Path $PSScriptRoot 'offline-not-written'
function Hash([byte[]]$Bytes) { $h=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-','')}finally{$h.Dispose()} }
function New-Fixture {
    $summary=[ordered]@{schema_version=1;run=$executionID;computer='ADSDK25MEM';cim_domain_role=2;product_type=3;os_build='26100';part_of_domain=$false;source_commit='59346e9641feada4915a3313273ee2fc845bdbeb';helper_sha256='09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957';terminal=$true;passed=$true;child_invoked=$true;process_uncertain=$false;capture_failed=$false;staging_preserved=$true;output_files=@();error=$null;process=[ordered]@{completed=$true;process_uncertain=$false;exit_code=1;pid=123;started_utc='2026-11-12T00:00:00Z';error=$null;stdout_sha256=(Hash ([Text.Encoding]::UTF8.GetBytes('stdout')));stderr_sha256=(Hash ([Text.Encoding]::UTF8.GetBytes('stderr')))}}
    $artifacts=@()
    foreach($name in @('owner.txt','options.json','sdk.requested.json','sdk.started.json','sdk.finished.json','sdk.stdout.txt','sdk.stderr.txt','summary.json')) {
        $text=if($name -eq 'summary.json'){$summary|ConvertTo-Json -Depth 24}else{switch($name){'sdk.stdout.txt'{'stdout'};'sdk.stderr.txt'{'stderr'};default{'{}'}}}
        $bytes=[Text.Encoding]::UTF8.GetBytes($text);$artifacts+=@([ordered]@{name=$name;bytes=$bytes.Length;sha256=(Hash $bytes);base64=[Convert]::ToBase64String($bytes)})
    }
    return [ordered]@{schema_version=1;run=$executionID;summary=$summary;artifacts=$artifacts}
}
$fixture=New-Fixture;$single=$fixture|ConvertTo-Json -Depth 24 -Compress
$script:guestUncertain=$false;$actual=Read-MemberOutcome $single
Check ($actual.passed -and -not $script:guestUncertain -and $script:writes.Count -eq 8) 'Single string result passes and captures eight raw files.'
foreach($malformed in @('not-json','[]','null','{}')) {
    $script:guestUncertain=$false;Reject {Read-MemberOutcome $malformed} 'Malformed result rejected.';Check $script:guestUncertain 'Malformed result retains uncertainty.'
}
$script:guestUncertain=$false;Reject {Read-MemberOutcome @($single,$single)} 'Duplicate return rejected.';Check $script:guestUncertain 'Duplicate return uncertain.'
foreach($field in @('terminal','passed','process_uncertain','capture_failed')) {
    $script:guestUncertain=$false;$fixture=New-Fixture;$fixture.summary[$field]='false';Reject {Read-MemberOutcome ($fixture|ConvertTo-Json -Depth 24 -Compress)} ('Untyped '+$field+' rejected.');Check $script:guestUncertain 'Untyped result remains uncertain.'
}
$script:guestUncertain=$false;$fixture=New-Fixture;$fixture.summary.process.completed=$false;Reject {Read-MemberOutcome ($fixture|ConvertTo-Json -Depth 24 -Compress)} 'Unknown child rejected.';Check $script:guestUncertain 'Unknown child uncertain.'
$script:guestUncertain=$false;$fixture=New-Fixture;$fixture.artifacts[0].base64=[Convert]::ToBase64String([byte[]]@(1));Reject {Read-MemberOutcome ($fixture|ConvertTo-Json -Depth 24 -Compress)} 'Changed artifact rejected.'
$script:guestUncertain=$false;$fixture=New-Fixture;$fixture.artifacts[0].name='..\escaped';Reject {Read-MemberOutcome ($fixture|ConvertTo-Json -Depth 24 -Compress)} 'Escaped artifact rejected.'
$script:guestUncertain=$false;$fixture=New-Fixture;$fixture.artifacts=$fixture.artifacts[0..6];Reject {Read-MemberOutcome ($fixture|ConvertTo-Json -Depth 24 -Compress)} 'Missing raw summary rejected.'
$script:guestUncertain=$false;$fixture=New-Fixture;$fixture.summary.passed=$false;Reject {Read-MemberOutcome ($fixture|ConvertTo-Json -Depth 24 -Compress)} 'Divergent raw summary rejected.'
$script:guestUncertain=$true;$writesBefore=$script:writes.Count;Reject {Read-MemberOutcome $single} 'Pre-existing uncertainty rejects even a valid payload.'
Check ($script:guestUncertain -and $script:writes.Count -eq $writesBefore) 'Valid payload cannot clear uncertainty or emit captures.'
function Stop-VM { param($VM,[switch]$AsJob,$Confirm,$ErrorAction);$script:shutdowns++;return [pscustomobject]@{Id=1} }
function Wait-OwnedJob { param($Job,$TimeoutSeconds,$Action);if($script:waitFailure){throw 'Mock unknown shutdown completion.'};if($script:waitReturnsUncertain){$script:guestUncertain=$true};return 'normal-return' }
$runState=[ordered]@{phase='';final_power=$null;power_restored=$false};$memberPower='Running'
$script:guestUncertain=$true;Reject {Restore-OwnedMemberOff} 'Uncertain guest forbids shutdown.';Check ($script:shutdowns -eq 0) 'No shutdown dispatched on uncertainty.'
$script:guestUncertain=$false;Restore-OwnedMemberOff;Check ($script:shutdowns -eq 1 -and $runState.power_restored -and $runState.final_power -ceq 'Off') 'Known completion permits normal shutdown.'
$runState.power_restored=$false;$script:waitFailure=$true;$script:guestUncertain=$false;Reject {Restore-OwnedMemberOff} 'Unknown shutdown result fails.';Check ($script:guestUncertain -and -not $runState.power_restored) 'Unknown shutdown never reports restored.'
$runState.power_restored=$false;$script:waitFailure=$false;$script:waitReturnsUncertain=$true;$script:guestUncertain=$false
Reject {Restore-OwnedMemberOff} 'Normally returning wait with removal uncertainty must stop shutdown completion.'
Check ($script:guestUncertain -and -not $runState.power_restored) 'Wait cleanup uncertainty must never report restored.'
foreach($action in @('start-member','member-heartbeat','unsupported-member-probe','normal-member-shutdown')) {
    $script:guestUncertain=$false;Reject {Wait-MemberJob ([pscustomobject]@{Id=1}) 120 $action} ('Normal return with uncertainty rejected: '+$action)
    Check $script:guestUncertain ('Uncertainty remains: '+$action)
}
$script:waitReturnsUncertain=$false;$script:guestUncertain=$false
$waitResult=@(Wait-MemberJob ([pscustomobject]@{Id=1}) 120 'known-complete');Check ($waitResult.Count -eq 1 -and $waitResult[0] -ceq 'normal-return' -and -not $script:guestUncertain) 'Known-complete wait preserves scalar result.'
# All four host call sites must use the guarded boundary; only the wrapper may
# call the frozen wait directly. AST inspection never executes the entrypoint.
$tokens=$null;$errors=$null;$hostAst=[Management.Automation.Language.Parser]::ParseFile($hostFile,[ref]$tokens,[ref]$errors)
$direct=@($hostAst.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Wait-OwnedJob'},$true))
$guarded=@($hostAst.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Wait-MemberJob'},$true))
Check ($direct.Count -eq 1 -and $guarded.Count -eq 4) 'Every host wait uses the guarded boundary.'
$report=[ordered]@{schema_version=1;mode='offline AST and mocked functions only; no VM or AD calls';powershell=$PSVersionTable.PSVersion.ToString();checks=$script:checks;passed=$true;host_sha256=(Get-FileHash -LiteralPath $hostFile).Hash;guest_sha256=(Get-FileHash -LiteralPath $guestFile).Hash;tests_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($ReportPath),($report|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false));$report|ConvertTo-Json
