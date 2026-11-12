#Requires -Version 5.1
# Offline AST-imported functions and mocks only. The two real children execute
# benign local PowerShell exit commands; no AD cmdlet, VM, registry, or ACL work.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:checks=0
function Check([bool]$Condition,[string]$Message) { if(-not $Condition){throw $Message};$script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $rejected=$false;try{& $Action}catch{$rejected=$true};Check $rejected $Message }
function Clone($Value) { return ($Value | ConvertTo-Json -Depth 24 | ConvertFrom-Json) }
function Import-Functions([string]$Path,[string[]]$Names) {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    foreach($name in $Names) {
        $definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -ceq $name)
        if($definition.Count -ne 1){throw "Expected exactly one function $name"}
        $text=$definition[0].Extent.Text -replace ('^function\s+'+[regex]::Escape($name)+'(?=[\s(])'),('function script:'+$name)
        . ([scriptblock]::Create($text))
    }
    return $ast
}
$source=Join-Path $PSScriptRoot 'guest-clone-config-negative.ps1'
$ast=Import-Functions $source @('Get-NegativeCases','Reference-Arguments','Expected-Projection','Same-Projection','Test-CaseOutcome','Assert-SdkEnvelope','Assert-CanRun','Assert-StagePath','Bytes-Hash','Write-NewBytes','Write-NewJson','Error-Observation','Wait-OwnedProcess','Start-OwnedProcess','Invoke-OwnedChild')
$commands=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
foreach($forbidden in @('Start-VM','Stop-VM','Set-VM','New-PSSession','Get-ADDomain','Add-ADGroupMember','Remove-ADGroupMember','Set-Acl','Set-ItemProperty','New-ItemProperty','Remove-Item','Stop-Process')) { Check ($forbidden -notin $commands) "Prepared harness contains forbidden action $forbidden" }
Check ($ast.Extent.Text -notmatch '\.Kill\(' -and $ast.Extent.Text.Contains('-WindowStyle Hidden')) 'Child ownership/visibility policy differs.'
$Run='offline-negative-fixture';$StageDirectory=Join-Path 'C:\ad-sdk-validation' $Run
Check ((Assert-StagePath (Join-Path $StageDirectory 'negative-cases\case\sdk')) -ceq (Join-Path $StageDirectory 'negative-cases\case\sdk')) 'Owned scratch path was rejected.'
Reject { Assert-StagePath 'C:\Windows\NTDS\DCCloneConfig.xml' } 'System NTDS path was accepted.'
Reject { Assert-StagePath (Join-Path $StageDirectory '..\other-run\DCCloneConfig.xml') } 'Sibling staging escape was accepted.'

$cases=@(Get-NegativeCases | ForEach-Object {Clone $_})
Check ($cases.Count -eq 19 -and @($cases | Where-Object positive_control).Count -eq 2) 'Frozen case matrix/control count differs.'
Check (@($cases.name | Select-Object -Unique).Count -eq 19) 'Case names are not unique.'
$positive=@($cases | Where-Object name -ceq 'control-v4-static')[0]
$referenceArguments=Reference-Arguments $positive.configuration (Join-Path $StageDirectory 'negative-cases\control-v4-static\reference')
Check ($referenceArguments.Offline -eq $true -and $referenceArguments.Path -like ($StageDirectory+'\*') -and $referenceArguments.Static -eq $true) 'Reference arguments did not retain explicit Offline and owned Path.'
$unexpected=Clone $positive.configuration;$unexpected | Add-Member NoteProperty Offline $false
Reject { Reference-Arguments $unexpected (Join-Path $StageDirectory 'negative-cases\reference') } 'Case configuration overrode Offline mode.'
$unexpected=Clone $positive.configuration;$unexpected | Add-Member NoteProperty Path 'C:\Windows\NTDS'
Reject { Reference-Arguments $unexpected (Join-Path $StageDirectory 'negative-cases\reference') } 'Case configuration overrode the owned output path.'
$emptyDns=@($cases | Where-Object name -ceq 'static-empty-dns')[0]
Check ($emptyDns.configuration.PSObject.Properties['ipv4_dns_resolvers'] -and @($emptyDns.configuration.ipv4_dns_resolvers).Count -eq 0) 'Explicit empty DNS array was confused with an omitted field.'

function Good-Process([int]$ExitCode=0) { return [pscustomobject]@{completed=$true;process_uncertain=$false;error=$null;exit_code=$ExitCode} }
function Wire([bool]$Invalid) {
    return [pscustomobject]@{protocol_version=1;operation='generate_config';data=[pscustomobject]@{outcome=$(if($Invalid){'not_written'}else{'written'});checks_skipped=$true;prerequisites=[pscustomobject]@{complete=$false}};error_details=[pscustomobject]@{present=$Invalid;invalid_configuration=$Invalid;invalid_path=$false;permission=$false;prerequisite=$false;unsupported=$false;deadline=$false;native_error=$null;errno_code=$null}}
}
foreach($case in $cases) {
    $sdkProcess=Good-Process $(if($case.positive_control){0}else{1});$sdk=Wire (-not $case.positive_control)
    $projection=Expected-Projection $case
    $sdkFile=[pscustomobject]@{exists=[bool]$case.positive_control;schema_valid=[bool]$case.positive_control;projection=$projection;bytes_base64='retained-sdk-bytes'}
    $refFile=[pscustomobject]@{exists=($case.reference_expectation -ceq 'written');schema_valid=($case.reference_expectation -ceq 'written');projection=$projection;bytes_base64='retained-reference-bytes'}
    $reference=[pscustomobject]@{completed=$true;cmdlet_invoked=$true;harness_error=$null;cmdlet_error=$null;offline=$true;file=$refFile}
    $script:publicationUncertain=$false
    Assert-SdkEnvelope $sdkProcess $sdk
    Check (Test-CaseOutcome $case $sdkProcess $sdk $sdkFile (Good-Process) $reference) "Expected frozen outcome failed for $($case.name)"
    if(-not $case.positive_control -and $case.reference_expectation -ceq 'written') { Check ($case.intentional_difference -ne '') 'Reference publication difference lacked an explicit explanation.' }
}
$case=$positive;$sdk=Wire $false;$sdkProcess=Good-Process;$projection=Expected-Projection $case
$sdkFile=[pscustomobject]@{exists=$true;schema_valid=$true;projection=$projection}
$reference=[pscustomobject]@{completed=$true;cmdlet_invoked=$true;harness_error=$null;cmdlet_error=$null;offline=$true;file=[pscustomobject]@{exists=$true;schema_valid=$true;projection=$projection}}
$badSdk=Wire $true;$badReference=Clone $reference;$badReference.file.exists=$false;$badReference.cmdlet_error='injected reference exception'
Check (-not (Test-CaseOutcome $case (Good-Process 1) $badSdk ([pscustomobject]@{exists=$false}) (Good-Process) $badReference)) 'Two mutual failures passed a positive control.'
$badReference=Clone $reference;$badReference.file.exists=$false
Check (-not (Test-CaseOutcome $case $sdkProcess $sdk $sdkFile (Good-Process) $badReference)) 'Exit 0 without a file passed a publication control.'
$badReference=Clone $reference;$badReference.cmdlet_error='exception after publication'
Check (-not (Test-CaseOutcome $case $sdkProcess $sdk $sdkFile (Good-Process) $badReference)) 'Exception after publication passed successful parity.'
$negative=@($cases | Where-Object name -ceq 'five-v4-dns')[0]
$noFile=[pscustomobject]@{exists=$false;schema_valid=$false;projection=$null}
$reference.file=$noFile
Check (Test-CaseOutcome $negative (Good-Process 1) (Wire $true) $noFile (Good-Process) $reference) 'Nonthrowing no-file rejection was confused with success.'
$reference.cmdlet_error=[pscustomobject]@{exceptions=@([pscustomobject]@{type='System.UnauthorizedAccessException'})}
Check (-not (Test-CaseOutcome $negative (Good-Process 1) (Wire $true) $noFile (Good-Process) $reference)) 'An unrelated no-file reference access exception passed input validation.'
$reference.cmdlet_error=[pscustomobject]@{exceptions=@([pscustomobject]@{type='System.Management.Automation.ParameterBindingValidationException'})}
Check (Test-CaseOutcome $emptyDns (Good-Process 1) (Wire $true) $noFile (Good-Process) $reference) 'Expected empty-array parameter validation was lost.'
$reference.cmdlet_error=$null
$reference.harness_error='module load failed'
Check (-not (Test-CaseOutcome $negative (Good-Process 1) (Wire $true) $noFile (Good-Process) $reference)) 'Infrastructure failure passed a negative case.'
$reference.harness_error=$null;$badSdk=Wire $true;$badSdk.error_details.invalid_configuration=$false;$badSdk.error_details.invalid_path=$true
Check (-not (Test-CaseOutcome $negative (Good-Process 1) $badSdk $noFile (Good-Process) $reference)) 'Wrong SDK typed error passed configuration validation.'
$literal=@($cases | Where-Object name -ceq 'malformed-ipv4-address')[0]
$literalProjection=Expected-Projection $literal
Check ($literalProjection.address -ceq 'not-an-ip') 'Intentional literal-validation difference lost the raw reference value.'
$reference.file=[pscustomobject]@{exists=$true;schema_valid=$true;projection=$literalProjection;bytes_base64='retain-after-exception'};$reference.cmdlet_error='after publication'
Check (-not (Test-CaseOutcome $literal (Good-Process 1) (Wire $true) $noFile (Good-Process) $reference) -and $reference.file.bytes_base64 -ceq 'retain-after-exception') 'A strict-validation difference accepted publication with an exception or altered retained bytes.'
foreach($mutation in @({$changed.data.outcome='uncertain'},{$changed.data.checks_skipped=$false},{$changed.data.prerequisites.complete=$true},{$changed.operation='other'},{$changed.data=$null})) {
    $changed=Wire $false;$script:publicationUncertain=$false;& $mutation
    Reject { Assert-SdkEnvelope (Good-Process) $changed } 'Invalid/uncertain SDK envelope passed.'
    Check $script:publicationUncertain 'Invalid SDK publication failed to halt subsequent writers.'
}

# Real benign held-handle children verify exit-status capture, including fast failures.
$testRoot=Join-Path $PSScriptRoot ('clone-config-negative-tests-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
function Assert-StagePath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($testRoot+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Offline test escaped its owned directory.' }
    return $full
}
$script:processUncertain=$false;$script:publicationUncertain=$false;$script:captureFailed=$false
$powerShell=Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
foreach($code in @(0,7)) {
    $result=Invoke-OwnedChild $powerShell ('-NoLogo -NoProfile -NonInteractive -Command "exit '+$code+'"') (Join-Path $testRoot ('exit-'+$code)) 15
    Check ($result.completed -and -not $result.process_uncertain -and $result.exit_code -eq $code -and $result.pid -gt 0 -and $result.started_utc -and $null -eq $result.error) 'Benign held-handle exit evidence was lost.'
    Check ((Get-FileHash -LiteralPath $result.stdout_path).Hash -ceq $result.stdout_sha256 -and (Get-FileHash -LiteralPath $result.stderr_path).Hash -ceq $result.stderr_sha256) 'Completed child streams were not retained and hash-bound.'
}
Reject { Invoke-OwnedChild $powerShell '-Command "exit 0"' (Join-Path $testRoot 'exit-0') 15 } 'Existing process evidence was replayed or overwritten.'
$fake=[pscustomobject]@{waits=0};$fake | Add-Member ScriptMethod WaitForExit {param($milliseconds) $this.waits++;return $false}
Check (-not (Wait-OwnedProcess $fake 0) -and $fake.waits -eq 0) 'Expired wait retried or claimed completion.'
$script:starts=0;$script:disposed=0
function Start-OwnedProcess {
    param($Executable,$Arguments,$Stdout,$Stderr,$Record)
    $script:starts++;$Record.pid=73;$Record.started_utc='2026-11-12T00:00:00Z'
    $process=[pscustomobject]@{}
    $process | Add-Member ScriptMethod Dispose {$script:disposed++}
    return $process
}
function Wait-OwnedProcess {param($Process,$Seconds) return $false}
$result=Invoke-OwnedChild 'mock-child' 'never executed' (Join-Path $testRoot 'timeout') 0
Check ($result.process_uncertain -and -not $result.completed -and $script:processUncertain -and $script:starts -eq 1 -and $script:disposed -eq 1) 'Unknown child was terminated, retried, or reported complete.'
Reject { Invoke-OwnedChild 'mock-child' 'never executed' (Join-Path $testRoot 'forbidden-after-timeout') 0 } 'An uncertain child allowed a subsequent writer.'
Check ($script:starts -eq 1) 'A second child started after timeout.'
foreach($flag in @('publication','capture')) {
    $script:processUncertain=$false;$script:publicationUncertain=($flag -ceq 'publication');$script:captureFailed=($flag -ceq 'capture')
    Reject { Invoke-OwnedChild 'mock-child' 'never executed' (Join-Path $testRoot ('forbidden-'+$flag)) 0 } 'Uncertain publication/capture allowed another child.'
    Check ($script:starts -eq 1) 'A child started despite evidence uncertainty.'
}
[ordered]@{passed=$true;checks=$script:checks;powershell=$PSVersionTable.PSVersion.ToString();scope='AST/mocked cases and two benign local PowerShell exit children only; no AD/VM/registry/ACL operations';fixture_directory=$testRoot;guest_script_sha256=(Get-FileHash -LiteralPath $source).Hash} | ConvertTo-Json -Depth 6
