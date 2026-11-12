#Requires -Version 5.1
# Offline AST helpers and mock readonly directory data only. No entrypoint runs.
param([string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;$script:checks=0
function Check([bool]$Value,[string]$Message) { if(-not $Value) { throw $Message };$script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $failed=$false;try { & $Action } catch { $failed=$true };Check $failed $Message }
function Parse-Script([string]$Path) { $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors);Check ($errors.Count -eq 0) 'Script parse failed.';return $ast }
$guestPath=Join-Path $PSScriptRoot 'get-clone-config-online-prerequisites.ps1';$hostPath=Join-Path $PSScriptRoot 'run-clone-config-online-inventory.ps1'
$guestAST=Parse-Script $guestPath;$hostAST=Parse-Script $hostPath
foreach($ast in @($guestAST,$hostAST)) {
    $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    foreach($forbidden in @('Start-VM','Stop-VM','Restart-VM','Remove-VM','Set-VM','New-ADDCCloneConfigFile','Add-ADGroupMember','Remove-ADGroupMember','Set-ADObject','Set-Acl','Set-ItemProperty','Remove-Item','Start-Process','Stop-Process')) { Check ($forbidden -notin $commands) "Unexpected mutator: $forbidden" }
}
Check ($guestAST.Extent.Text -notmatch '(WriteAll|CreateDirectory|GenerateXml|\.Kill\()') 'Readonly guest contains write/generation entrypoints.'
Check ($hostAST.Extent.Text.Contains('Invoke-OwnedGuest -FilePath $snapshot -Arguments @($executionID) -TimeoutSeconds 90')) 'Host lost bounded file invocation.'
Check ($hostAST.Extent.Text.Contains('116353985A315D63E60B16B3386B8E305B965F9D36FEA131D80A6B8F999C06BE')) 'Approved guard hash changed.'
Check ($hostAST.Extent.Text.IndexOf("'inventory-return.json'") -lt $hostAST.Extent.Text.IndexOf('$values=@($returned | ConvertFrom-Json')) 'Host parses before retaining raw inventory.'
foreach($function in $guestAST.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) { . ([scriptblock]::Create($function.Extent.Text)) }
$fixture=Join-Path $PSScriptRoot ('clone-config-online-inventory-tests-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixture)
$sample=Join-Path $fixture 'sample.xml';[IO.File]::WriteAllText($sample,'<owned/>')
$file=Read-InventoryFile $sample
Check ($file.exists -and $file.length -eq 8 -and $file.sha256.Length -eq 64 -and $file.sddl) 'Existing local file observation failed.'
Check (-not (Read-InventoryFile (Join-Path $fixture 'absent.xml')).exists) 'Missing file was not distinguished.'
foreach($path in @('relative.xml','\\server\share\x','C:\temp\..\x','C:\temp\x:stream')) { Reject { Assert-InventoryPath $path } 'Unsafe path accepted.' }
Reject { Read-InventoryFile $fixture } 'Directory accepted as file.'
$sid='S-1-5-21-111-222-333-522';$sidObject=[Security.Principal.SecurityIdentifier]::new($sid);$sidBytes=[byte[]]::new($sidObject.BinaryLength);$sidObject.GetBinaryForm($sidBytes,0)
foreach($value in @($sid,$sidObject,$sidBytes)) { Check ((Inventory-SID $value) -ceq $sid) 'SID representation changed.' }
Reject { Inventory-SID 'invalid' } 'Invalid SID accepted.'
Reject { Inventory-SID 42 } 'Unknown SID representation accepted.'
function Get-Item { param([string]$LiteralPath,[switch]$Force,[string]$ErrorAction) throw [UnauthorizedAccessException]::new('fixture denied') }
Reject { Read-InventoryItem $sample } 'Access denial was classified as absence.'
function Read-InventoryItem([string]$Path) { return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint} }
Reject { Assert-InventoryPath $sample } 'Linked path accepted.'

# The complete inventory is exercised with fake directory, filesystem and module
# data. No AD cmdlet, registry provider, drive enumeration, or VM call is reached.
$script:scenario='baseline';$sourceDN='CN=ADSDK25DC1,OU=Domain Controllers,DC=ad,DC=sdk,DC=test';$domainSID='S-1-5-21-111-222-333'
function Import-Module { param([string]$Name,[string]$ErrorAction) Check ($Name -ceq 'ActiveDirectory') 'Unexpected mocked module.' }
function Get-ADRootDSE { param($Server,$ErrorAction) return [pscustomobject]@{dnsHostName=$Server;defaultNamingContext='DC=ad,DC=sdk,DC=test';domainControllerFunctionality=10} }
function Get-ADDomain { param($Server,$ErrorAction) return [pscustomobject]@{DNSRoot='ad.sdk.test';PDCEmulator=$(if($script:scenario -eq 'pdc-changed'){'ADSDK25DC2.ad.sdk.test'}else{$Server});DomainSID=$domainSID;DistinguishedName='DC=ad,DC=sdk,DC=test'} }
function Get-ADDomainController { param($Identity,$Server,$ErrorAction) return [pscustomobject]@{ComputerObjectDN=$sourceDN;OperationMasterRoles=@('PDCEmulator');IsReadOnly=$false} }
function Get-ADGroup { param($Identity,$Properties,$Server,$ErrorAction) return [pscustomobject]@{SID=$Identity;member=$(if($script:scenario -eq 'direct-member'){@($sourceDN)}else{@()});DistinguishedName='CN=Cloneable Domain Controllers,CN=Users,DC=ad,DC=sdk,DC=test';ObjectGUID=[guid]'11111111-1111-1111-1111-111111111111'} }
function Get-ADComputer { param($Identity,$Properties,$Server,$ErrorAction) return [pscustomobject]@{DistinguishedName=$Identity;SID=($domainSID+'-1000');ObjectGUID=[guid]'22222222-2222-2222-2222-222222222222';memberOf=@();tokenGroups=$(if($script:scenario -eq 'no-token'){@()}elseif($script:scenario -in @('direct-member','nested-member')){@($domainSID+'-522')}else{@($domainSID+'-516')})} }
function Get-ADPrincipalGroupMembership { param($Identity,$Server,$ErrorAction) if($script:scenario -eq 'direct-member') { return [pscustomobject]@{DistinguishedName='group';SID=($domainSID+'-522')} };return @() }
function Get-ItemProperty { param($LiteralPath,$ErrorAction) if($LiteralPath.EndsWith('Parameters')) { return [pscustomobject]@{'DSA Working Directory'='C:\Windows\NTDS'} };return [pscustomobject]@{CurrentBuildNumber='26100';UBR=1} }
function Get-InventoryRemovable { if($script:scenario -eq 'removable') { return [pscustomobject]@{root='E:\';ready=$false} };return @() }
function Assert-InventoryPath([string]$Path) { return [IO.Path]::GetFullPath($Path) }
function Read-InventoryItem([string]$Path) { return [pscustomobject]@{PSIsContainer=$true;Attributes=[IO.FileAttributes]::Directory} }
function Read-InventoryFile([string]$Path) { return [ordered]@{path=$Path;exists=($Path.EndsWith('DefaultDCCloneAllowList.xml') -or ($script:scenario -eq 'collision' -and $Path.EndsWith('DCCloneConfig.xml')));length=8;sha256=('A'*64);sddl='fixture'} }
function Get-Acl { param($LiteralPath,$ErrorAction) return [pscustomobject]@{Sddl='fixture'} }
function Get-Command { param($Name,$ErrorAction) return [pscustomobject]@{ImplementingType=[string];Module=[pscustomobject]@{Version=[version]'1.0.1.0'}} }
function Get-FileHash { param($LiteralPath,$Algorithm) return [pscustomobject]@{Hash=('A'*64)} }
function Get-ADDCCloningExcludedApplicationList {
    param($ErrorAction,$WarningVariable,$InformationVariable)
    if($script:scenario -eq 'exclusion-error') { throw 'Reference inventory failed.' }
    if($script:scenario -eq 'null-exclusions') { return $null }
    if($script:scenario -eq 'empty-exclusions') { return @() }
    if($script:scenario -eq 'invalid-exclusions') { return $false }
    if($script:scenario -eq 'mixed-exclusions') { return @($null,[pscustomobject]@{Name='Synthetic service';Type='Service'},$null) }
    return [pscustomobject]@{Name='Synthetic service';Type='Service'}
}
$run='clone-config-reviewed-20261112T215735Z-b4707e3f-online-inventory-v1';$savedComputer=$env:COMPUTERNAME;$savedWindows=$env:windir
try {
    $env:COMPUTERNAME='ADSDK25DC1';$env:windir='C:\Windows'
    foreach($scenario in @('baseline','direct-member','nested-member','collision')) {
        $script:scenario=$scenario;$result=Read-CloneConfigOnlineInventory $run
        Check ($result.completed -and $null -eq $result.error) "Mock inventory failed: $scenario"
        Check (@($result.files.clone_configs).Count -eq 1) 'DSA/NTDS duplicate was retained.'
        Check (@($result.applications.reference_entries).Count -eq 1 -and -not $result.applications.vendor_approval_claimed) 'Inventory implied application approval.'
        if($scenario -eq 'baseline') { Check (-not $result.directory.direct_member -and -not $result.directory.token_member -and -not $result.directory.reference_member) 'Missing group state changed.' }
        if($scenario -eq 'direct-member') { Check ($result.directory.direct_member -and $result.directory.token_member -and $result.directory.reference_member) 'Direct group state changed.' }
        if($scenario -eq 'nested-member') { Check (-not $result.directory.direct_member -and $result.directory.token_member -and -not $result.directory.reference_member) 'Nested/direct parity boundary was hidden.' }
        if($scenario -eq 'collision') { Check $result.files.clone_configs[0].exists 'Existing clone file was hidden.' }
    }
    foreach($scenario in @('null-exclusions','empty-exclusions','mixed-exclusions')) {
        $script:scenario=$scenario;$result=Read-CloneConfigOnlineInventory $run
        Check ($result.completed -and $null -eq $result.error) "Valid empty/mixed inventory rejected: $scenario"
        $expected=if($scenario -eq 'mixed-exclusions'){1}else{0}
        Check (@($result.applications.reference_entries).Count -eq $expected) "Exclusion cardinality differs: $scenario"
        if($expected) { Check ($result.applications.reference_entries[0].name -ceq 'Synthetic service') 'Non-null exclusion was discarded.' }
    }
    foreach($scenario in @('no-token','pdc-changed','removable','exclusion-error','invalid-exclusions')) { $script:scenario=$scenario;$result=Read-CloneConfigOnlineInventory $run;Check (-not $result.completed -and $null -ne $result.error) "Uncertain inventory accepted: $scenario" }
    $script:scenario='baseline';$env:COMPUTERNAME='OTHER';Check (-not (Read-CloneConfigOnlineInventory $run).completed) 'Wrong host accepted.'
    $env:COMPUTERNAME='ADSDK25DC1';Check (-not (Read-CloneConfigOnlineInventory 'other-run').completed) 'Wrong run accepted.'
} finally { $env:COMPUTERNAME=$savedComputer;$env:windir=$savedWindows }
$record=[ordered]@{passed=$true;checks=$script:checks;collected_utc=[DateTime]::UtcNow.ToString('o');powershell=$PSVersionTable.PSVersion.ToString();scope='offline AST helpers, local files, and mocked directory data; no host/guest entrypoints, VM, AD, registry, or drive enumeration';guest_sha256=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $guestPath -Algorithm SHA256).Hash;host_sha256=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash;fixture_directory=$fixture}
if($OutputPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($record | ConvertTo-Json),[Text.UTF8Encoding]::new($false)) }
$record | ConvertTo-Json
