#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'reference-credentials.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Credential fixture script syntax error.'}
$helper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-CredentialFixtures'},$true)
if(-not $helper){throw 'Credential fixture cleanup helper missing.'}
. ([scriptblock]::Create($helper.Extent.Text))

function Test-CredentialCleanup([string]$Case,[bool]$MustFail) {
    $state=@{ouPresent=($Case -ne 'absent');childRemovals=0;ouRemovals=0;children=[Collections.Generic.List[object]]::new()}
    $ou=[pscustomobject]@{Description='owned-marker';ObjectGUID=[guid]'11111111-1111-1111-1111-111111111111';DistinguishedName='OU=owned,DC=test'}
    $state.children.Add([pscustomobject]@{Name='owned-user';Description='owned-marker';ObjectGUID='user-guid';ObjectClass='user'})
    $state.children.Add([pscustomobject]@{Name='NativeAllowed';Description='owned-marker';ObjectGUID='container-guid';ObjectClass='container'})
    if($Case -eq 'foreign-ou'){$ou.Description='foreign-marker'}
    if($Case -eq 'foreign-child'){$state.children.Add([pscustomobject]@{Name='foreign';Description='foreign-marker';ObjectGUID='foreign-guid';ObjectClass='container'})}
    function Get-ADOrganizationalUnit($LDAPFilter,$SearchBase,$SearchScope,$Properties,$Server) {
        if($Case -eq 'query-ou-fails'){Write-Error 'Injected OU lookup failure.'}
        if($state.ouPresent){return $ou}
    }
    function Get-ADObject($Filter,$SearchBase,$SearchScope,$Properties,$Server) {
        if($Case -eq 'query-children-fails'){Write-Error 'Injected child lookup failure.'}
        return @($state.children.ToArray())
    }
    function Remove-ADObject($Identity,$Server,$Confirm) {
        if($Identity -notin @('user-guid','container-guid')){throw 'Attempted deletion of a foreign child.'}
        $state.childRemovals++
        if($Case -eq 'child-remove-fails' -and $Identity -eq 'user-guid'){throw 'Injected child removal failure.'}
        if($Case -eq 'remove-no-effect'){return}
        $child=@($state.children | Where-Object ObjectGUID -eq $Identity)[0]
        $null=$state.children.Remove($child)
    }
    function Remove-ADOrganizationalUnit($Identity,$Server,$Confirm) {
        $state.ouRemovals++
        if($state.children.Count -or $Case -eq 'ou-remove-fails'){throw 'OU is not empty or removal failed.'}
        $state.ouPresent=$false
    }
    $guid=if($Case -eq 'lost-response'){''}elseif($Case -eq 'changed-guid'){'22222222-2222-2222-2222-222222222222'}else{$ou.ObjectGUID.ToString()}
    $caught=$null
    try {Remove-CredentialFixtures 'source' 'DC=test' 'owned' $guid 'owned-marker' @('owned-user','NativeAllowed')} catch {$caught=$_}
    if($MustFail -and -not $caught){throw "$Case incorrectly passed."}
    if(-not $MustFail -and $caught){throw "$Case failed: $($caught.Exception.Message)"}
    if($Case -in @('success','lost-response') -and ($state.ouPresent -or $state.children.Count)){throw "$Case left fixture objects."}
    if($Case -in @('absent','foreign-ou','changed-guid','query-ou-fails','query-children-fails') -and ($state.childRemovals -or $state.ouRemovals)){throw "$Case attempted removal without confirmed ownership."}
    if($Case -eq 'foreign-child' -and ($state.children.Count -ne 1 -or $state.children[0].ObjectGUID -ne 'foreign-guid')){throw 'Foreign child was removed or owned cleanup stopped prematurely.'}
    if($Case -eq 'child-remove-fails' -and ($state.childRemovals -ne 2 -or $state.children.Count -ne 1)){throw 'A child failure prevented independent owned cleanup.'}
    Write-Output "$Case`: passed"
}
Test-CredentialCleanup 'success' $false
Test-CredentialCleanup 'absent' $false
Test-CredentialCleanup 'lost-response' $false
Test-CredentialCleanup 'foreign-ou' $true
Test-CredentialCleanup 'changed-guid' $true
Test-CredentialCleanup 'foreign-child' $true
Test-CredentialCleanup 'child-remove-fails' $true
Test-CredentialCleanup 'ou-remove-fails' $true
Test-CredentialCleanup 'query-ou-fails' $true
Test-CredentialCleanup 'query-children-fails' $true
Test-CredentialCleanup 'remove-no-effect' $true
$errorHelper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-CredentialError'},$true)
if(-not $errorHelper){throw 'Credential error helper missing.'}
. ([scriptblock]::Create($errorHelper.Extent.Text))
$aggregate=[AggregateException]::new('private-error-text',[Exception[]]@([InvalidOperationException]::new('private-error-text'),[ArgumentException]::new('private-error-text')))
$details=@(Get-CredentialError ([pscustomobject]@{Exception=$aggregate}))
if($details.Count -ne 3 -or 'System.InvalidOperationException' -notin $details.type -or 'System.ArgumentException' -notin $details.type){throw 'Aggregate cleanup failure lost an inner error.'}
if(($details | ConvertTo-Json -Compress).Contains('private-error-text')){throw 'Credential error evidence retained exception messages.'}
Write-Output 'aggregate-errors: passed'
$denialHelper=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-CredentialPermissionDenial'},$true)
if(-not $denialHelper){throw 'Credential permission helper missing.'}
. ([scriptblock]::Create($denialHelper.Extent.Text))
Add-Type 'public sealed class CredentialNativeException : System.Exception { public int ErrorCode { get; private set; } public CredentialNativeException(int code) : base("private-error-text") { ErrorCode = code; } }'
foreach($code in @(8344,5,49)) {
    $details=@(Get-CredentialError ([pscustomobject]@{Exception=[CredentialNativeException]::new($code)}))
    if($details[0].code -ne $code){throw 'Native AD error code was discarded.'}
    if((Test-CredentialPermissionDenial $details) -ne ($code -in @(5,8344))){throw 'Native AD permission error was misclassified.'}
    if(($details | ConvertTo-Json -Compress).Contains('private-error-text')){throw 'Native AD error evidence retained exception messages.'}
}
$details=@(Get-CredentialError ([pscustomobject]@{Exception=[UnauthorizedAccessException]::new('private-error-text')}))
if(-not (Test-CredentialPermissionDenial $details)){throw 'Managed permission error was misclassified.'}
Write-Output 'native-permission-errors: passed'
