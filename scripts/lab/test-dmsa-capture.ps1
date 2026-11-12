#Requires -Version 5.1
# Offline helper regressions only: no AD module, VM or directory connection.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'dmsa-capture.ps1')
Add-Type -AssemblyName System.DirectoryServices.Protocols

$attribute=[DirectoryServices.Protocols.DirectoryAttribute]::new()
$attribute.Name='servicePrincipalName'
$null=$attribute.Add('test/z');$null=$attribute.Add('test/A')
$field=Convert-DmsaField 'serviceprincipalname' $attribute
if($field.status -ne 'present' -or $field.values.Count -ne 2 -or $field.values[0] -cne 'test/A') {throw 'String capture did not preserve and sort values.'}
$absent=Convert-DmsaField 'msds-delegatedmsastate' $null
if($absent.status -ne 'absent' -or $absent.values.Count -ne 0 -or $absent.kind -ne 'integer') {throw 'Absence was not represented independently.'}
$numeric=[DirectoryServices.Protocols.DirectoryAttribute]::new();$numeric.Name='msDS-DelegatedMSAState';$null=$numeric.Add('0')
if((Convert-DmsaField 'msds-delegatedmsastate' $numeric).status -ne 'present') {throw 'Numeric zero was collapsed to absence.'}
$descriptor=[DirectoryServices.Protocols.DirectoryAttribute]::new();$descriptor.Name='nTSecurityDescriptor'
$bytes=[byte[]]@(1,0,0,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);$null=$descriptor.Add($bytes)
$captured=Convert-DmsaField 'ntsecuritydescriptor' $descriptor
if($captured.kind -ne 'security_descriptor' -or $captured.values[0] -cne [Convert]::ToBase64String($bytes)) {throw 'Descriptor binary fidelity was lost.'}

$broken=[pscustomobject]@{}
$broken|Add-Member ScriptMethod SendRequest {param($request) throw [InvalidOperationException]::new('Synthetic transport failure.')}
$target=[pscustomobject]@{role='legacy';guid='11111111-1111-1111-1111-111111111111';sid='S-1-5-21-1-2-3-1000';dn='CN=synthetic,DC=test';class='user';marker='synthetic'}
$capture=Get-DmsaCapture $broken 'synthetic-dc' 'synthetic-run' 'start-unlinked' 'cleanup' @($target)
if($capture.objects[0].status -ne 'read_error' -or $capture.errors.Count -eq 0) {throw 'Read failure was treated as cleanup absence.'}
if($capture.objects[0].fields['useraccountcontrol'].status -ne 'read_error') {throw 'Read failure became empty account state.'}

$fixtureRoot=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ('ad-sdk-dmsa-tests-'+[guid]::NewGuid().ToString('N'))))
$null=New-Item -ItemType Directory -Path $fixtureRoot
try {
    $artifact=Write-DmsaArtifact $fixtureRoot 'capture.json' $capture
    if($artifact.sha256 -cne (Get-FileHash -LiteralPath (Join-Path $fixtureRoot 'capture.json') -Algorithm SHA256).Hash.ToLowerInvariant()) {throw 'Artifact hash mismatch.'}
    $rejected=$false
    try {$null=Write-DmsaArtifact $fixtureRoot 'capture.json' $capture} catch {$rejected=$true}
    if(-not $rejected) {throw 'Artifact overwrite was accepted.'}
    $rejected=$false
    try {$null=Write-DmsaArtifact $fixtureRoot '../escape.json' $capture} catch {$rejected=$true}
    if(-not $rejected) {throw 'Artifact path escape was accepted.'}
} finally {
    $expectedParent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if([IO.Path]::GetDirectoryName($fixtureRoot) -cne $expectedParent -or [IO.Path]::GetFileName($fixtureRoot) -notmatch '^ad-sdk-dmsa-tests-[a-f0-9]{32}$') {throw 'Unexpected test cleanup path.'}
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
}
'DMSA capture offline regressions passed; no migration was executed.'
