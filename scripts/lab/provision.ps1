#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('2016', '2019', '2022', '2025')][string]$ServerVersion = '2025',
    [string]$StorageRoot = 'H:\ad-sdk-lab',
    [string]$IsoPath,
    [ValidateRange(1, 20)][int]$ImageIndex = 1,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSHA256,
    [switch]$MediaOnly,
    [switch]$WithLDS
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if($WithLDS -and $ServerVersion -ne '2025'){throw 'The LDS fixture currently requires the Server 2025 profile.'}
. (Join-Path $PSScriptRoot 'media.ps1')
$StorageRoot = Resolve-LabInputPath $StorageRoot
if ($IsoPath) { $IsoPath = Resolve-LabInputPath $IsoPath }
$mediaOptions = @{ServerVersion=$ServerVersion; StorageRoot=$StorageRoot; ImageIndex=$ImageIndex}
if ($IsoPath) { $mediaOptions.IsoPath = $IsoPath }
if ($ExpectedSHA256) { $mediaOptions.ExpectedSHA256 = $ExpectedSHA256 }
$media = Get-LabMedia @mediaOptions
if ($MediaOnly) { $media; return }
$labOptions = @{ServerVersion=$ServerVersion; StorageRoot=$StorageRoot; IsoPath=$media.path; ImageIndex=$ImageIndex}
$actions=@('New','Configure')
if($WithLDS){$actions+='ConfigureLDS'}
$actions+='Reference'
foreach ($action in $actions) {
    & (Join-Path $PSScriptRoot 'lab.ps1') -Action $action @labOptions
}
