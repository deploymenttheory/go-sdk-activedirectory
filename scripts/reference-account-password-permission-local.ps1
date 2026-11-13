# Offline Microsoft reference transform only. No account/directory methods run.
[CmdletBinding()]
param(
    [string]$AssemblyPath = 'C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\v4.0_10.0.0.0__31bf3856ad364e35\Microsoft.ActiveDirectory.Management.dll'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.DirectoryServices
$assembly = [Reflection.Assembly]::LoadFrom($AssemblyPath)
$factory = $assembly.GetType('Microsoft.ActiveDirectory.Management.Commands.ADAccountFactory`1', $true).MakeGenericType($assembly.GetType('Microsoft.ActiveDirectory.Management.ADAccount', $true))
$flags = [Reflection.BindingFlags]'Static,NonPublic,Public'
# These two static methods were inspected: they accept only a local descriptor
# and operate on its access rules. Neither binds nor resolves an account.
$setter = $factory.GetMethod('SetCannotChangePassword', $flags)
$scan = $factory.GetMethod('ScanACLForChangePasswordRight', $flags)
if ($null -eq $setter -or $null -eq $scan) { throw 'Local reference transform is unavailable.' }
$guid = 'ab721a53-1e2f-11d0-9819-00aa0040529b'
$allow = "(OA;;CR;$guid;;PS)(OA;;CR;$guid;;WD)"
$deny = "(OD;;CR;$guid;;PS)(OD;;CR;$guid;;WD)"
$cases = @(
    @{ name='empty-to-deny'; sddl='O:SYG:SYD:P(A;;RC;;;WD)'; cannot=$true },
    @{ name='allow-to-deny'; sddl="O:SYG:SYD:P(A;;RC;;;WD)$allow"; cannot=$true },
    @{ name='deny-noop'; sddl="O:SYG:SYD:P$deny(A;;RC;;;WD)"; cannot=$true },
    @{ name='deny-to-allow'; sddl="O:SYG:SYD:P$deny(A;;RC;;;WD)"; cannot=$false }
)
$observations = foreach ($case in $cases) {
    $descriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $descriptor.SetSecurityDescriptorSddlForm($case.sddl)
    $before = $descriptor.GetSecurityDescriptorBinaryForm()
    $changed = $setter.Invoke($null, [object[]]@($descriptor.PSObject.BaseObject, [bool]$case.cannot))
    $arguments = [object[]]@($descriptor.PSObject.BaseObject, $false, $false, $false, $false)
    $null = $scan.Invoke($null, $arguments)
    [pscustomobject]@{
        name=$case.name; requested_cannot=[bool]$case.cannot; changed=[bool]$changed
        before_base64=[Convert]::ToBase64String($before)
        after_base64=[Convert]::ToBase64String($descriptor.GetSecurityDescriptorBinaryForm())
        self_deny=[bool]$arguments[1]; everyone_deny=[bool]$arguments[2]
        self_allow=[bool]$arguments[3]; everyone_allow=[bool]$arguments[4]
    }
}
[pscustomobject]@{
    kind='local-reference-only-no-directory-qualification'
    powershell_version=$PSVersionTable.PSVersion.ToString()
    file_version=(Get-Item -LiteralPath $AssemblyPath).VersionInfo.FileVersion
    assembly_sha256=(Get-FileHash -LiteralPath $AssemblyPath -Algorithm SHA256).Hash
    cases=@($observations)
} | ConvertTo-Json -Depth 5
