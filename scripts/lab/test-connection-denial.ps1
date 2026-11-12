#Requires -Version 5.1
# Called by the elevated connection runner with its verified member/session.
[CmdletBinding()]
param([Parameter(Mandatory)]$Member, [Parameter(Mandatory)]$AdminSession, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Executable, [Parameter(Mandatory)][string]$ExpectedHash, [Parameter(Mandatory)][string]$LabId)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$name = 'sdkdeny' + [guid]::NewGuid().ToString('N').Substring(0, 10)
# Local-account descriptions allow at most 48 characters.
$marker = 'ad-sdk:' + $LabId.Substring(0,8) + ':' + [guid]::NewGuid().ToString('N').Substring(0,20)
$password = ConvertTo-SecureString ('Aa9!' + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
$localCredential = [PSCredential]::new("$($Member.name)\$name", $password)
$sid = $null; $deniedSession = $null; $creationAttempted = $false
$proof = [ordered]@{passed=$false;exit_code=$null;output=@();error=$null;cleanup_confirmed=$false}
function Remove-LabDenialUser([string]$SID, [string]$Name, [string]$Marker) {
    $ErrorActionPreference='Stop'
    $user=Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if (-not $user) { return }
    if ($user.Name -ne $Name -or $user.Description -ne $Marker -or ($SID -and $user.SID.Value -ne $SID)) { throw 'Denial fixture ownership changed; refusing removal.' }
    $ownedSID=$user.SID.Value
    Remove-LocalUser -SID $ownedSID
    if (Get-LocalUser -SID $ownedSID -ErrorAction SilentlyContinue) { throw 'Denial fixture survived cleanup.' }
}
try {
    # Record identity before adding membership so even a membership failure can
    # be cleaned up by exact SID, name, and marker in the host's finally block.
    $creationAttempted = $true
    $sid = Invoke-Command -Session $AdminSession -ArgumentList $name,$marker,$password -ScriptBlock {
        param($Name,$Marker,$Password)
        $ErrorActionPreference='Stop'
        if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) { throw 'Denial fixture name already exists.' }
        $user = New-LocalUser -Name $Name -Password $Password -Description $Marker
        return $user.SID.Value
    }
    Invoke-Command -Session $AdminSession -ArgumentList $sid -ScriptBlock {
        param($SID)
        $ErrorActionPreference='Stop'
        # PowerShell Direct requires guest administrator membership. This local
        # disposable identity has no AD account or domain authorization.
        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $SID
    }
    $deniedSession = New-PSSession -VMId ([guid]$Member.id) -Credential $localCredential -ErrorAction Stop
    $result = Invoke-Command -Session $deniedSession -ArgumentList $Executable,$Server,$ExpectedHash -ScriptBlock {
        param($Executable,$Server,$ExpectedHash)
        $ErrorActionPreference='Stop'
        if ((Get-FileHash -LiteralPath $Executable).Hash -ne $ExpectedHash) { throw 'Denial test binary hash mismatch.' }
        $oldServer=$env:ADSDK_LDAP_SERVER; $oldDenied=$env:ADSDK_LDAP_DENIED
        try {
            $env:ADSDK_LDAP_SERVER=$Server; $env:ADSDK_LDAP_DENIED='1'
            $ErrorActionPreference='Continue'
            $output=@(& $Executable '-test.run=^TestRootDSEDeniedLab$' '-test.v' '-test.count=1' 2>&1 | ForEach-Object { $_.ToString() })
            [ordered]@{exit_code=$LASTEXITCODE;output=$output} | ConvertTo-Json -Depth 4
        } finally { $env:ADSDK_LDAP_SERVER=$oldServer; $env:ADSDK_LDAP_DENIED=$oldDenied }
    } | ConvertFrom-Json
    $proof.exit_code=$result.exit_code; $proof.output=$result.output; $proof.passed=($result.exit_code -eq 0)
} catch { $proof.error=$_.Exception.Message; $proof.passed=$false }
finally {
    if ($deniedSession) {
        try { Remove-PSSession $deniedSession } catch { $proof.passed=$false; $proof.error='Denial session cleanup failed: ' + $_.Exception.Message }
    }
    if ($creationAttempted) {
        try {
            # Recover a lost creation response only through the unique name and
            # marker. The helper executes inside the already verified member.
            Invoke-Command -Session $AdminSession -ArgumentList $sid,$name,$marker -ScriptBlock ${function:Remove-LabDenialUser}
            $proof.cleanup_confirmed=$true
        } catch { $proof.passed=$false; $proof.error='Denial fixture cleanup failed: ' + $_.Exception.Message }
    }
    $localCredential=$null; $password.Dispose()
}
return [pscustomobject]$proof
