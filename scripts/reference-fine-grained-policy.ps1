# Read-only observations of caller-selected existing fixtures. No fixture creation.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Server,
    [string[]]$PolicyDN = @(),
    [string[]]$UserDN = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

function Convert-Policy($Policy) {
    if ($null -eq $Policy) { return $null }
    $fields = [ordered]@{
        distinguished_name = [string]$Policy.DistinguishedName
        guid = [string]$Policy.ObjectGUID
        precedence = $Policy.Precedence
        complexity_enabled = $Policy.ComplexityEnabled
        reversible_encryption_enabled = $Policy.ReversibleEncryptionEnabled
        password_history_count = $Policy.PasswordHistoryCount
        min_password_length = $Policy.MinPasswordLength
        lockout_threshold = $Policy.LockoutThreshold
        applies_to = @($Policy.AppliesTo | ForEach-Object { [string]$_ })
    }
    foreach ($name in @('MinPasswordAge', 'MaxPasswordAge', 'LockoutDuration', 'LockoutObservationWindow')) {
        # Preserve exact .NET ticks as strings, including sentinel conversions.
        $value = $Policy.$name
        $fields[$name + '_ticks'] = if ($null -eq $value) { $null } else { $value.Ticks.ToString([Globalization.CultureInfo]::InvariantCulture) }
    }
    return $fields
}

function Observe([string]$Operation, [string]$Identity, [scriptblock]$Read) {
    $items = [Collections.Generic.List[object]]::new()
    try {
        & $Read | ForEach-Object { $items.Add($_) }
        return [ordered]@{ operation = $Operation; identity = $Identity; complete = $true; items = @($items.ToArray()); error = $null }
    } catch {
        return [ordered]@{
            operation = $Operation; identity = $Identity; complete = $false
            items = @($items.ToArray()); error = [ordered]@{ type = $_.Exception.GetType().FullName; message = $_.Exception.Message; id = $_.FullyQualifiedErrorId }
        }
    }
}

$root = Get-ADRootDSE -Server $Server -ErrorAction Stop
$module = Get-Module ActiveDirectory
$records = @()
foreach ($dn in $PolicyDN) {
    $records += Observe 'policy' $dn { Convert-Policy (Get-ADFineGrainedPasswordPolicy -Server $Server -Identity $dn -Properties * -ErrorAction Stop) }
    $records += Observe 'subjects' $dn {
        Get-ADFineGrainedPasswordPolicySubject -Server $Server -Identity $dn -ErrorAction Stop | ForEach-Object {
            [ordered]@{ distinguished_name = [string]$_.DistinguishedName; guid = [string]$_.ObjectGUID; object_class = [string]$_.ObjectClass; sam_account_name = [string]$_.SamAccountName }
        }
    }
    $records += Observe 'raw-policy' $dn {
        $names = @('msDS-PasswordSettingsPrecedence', 'msDS-PasswordHistoryLength', 'msDS-MinimumPasswordLength', 'msDS-LockoutThreshold', 'msDS-MinimumPasswordAge', 'msDS-MaximumPasswordAge', 'msDS-LockoutDuration', 'msDS-LockoutObservationWindow', 'msDS-PasswordComplexityEnabled', 'msDS-PasswordReversibleEncryptionEnabled', 'msDS-PSOAppliesTo', 'uSNChanged')
        $object = Get-ADObject -Server $Server -Identity $dn -Properties $names -ErrorAction Stop
        $raw = [ordered]@{ distinguished_name = [string]$object.DistinguishedName; guid = [string]$object.ObjectGUID }
        foreach ($name in $names) {
            $property = $object.PSObject.Properties[$name]
            $raw[$name] = if ($null -eq $property) { $null } else { @($property.Value | ForEach-Object { [string]$_ }) }
        }
        $raw
    }
}
foreach ($dn in $UserDN) {
    $records += Observe 'resultant' $dn {
        Convert-Policy (Get-ADUserResultantPasswordPolicy -Server $Server -Identity $dn -ErrorAction Stop)
    }
    $records += Observe 'raw-resultant' $dn {
        $user = Get-ADUser -Server $Server -Identity $dn -Properties msDS-ResultantPSO -ErrorAction Stop
        [ordered]@{ distinguished_name = [string]$user.DistinguishedName; guid = [string]$user.ObjectGUID; resultant_pso = @($user.'msDS-ResultantPSO' | ForEach-Object { [string]$_ }) }
    }
}
[ordered]@{
    schema_version = 1; collected_utc = [DateTime]::UtcNow.ToString('o'); server = $Server
    module_version = [string]$module.Version; module_path = $module.Path
    powershell_version = [string]$PSVersionTable.PSVersion
    domain_functionality = [string]$root.DomainFunctionality; server_functionality = [string]$root.DomainControllerFunctionality
    dns_host_name = [string]$root.DnsHostName; records = $records
} | ConvertTo-Json -Depth 15
