param([Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
# Offline converter comparison only. No AD cmdlet, provider drive, directory
# session, network operation, fixture creation or password is used.
$previous = $env:ADPS_LoadDefaultDrive
try {
    $env:ADPS_LoadDefaultDrive = '0'
    Import-Module ActiveDirectory
    $module = Get-Module ActiveDirectory
    $assembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Microsoft.ActiveDirectory.Management' }
    $flags = [Reflection.BindingFlags]'Public,NonPublic,Static,Instance'
    $converter = $assembly.GetType('Microsoft.ActiveDirectory.Management.Commands.AccountExpiresUtils',$true).GetMethod('ToDirectoryAccountExpirationDate',$flags)
    $cases = @(
        @{kind='clear'},
        @{kind='set';instant='2026-11-13T11:22:33.1234567Z'},
        @{kind='set';instant='2026-11-13T12:22:33.1234567+01:00'},
        @{kind='set';instant='1601-01-01T00:00:00.0000001Z'}
    )
    $rows = @()
    foreach ($case in $cases) {
        $entity = [Activator]::CreateInstance($assembly.GetType('Microsoft.ActiveDirectory.Management.ADObject',$true))
        $values = [Activator]::CreateInstance($assembly.GetType('Microsoft.ActiveDirectory.Management.ADPropertyValueCollection',$true))
        if ($case.kind -eq 'set') {
            $date = [DateTimeOffset]::Parse($case.instant,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime
            $values.Add($date) | Out-Null
        }
        $converter.Invoke($null,@('AccountExpirationDate',[string[]]@('accountExpires'),$values,$entity,$null)) | Out-Null
        $rows += [ordered]@{kind=$case.kind;instant=$case.instant;ldap_value=[string]$entity['accountExpires'].Value}
    }
    # Read-only metadata/IL provenance for the documented manual inspection of
    # SearchADAccount criteria. Do not invoke the cmdlet or its session methods.
    $stateType = $assembly.GetType('Microsoft.ActiveDirectory.Management.Commands.SearchADAccount',$true)
    $methods = @()
    foreach ($name in @('SearchADAccountBeginCSRoutine','GetInactiveTimeSpanDays','FilterIsLockedOut')) {
        $method = $stateType.GetMethod($name,$flags)
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $digest = [BitConverter]::ToString($hash.ComputeHash($method.GetMethodBody().GetILAsByteArray())).Replace('-','') }
        finally { $hash.Dispose() }
        $methods += [ordered]@{method=$name;il_sha256=$digest}
    }
    $factory = $assembly.GetType('Microsoft.ActiveDirectory.Management.Commands.ADAccountFactory`1',$true).MakeGenericType($assembly.GetType('Microsoft.ActiveDirectory.Management.ADAccount',$true))
    $mappings = @()
    foreach ($table in @('ADMappingTable','ADAMMappingTable')) {
        foreach ($entry in $factory.GetField($table,$flags).GetValue($null)) {
            $name = $entry.GetType().GetProperty('ExtendedAttribute',$flags).GetValue($entry)
            if ($name -notin @('LockedOut','PasswordExpired','LastLogonDate')) { continue }
            $mappings += [ordered]@{table=$table;property=$name;attributes=[string[]]$entry.GetType().GetField('_directoryAttributes',$flags).GetValue($entry)}
        }
    }
    [ordered]@{
        schema_version=1;source='offline_module_converter';directory_contacted=$false
        module_version=$module.Version.ToString()
        assembly_file_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($assembly.Location).FileVersion
        assembly_sha256=(Get-FileHash -LiteralPath $assembly.Location -Algorithm SHA256).Hash
        host_version=[Environment]::OSVersion.Version.ToString()
        powershell_version=$PSVersionTable.PSVersion.ToString()
        converter=$converter.DeclaringType.FullName+'.'+$converter.Name
        state_inspection=[ordered]@{methods=$methods;mappings=$mappings;greater_or_equal_operator=[int][Enum]::Parse($assembly.GetType('Microsoft.ActiveDirectory.Management.ADOperator',$true),'Ge')}
        cases=$rows
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
} finally {
    $env:ADPS_LoadDefaultDrive=$previous
}
