param([Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
# Explicit offline reference only: no Get-AD*, provider drive, directory session,
# fixture creation, remoting, command evaluation or network calls.
$previousDrive = $env:ADPS_LoadDefaultDrive
try {
    $env:ADPS_LoadDefaultDrive = '0'
    Import-Module ActiveDirectory
    $module = Get-Module ActiveDirectory
    $assembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Microsoft.ActiveDirectory.Management' }
    $instance = [Reflection.BindingFlags]'Public,NonPublic,Instance'
    $static = [Reflection.BindingFlags]'Public,NonPublic,Static'
    $parserType = $assembly.GetType('Microsoft.ActiveDirectory.Management.QueryParser', $true)
    $nodeType = $assembly.GetType('Microsoft.ActiveDirectory.Management.IADOPathNode', $true)
    $search = $assembly.GetType('Microsoft.ActiveDirectory.Management.Commands.SearchConverters', $true)
    $objectConverter = $search.GetMethod('ToSearchObject', $static)
    $guidConverter = $search.GetMethod('ToSearchGuid', $static)
    $mappings = @{}
    $mappingEvidence = @()
    foreach ($kind in @('ADObject','ADPrincipal','ADAccount','ADUser','ADComputer','ADGroup')) {
        $factory = $assembly.GetType('Microsoft.ActiveDirectory.Management.Commands.'+$kind+'Factory`1', $true).MakeGenericType($assembly.GetType('Microsoft.ActiveDirectory.Management.'+$kind, $true))
        $mappings[$kind] = @{}
        foreach ($entry in $factory.GetField('ADMappingTable',$static).GetValue($null)) {
            $entryType=$entry.GetType()
            $name=$entryType.GetProperty('ExtendedAttribute',$instance).GetValue($entry)
            $attributes=$entryType.GetField('_directoryAttributes',$instance).GetValue($entry)
            $delegate=$entryType.GetField('_toSearchDelegate',$instance).GetValue($entry)
            $mappings[$kind][$name]=@{attributes=$attributes;delegate=$delegate}
            $mappingEvidence += [ordered]@{factory=$kind;property=$name;attributes=$attributes;converter=$delegate.Method.Name;value_type=$entryType.GetProperty('AttributeType',$instance).GetValue($entry).FullName}
        }
    }
    $cases = @(
        @{expression='ObjectClass -like "*"'},
        @{expression='CN -like "*bob*"'},
        @{expression='badPwdCount -ge 5'},
        @{expression='email -like "*" -and ObjectClass -eq "user"'},
        @{expression='EmailAddress -like "*" -and Surname -eq "smith"';profile='user'},
        @{expression='objectClass -eq "user" -and (CN -like "andy*" -or CN -eq "steve")'},
        @{expression='-not EmailAddress -like "*"';profile='user'},
        @{expression='-not lastLogon -le $date';profile='user';date=$true},
        @{expression='lastLogon -gt $date';profile='user';date=$true},
        @{expression='groupType -band 0x80000000'},
        @{expression='memberOf -RecursiveMatch "CN=Group\5c, One,DC=test"'},
        @{expression='cn -eq "a" -or sn -eq "b" -and mail -eq "c"'},
        @{expression='cn -eq ''a''''b'''},
        @{expression='cn -eq "a`"b"'},
        @{expression='cn -eq "a`nb"'},
        @{expression='cn -eq "$literal"'},
        @{expression='cn -eq $literal';literal=$true},
        @{expression='cn -like "a\2a*b?c[d]"'},
        @{expression='cn -eq "a\00\5cb"'},
        @{expression='cn -ne "*"'},
        @{expression='cn -notlike "bob*"'},
        @{expression='cn -notlike "***"'},
        @{expression='badPwdCount -lt 5'},
        @{expression='uSNChanged -eq 9007199254740993'},
        @{expression='Enabled -eq $true';profile='user'},
        @{expression='Enabled -ne "False"';profile='computer'},
        @{expression='PasswordNeverExpires -eq $true';profile='user'},
        @{expression='Deleted -eq $false'},
        @{expression='GroupScope -eq "Global"';profile='group'},
        @{expression='GroupCategory -ne "Security"';profile='group'},
        @{expression='SamAccountName -eq "HOST$"';profile='computer'},
        @{expression='SamAccountName -like "HOST*"';profile='computer'},
        @{expression='ObjectGUID -eq "00112233-4455-6677-8899-aabbccddeeff"'},
        @{expression='SID -eq $sid';profile='user';sid=$true},
        @{expression='cn -eq $null'},
        @{expression='cn -eq $missing'},
        @{expression='cn -eq bob'},
        @{expression='cn -eq "unterminated'},
        @{expression='Enabled -like "*"';profile='user'},
        @{expression='n -eq 1.5';intentional_difference='reject_fractional_literal'},
        @{expression='n -eq 1e3';intentional_difference='reject_exponent_literal'}
    )
    $results=@()
    foreach ($case in $cases) {
        $profile=if($case.profile){$case.profile}else{'object'}
        $referenceValues=@{true=$true;false=$false;null=$null;literal='*)(|(objectClass=*))'}
        $variables=@{}
        if($case.literal){$variables.literal=@{kind='string';value=$referenceValues.literal}}
        if($case.date){$date=[datetime]'2026-01-02T03:04:05Z';$referenceValues.date=$date.ToUniversalTime().ToFileTimeUtc();$variables.date=@{kind='time';value='2026-01-02T03:04:05Z'}}
        if($case.sid){$sid=[System.Security.Principal.SecurityIdentifier]'S-1-5-21-111-222-333-1001';$binary=New-Object byte[] $sid.BinaryLength;$sid.GetBinaryForm($binary,0);$referenceValues.sid=$binary;$variables.sid=@{kind='sid';value=$sid.Value}}
        $tables=@('ADObject')
        if($profile-ne'object'){$tables+='ADPrincipal'}
        if($profile-in@('user','computer')){$tables+='ADAccount'}
        if($profile-ne'object'){$tables+='AD'+(Get-Culture).TextInfo.ToTitleCase($profile)}
        $evaluate=[System.Management.Automation.LanguagePrimitives]::ConvertTo({param($name) if(-not $referenceValues.ContainsKey($name)){throw 'missing explicit reference variable'};return ,$referenceValues[$name]},$assembly.GetType('Microsoft.ActiveDirectory.Management.EvaluateVariableDelegate',$true))
        $convert=[System.Management.Automation.LanguagePrimitives]::ConvertTo({param($node)
            $left=$node.GetType().GetProperty('LeftNode',$instance).GetValue($node)
            $name=$left.GetType().GetProperty('PropertyName',$instance).GetValue($left)
            $mapping=$null;foreach($table in $tables){if($mappings[$table].ContainsKey($name)){$mapping=$mappings[$table][$name]}}
            $attributes=if($mapping){[string[]]$mapping.attributes}else{[string[]]@($name)}
            # Only these observed pure converters are invoked. In particular,
            # no schema discovery, identity lookup, DNS or session helpers run.
            if($name-eq'ObjectGUID'){return $guidConverter.Invoke($null,@($name,[string[]]$attributes,$node,$null))}
            if($name-in@('Enabled','PasswordNeverExpires','GroupScope','GroupCategory','SamAccountName')){
                if($name-ne'SamAccountName'-or$profile-eq'computer'){return $mapping.delegate.DynamicInvoke(@($name,[string[]]$attributes,$node,$null))}
            }
            return $objectConverter.Invoke($null,@($name,[string[]]$attributes,$node,$null))
        },$assembly.GetType('Microsoft.ActiveDirectory.Management.ConvertSearchFilterDelegate',$true))
        $variableConverter=$assembly.GetType('Microsoft.ActiveDirectory.Management.VariableExpressionConverter',$true).GetConstructors($instance)[0].Invoke(@($evaluate))
        $row=[ordered]@{expression=$case.expression;profile=$profile;variables=$variables}
        if($case.date){$row.conversion='schema FILETIME representation supplied by DateTime.ToFileTimeUtc; no schema discovery'}
        if($case.sid){$row.conversion='SID binary representation supplied by SecurityIdentifier.GetBinaryForm; no schema discovery'}
        if($case.intentional_difference){$row.intentional_difference=$case.intentional_difference}
        try{$parser=$parserType.GetConstructors($instance)[0].Invoke(@($case.expression,$variableConverter,$convert));$tree=$parserType.GetProperty('FilterExpressionTree',$instance).GetValue($parser);$row.ldap=$nodeType.GetMethod('GetLdapFilterString').Invoke($tree,@())}
        catch{$failure=$_.Exception;while($failure.InnerException){$failure=$failure.InnerException};$row.error_type=$failure.GetType().FullName;$row.error=$failure.Message}
        $results+=$row
    }
    $reference=[ordered]@{
        schema_version=1;purpose='offline AD expression parser and selected pure converter reference';directory_contacted=$false;server_version=$null;full_ticket_complete=$false
        os_version=[Environment]::OSVersion.Version.ToString();powershell_version=$PSVersionTable.PSVersion.ToString();module_version=$module.Version.ToString()
        assembly_version=$assembly.GetName().Version.ToString();assembly_file_version=(Get-Item -LiteralPath $assembly.Location).VersionInfo.FileVersion
        assembly_sha256=(Get-FileHash -LiteralPath $assembly.Location -Algorithm SHA256).Hash;collector_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        captured_utc=[datetime]::UtcNow.ToString('o');mappings=$mappingEvidence;cases=$results
    }
    [IO.File]::WriteAllText($OutputPath,($reference|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
} finally { $env:ADPS_LoadDefaultDrive=$previousDrive }
