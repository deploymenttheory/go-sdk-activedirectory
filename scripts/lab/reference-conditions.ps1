#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CorpusPath,
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$RunId
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module ActiveDirectory
if ($RunId -notmatch '^conditions-\d{8}T\d{6}Z-[a-f0-9]{8}$' -or
    [IO.Path]::GetFullPath($CorpusPath) -ne "C:\ad-sdk-validation\$RunId\reference-corpus.json") {
    throw 'Unexpected native corpus location.'
}
$corpus = Get-Content -LiteralPath $CorpusPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (@($corpus).Count -ne 10 -or @($corpus | Select-Object -ExpandProperty name -Unique).Count -ne 10) {
    throw 'Expected ten distinct native reference cases.'
}
$domain = Get-ADDomain -Server $Source
$forest = Get-ADForest -Server $Source
$root = Get-ADRootDSE -Server $Source
$policyBase = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$($root.configurationNamingContext)"
$marker = "AD SDK condition reference $RunId"
$suffix = [guid]::NewGuid().ToString('N')
$ouName = "sdk-conditions-$suffix"
$userSam = 'sdk' + $suffix.Substring(0, 12)
$policyNames = [Collections.Generic.List[string]]::new()
$rows = [Collections.Generic.List[object]]::new()
$createdOU = $false
$failure = $null
$clean = $false
$permission = $null

function Get-ErrorDetails($Record) {
    $details = @()
    for ($exception = $Record.Exception; $null -ne $exception; $exception = $exception.InnerException) {
        $code = $null
        if ($exception.PSObject.Properties['ErrorCode']) { $code = $exception.ErrorCode }
        $details += [ordered]@{type=$exception.GetType().FullName; hresult=$exception.HResult; code=$code}
    }
    return [ordered]@{id=$Record.FullyQualifiedErrorId; exceptions=$details}
}

function Get-CanonicalSDDL([string]$Text) {
    return [Security.AccessControl.RawSecurityDescriptor]::new($Text).GetSddlForm([Security.AccessControl.AccessControlSections]::All)
}

function Reserve-PolicyName([string]$Name) {
    if (@(Get-ADAuthenticationPolicy -LDAPFilter "(name=$Name)" -Server $Source).Count -ne 0) {
        throw 'Refusing to adopt an existing authentication policy.'
    }
    # Reserve before creation so cleanup also covers an uncertain create result.
    $policyNames.Add($Name)
}

try {
    foreach ($case in $corpus) {
        $valid = $true
        $normalized = ''
        $parseError = $null
        try { $normalized = Get-CanonicalSDDL $case.input }
        catch { $valid = $false; $parseError = Get-ErrorDetails $_ }
        $matches = ($valid -eq $case.valid) -and ($normalized -ceq $case.normalized)
        $rows.Add([ordered]@{name=$case.name; kind='sddl-normalization'; passed=$matches; accepted=$valid; normalized=$normalized; error=$parseError})
        if (-not $matches) { throw "PowerShell/native SDDL mismatch: $($case.name)" }
    }

    $policyCases = @($corpus | Where-Object { $_.PSObject.Properties['policy_property'] })
    $properties = @('UserAllowedToAuthenticateFrom', 'UserAllowedToAuthenticateTo', 'ServiceAllowedToAuthenticateFrom')
    if ($policyCases.Count -ne 3 -or @(Compare-Object $properties @($policyCases.policy_property)).Count -ne 0) {
        throw 'Unexpected authentication policy reference cases.'
    }
    foreach ($case in $policyCases) {
        $name = "sdk-$suffix-$($case.name)"
        Reserve-PolicyName $name
        $arguments = @{
            Name=$name; Description=$marker; Server=$Source; PassThru=$true
            ProtectedFromAccidentalDeletion=$false; Enforce=$false
        }
        $arguments[$case.policy_property] = $case.normalized
        $created = New-ADAuthenticationPolicy @arguments
        $read = Get-ADAuthenticationPolicy -Identity $created.ObjectGUID -Properties * -Server $Source
        $stored = Get-CanonicalSDDL $read.($case.policy_property)
        $matches = ($stored -ceq $case.normalized) -and -not $read.Enforce
        $rows.Add([ordered]@{name=$case.name; kind='policy-storage'; property=$case.policy_property; passed=$matches; enforced=[bool]$read.Enforce; normalized=$stored})
        if (-not $matches) { throw "Policy readback mismatch: $($case.name)" }
    }

    # Authenticate an ordinary, newly created user before checking authorization.
    if (@(Get-ADOrganizationalUnit -LDAPFilter "(ou=$ouName)" -SearchBase $domain.DistinguishedName -Server $Source).Count -ne 0) {
        throw 'Refusing to adopt an existing fixture OU.'
    }
    $createdOU = $true
    $ou = New-ADOrganizationalUnit -Name $ouName -Description $marker -Path $domain.DistinguishedName -ProtectedFromAccidentalDeletion:$false -PassThru -Server $Source
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 32
        $random.GetBytes($bytes)
        $password = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
    } finally { $random.Dispose() }
    New-ADUser -Name $userSam -SamAccountName $userSam -UserPrincipalName "$userSam@$($domain.DNSRoot)" -Description $marker -Path $ou.DistinguishedName -AccountPassword $password -Enabled:$true -Server $Source
    $ordinary = [PSCredential]::new("$($domain.NetBIOSName)\$userSam", $password)
    $null = Get-ADDomain -Server $Source -Credential $ordinary
    $name = "sdk-$suffix-permission"
    Reserve-PolicyName $name
    $denied = $false
    $denial = $null
    try {
        New-ADAuthenticationPolicy -Name $name -Description $marker -UserAllowedToAuthenticateFrom $policyCases[0].normalized -Enforce:$false -ProtectedFromAccidentalDeletion:$false -Server $Source -Credential $ordinary
    } catch {
        $denial = Get-ErrorDetails $_
        $denied = @($denial.exceptions | Where-Object {
            $_.code -in @(5, 8344) -or ($_.hresult -band 0xffff) -in @(5, 8344) -or
            $_.type -in @('System.UnauthorizedAccessException', 'Microsoft.ActiveDirectory.Management.ADUnauthorizedAccessException')
        }).Count -gt 0
    }
    $permission = [ordered]@{authenticated=$true; denied=$denied; error=$denial}
    if (-not $denied) { throw 'Expected an authorization denial for the ordinary fixture user.' }
} catch {
    $failure = Get-ErrorDetails $_
} finally {
    try {
        foreach ($name in $policyNames) {
            foreach ($policy in @(Get-ADAuthenticationPolicy -LDAPFilter "(name=$name)" -Properties Description -Server $Source)) {
                if ($policy.Description -cne $marker) { throw 'Policy ownership marker does not match; refusing cleanup.' }
                Remove-ADAuthenticationPolicy -Identity $policy.ObjectGUID -Server $Source -Confirm:$false
            }
        }
        if ($createdOU) {
            foreach ($ownedOU in @(Get-ADOrganizationalUnit -LDAPFilter "(ou=$ouName)" -SearchBase $domain.DistinguishedName -Properties Description -Server $Source)) {
                if ($ownedOU.Description -cne $marker) { throw 'OU ownership marker does not match; refusing cleanup.' }
                foreach ($user in @(Get-ADUser -LDAPFilter "(sAMAccountName=$userSam)" -SearchBase $ownedOU.DistinguishedName -Properties Description -Server $Source)) {
                    if ($user.Description -cne $marker) { throw 'User ownership marker does not match; refusing cleanup.' }
                    Remove-ADUser -Identity $user.ObjectGUID -Server $Source -Confirm:$false
                }
                # Nonrecursive removal fails if an unexpected child was added.
                Remove-ADOrganizationalUnit -Identity $ownedOU.ObjectGUID -Server $Source -Confirm:$false
            }
        }
        $deadline = [DateTime]::UtcNow.AddMinutes(3)
        do {
            $remaining = @()
            foreach ($server in @($Source, $Destination)) {
                $remaining += @(Get-ADObject -LDAPFilter "(description=$marker)" -SearchBase $policyBase -Server $server)
                $remaining += @(Get-ADObject -LDAPFilter "(description=$marker)" -SearchBase $domain.DistinguishedName -Server $server)
            }
            if ($remaining.Count -eq 0) { $clean = $true; break }
            Start-Sleep -Seconds 3
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not $clean) { throw 'Fixture cleanup was not confirmed on both domain controllers.' }
    } catch {
        $failure = [ordered]@{operation=$failure; cleanup=(Get-ErrorDetails $_)}
    }
}
$build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[ordered]@{
    schema_version=1; run=$RunId; time=[DateTime]::UtcNow.ToString('o')
    passed=($null -eq $failure -and $clean); error=$failure
    corpus_sha256=(Get-FileHash -LiteralPath $CorpusPath -Algorithm SHA256).Hash
    environment=[ordered]@{
        build="$($build.CurrentBuild).$($build.UBR)"; architecture=$env:PROCESSOR_ARCHITECTURE
        powershell=$PSVersionTable.PSVersion.ToString(); clr=$PSVersionTable.CLRVersion.ToString()
        dotnet_release=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
        ad_module=(Get-Module ActiveDirectory).Version.ToString()
        schema_version=(Get-ADObject -Identity $root.schemaNamingContext -Properties objectVersion -Server $Source).objectVersion
        domain_mode=$domain.DomainMode.ToString(); forest_mode=$forest.ForestMode.ToString()
    }
    cases=@($rows.ToArray()); permission=$permission; cleanup_on_both_controllers=$clean
    scope='Native SDDL versus PowerShell/.NET normalization and rejection; audit-only, unassigned authentication-policy storage/readback; real create authorization denial. No GUI invocation, claim-existence validation, or logon-enforcement claim.'
} | ConvertTo-Json -Depth 12
