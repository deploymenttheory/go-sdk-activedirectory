#Requires -Version 5.1
# Captures what the reference module actually writes to msDS-TransformationRules
# for each New/Set-ADClaimTransformPolicy form. This runner CREATES and REMOVES
# claim transformation policies and one claim type in an owned disposable
# domain. It observes; it does not claim full evidence.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$ExpectedDomainSID,
    [Parameter(Mandatory)][guid]$LabId,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$ResultPath,
    [switch]$AllowWrites
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# The write switch must be explicit: this runner mutates the configuration
# partition of whatever domain it is pointed at.
if (-not $AllowWrites) { throw 'Explicit AllowWrites is required for this disposable reference runner.' }
. (Join-Path $PSScriptRoot 'directory-harness.ps1')
if ($Server -notmatch '\A[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?\z') { throw 'An explicit endpoint is required.' }

$env:ADPS_LoadDefaultDrive = '0'
Import-Module ActiveDirectory -ErrorAction Stop

# Refuse to run anywhere but the owned disposable domain.
$domain = Get-ADDomain -Server $Server
if ($domain.DNSRoot -ne 'ad.sdk.test' -or $domain.DomainSID.Value -ne $ExpectedDomainSID) {
    throw 'The explicitly owned disposable domain does not match.'
}
$root = Get-ADRootDSE -Server $Server
$forest = Get-ADForest -Server $Server
$configuration = $root.configurationNamingContext
$policyContainer = "CN=Claims Transformation Policies,CN=Claims Configuration,CN=Services,$configuration"
$claimContainer = "CN=Claim Types,CN=Claims Configuration,CN=Services,$configuration"
foreach ($container in @($policyContainer, $claimContainer)) {
    if (@(Get-ADObject -Identity $container -Server $Server -ErrorAction SilentlyContinue).Count -ne 1) {
        throw "Required claims container is missing: $container"
    }
}
foreach ($name in @('New-ADClaimTransformPolicy', 'Set-ADClaimTransformPolicy', 'Remove-ADClaimTransformPolicy', 'New-ADClaimType', 'Remove-ADClaimType')) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "The installed module lacks $name." }
}

$resultRoot = [IO.Path]::GetFullPath($ResultPath)
if (Test-Path -LiteralPath $resultRoot) { throw 'Use a new result directory for each run.' }
$parent = [IO.Path]::GetDirectoryName($resultRoot)
while ($parent) {
    if ((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Result path contains a reparse point.'
    }
    $parent = [IO.Path]::GetDirectoryName($parent)
}
$null = New-Item -ItemType Directory -Path $resultRoot

$runId = [guid]::NewGuid().ToString('N')
$suffix = $runId.Substring(0, 10)
$marker = "ad-sdk-claims:$($LabId.ToString()):$runId"
$ledger = @()

# Every raw attribute read back after a write. The compiled rules are binary and
# server-generated; only their length and digest are recorded, never a guess at
# their meaning.
$policyProperties = @('msDS-TransformationRules', 'msDS-TransformationRulesCompiled', 'objectClass', 'name', 'displayName', 'description', 'whenCreated', 'uSNChanged')

function Get-ClaimsRawPolicy([string]$DistinguishedName) {
    $object = Get-ADObject -Identity $DistinguishedName -Server $Server -Properties $policyProperties -ErrorAction Stop
    $fields = [ordered]@{}
    foreach ($name in $policyProperties) {
        $property = $object.PSObject.Properties[$name]
        if (-not $property -or $null -eq $property.Value) { $fields[$name] = [ordered]@{ status = 'absent' }; continue }
        $values = @($property.Value)
        if ($name -eq 'msDS-TransformationRulesCompiled') {
            # Binary and server-generated. Record shape, not an interpretation.
            $bytes = [byte[]]$values[0]
            $fields[$name] = [ordered]@{
                status = 'present'; kind = 'binary'; count = $values.Count; length = $bytes.Length
                sha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
            }
            continue
        }
        if ($name -eq 'msDS-TransformationRules') {
            # The whole point of this capture: retain the exact text, its byte
            # length and a digest so whitespace and line endings are provable.
            $text = [string]$values[0]
            $fields[$name] = [ordered]@{
                status = 'present'; kind = 'text'; count = $values.Count; value = $text
                utf8_length = [Text.Encoding]::UTF8.GetByteCount($text)
                sha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-', '').ToLowerInvariant()
                lines  = @($text -split "`r`n|`n|`r")
            }
            continue
        }
        $fields[$name] = [ordered]@{ status = 'present'; kind = 'string'; count = $values.Count; values = @($values | ForEach-Object { [string]$_ }) }
    }
    return [ordered]@{ distinguished_name = $object.DistinguishedName; object_guid = $object.ObjectGUID.ToString(); fields = $fields }
}

function Get-ClaimsError($Record) {
    $items = @(); $pending = [Collections.Generic.Queue[Exception]]::new()
    $pending.Enqueue($Record.Exception)
    while ($pending.Count) {
        $exception = $pending.Dequeue()
        $items += [ordered]@{ type = $exception.GetType().FullName; hresult = [long]$exception.HResult; message = $exception.Message }
        if ($exception -is [AggregateException]) { foreach ($inner in $exception.InnerExceptions) { $pending.Enqueue($inner) } }
        elseif ($exception.InnerException) { $pending.Enqueue($exception.InnerException) }
    }
    return $items
}

$assembly = (Get-Command New-ADClaimTransformPolicy).ImplementingType.Assembly.Location
$build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$module = Get-Module ActiveDirectory
$os = Get-CimInstance Win32_OperatingSystem
$environment = [ordered]@{
    run_id = $runId; lab_id = $LabId.ToString(); domain_sid = $ExpectedDomainSID
    server = $Server; os = $os.Caption; os_build = "$($build.CurrentBuild).$($build.UBR)"
    architecture = $env:PROCESSOR_ARCHITECTURE; powershell = $PSVersionTable.PSVersion.ToString()
    module_version = $module.Version.ToString()
    module_file_version = (Get-Item -LiteralPath $assembly).VersionInfo.FileVersion
    module_sha256 = (Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash.ToLowerInvariant()
    schema_version = [int](Get-ADObject -Identity $root.schemaNamingContext -Server $Server -Properties objectVersion).objectVersion
    domain_level = $domain.DomainMode.ToString(); forest_level = $forest.ForestMode.ToString()
    configuration_naming_context = $configuration
    domain_controller_functionality = $root.domainControllerFunctionality
    observed_at = [DateTime]::UtcNow.ToString('o')
}

$run = [ordered]@{
    schema_version = 1
    purpose = 'go-sdk-activedirectory-claims-transformation-reference'
    run_id = $runId
    provenance = [ordered]@{ source_commit = $SourceCommit; runner_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    environment = $environment
    cases = @()
    passed = $false
    unresolved = @(
        'Set-ADClaimTransformLink and Clear-ADClaimTransformLink are NOT exercised: they require a second forest with a trust, which this single-forest lab does not provide.',
        'Rule-language semantics are not interpreted. This run records the exact text the module wrote; it does not prove how the server evaluates it.',
        'msDS-TransformationRulesCompiled is recorded as length and digest only.'
    )
}

$claimTypeDN = $null
$failure = $null
try {
    # One claim type fixture, needed by the *Except forms which name claim types.
    $claimId = "ad://ext/sdk$suffix"
    $claimType = New-ADClaimType -DisplayName "sdk$suffix" -ID $claimId -SourceAttribute 'department' -AppliesToClasses @('user') -Description $marker -Server $Server -PassThru -ErrorAction Stop
    $claimTypeDN = $claimType.DistinguishedName
    $ledger += , ([pscustomobject]@{ role = 'claim-type'; dn = $claimTypeDN; kind = 'claimtype' })
    $run.cases += , ([ordered]@{ id = 'fixture-claim-type'; command = 'New-ADClaimType'; outcome = 'success'; parameters = [ordered]@{ ID = $claimId; SourceAttribute = 'department' }; observed = (Get-ADObject -Identity $claimTypeDN -Server $Server -Properties 'msDS-ClaimValueType', 'msDS-ClaimAttributeSource', 'msDS-ClaimSourceType' | ForEach-Object { [ordered]@{ value_type = $_.'msDS-ClaimValueType'; attribute_source = $_.'msDS-ClaimAttributeSource'; source_type = $_.'msDS-ClaimSourceType' } }); errors = @() })

    # Each New-ADClaimTransformPolicy form, captured independently.
    $forms = @(
        [ordered]@{ id = 'new-allow-all'; splat = @{ AllowAll = $true } }
        [ordered]@{ id = 'new-deny-all'; splat = @{ DenyAll = $true } }
        [ordered]@{ id = 'new-allow-all-except'; splat = @{ AllowAllExcept = @($claimId) } }
        [ordered]@{ id = 'new-deny-all-except'; splat = @{ DenyAllExcept = @($claimId) } }
    )
    foreach ($form in $forms) {
        $name = "sdkp$suffix$($run.cases.Count)"
        $case = [ordered]@{ id = $form.id; command = 'New-ADClaimTransformPolicy'; parameters = [ordered]@{}; outcome = 'not_run'; observed = $null; errors = @() }
        foreach ($key in $form.splat.Keys) { $case.parameters[$key] = $form.splat[$key] }
        # Splatting requires a variable; an expression cannot be splatted.
        $splat = $form.splat
        try {
            $policy = New-ADClaimTransformPolicy -Name $name -Description $marker -Server $Server -PassThru -ErrorAction Stop @splat
            $ledger += , ([pscustomobject]@{ role = $form.id; dn = $policy.DistinguishedName; kind = 'policy' })
            $case.observed = Get-ClaimsRawPolicy $policy.DistinguishedName
            $case.outcome = 'success'
        } catch { $case.outcome = 'error'; $case.errors = @(Get-ClaimsError $_) }
        $run.cases += , $case
    }

    # The explicit Rule form, plus Set applying each shorthand to one policy, so
    # a transition is observable and not just a creation.
    $setName = "sdks$suffix"
    $setCase = [ordered]@{ id = 'new-rule-explicit'; command = 'New-ADClaimTransformPolicy'; parameters = [ordered]@{ Rule = 'C1:[] => Issue(claim = C1);' }; outcome = 'not_run'; observed = $null; errors = @() }
    $setPolicyDN = $null
    try {
        $policy = New-ADClaimTransformPolicy -Name $setName -Description $marker -Rule 'C1:[] => Issue(claim = C1);' -Server $Server -PassThru -ErrorAction Stop
        $setPolicyDN = $policy.DistinguishedName
        $ledger += , ([pscustomobject]@{ role = 'set-target'; dn = $setPolicyDN; kind = 'policy' })
        $setCase.observed = Get-ClaimsRawPolicy $setPolicyDN
        $setCase.outcome = 'success'
    } catch { $setCase.outcome = 'error'; $setCase.errors = @(Get-ClaimsError $_) }
    $run.cases += , $setCase

    if ($setPolicyDN) {
        foreach ($form in @(
                [ordered]@{ id = 'set-allow-all'; splat = @{ AllowAll = $true } }
                [ordered]@{ id = 'set-deny-all'; splat = @{ DenyAll = $true } }
                [ordered]@{ id = 'set-allow-all-except'; splat = @{ AllowAllExcept = @($claimId) } }
                [ordered]@{ id = 'set-deny-all-except'; splat = @{ DenyAllExcept = @($claimId) } }
            )) {
            $case = [ordered]@{ id = $form.id; command = 'Set-ADClaimTransformPolicy'; parameters = [ordered]@{}; outcome = 'not_run'; before = $null; observed = $null; errors = @() }
            foreach ($key in $form.splat.Keys) { $case.parameters[$key] = $form.splat[$key] }
            $splat = $form.splat
            try {
                $case.before = Get-ClaimsRawPolicy $setPolicyDN
                Set-ADClaimTransformPolicy -Identity $setPolicyDN -Server $Server -ErrorAction Stop @splat
                $case.observed = Get-ClaimsRawPolicy $setPolicyDN
                $case.outcome = 'success'
            } catch { $case.outcome = 'error'; $case.errors = @(Get-ClaimsError $_) }
            $run.cases += , $case
        }
    }
    $run.passed = $true
} catch {
    $failure = $_
    $run.unresolved += @('Fixture preparation or capture failed before all forms were observed.')
    $run.cases += , ([ordered]@{ id = 'runner-failure'; command = ''; outcome = 'error'; errors = @(Get-ClaimsError $_) })
} finally {
    # Remove only what this run created, newest first, and record the outcome.
    $cleanup = @()
    foreach ($item in ($ledger | Sort-Object -Property @{Expression = { $_.kind } } -Descending)) {
        $state = [ordered]@{ dn = $item.dn; kind = $item.kind; removed = $false; errors = @() }
        try {
            if ($item.kind -eq 'policy') { Remove-ADClaimTransformPolicy -Identity $item.dn -Server $Server -Confirm:$false -ErrorAction Stop }
            else { Remove-ADClaimType -Identity $item.dn -Server $Server -Confirm:$false -ErrorAction Stop }
            $state.removed = -not (Get-ADObject -Identity $item.dn -Server $Server -ErrorAction SilentlyContinue)
        } catch { $state.errors = @(Get-ClaimsError $_) }
        $cleanup += , $state
    }
    $run['cleanup'] = @($cleanup)
    if (@($cleanup | Where-Object { -not $_.removed }).Count) {
        $run.unresolved += @('Owned fixture cleanup did not confirm removal of every object; inspect the lab.')
    }
    Write-DirectoryNewJSON (Join-Path $resultRoot 'claims-transformation.json') $run
}
if ($failure) { throw 'Claims transformation reference failed; inspect the retained artifact.' }
Write-Output 'Claims transformation forms captured. Trust-link forms remain unobserved; evidence is incomplete.'
