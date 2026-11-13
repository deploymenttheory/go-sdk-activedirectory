#Requires -Version 5.1
# Captures what Install/Uninstall/Test/Reset-ADServiceAccount actually do on a
# domain member, for issues #47, #48 and #49. This runner CREATES directory
# service accounts and INSTALLS them on the local host, then removes both. It
# observes; it does not claim full evidence.
#
# Run this ON the owned disposable member, not on a domain controller.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$ExpectedDomainSID,
    [Parameter(Mandatory)][guid]$LabId,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$ResultPath,
    [switch]$AllowLocalInstall
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# The switch must be explicit: this runner changes local host credential state.
if (-not $AllowLocalInstall) { throw 'Explicit AllowLocalInstall is required for this disposable reference runner.' }
. (Join-Path $PSScriptRoot 'directory-harness.ps1')
if ($Server -notmatch '\A[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?\z') { throw 'An explicit endpoint is required.' }

$env:ADPS_LoadDefaultDrive = '0'
Import-Module ActiveDirectory -ErrorAction Stop

$domain = Get-ADDomain -Server $Server
if ($domain.DNSRoot -ne 'ad.sdk.test' -or $domain.DomainSID.Value -ne $ExpectedDomainSID) {
    throw 'The explicitly owned disposable domain does not match.'
}
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
    throw 'Run this reference on the owned member, not on a domain controller.'
}
if (-not (Test-ComputerSecureChannel)) { throw 'The member secure channel is not healthy.' }
foreach ($name in @('Install-ADServiceAccount', 'Uninstall-ADServiceAccount', 'Test-ADServiceAccount', 'Reset-ADServiceAccountPassword', 'New-ADServiceAccount')) {
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
$suffix = $runId.Substring(0, 8)
$marker = "ad-sdk-localmsa:$($LabId.ToString()):$runId"
$ledger = @()

function Get-LocalError($Record) {
    $items = @(); $pending = [Collections.Generic.Queue[Exception]]::new()
    $pending.Enqueue($Record.Exception)
    while ($pending.Count) {
        $exception = $pending.Dequeue()
        $code = $null
        if ($exception.PSObject.Properties['ErrorCode']) { $code = [long]$exception.ErrorCode }
        $items += [ordered]@{ type = $exception.GetType().FullName; hresult = [long]$exception.HResult; code = $code; message = $exception.Message }
        if ($exception -is [AggregateException]) { foreach ($inner in $exception.InnerExceptions) { $pending.Enqueue($inner) } }
        elseif ($exception.InnerException) { $pending.Enqueue($exception.InnerException) }
    }
    return $items
}

# Directory-side attributes worth comparing before and after each local step.
$accountProperties = @('objectClass', 'sAMAccountName', 'msDS-ManagedPasswordId', 'msDS-ManagedPasswordInterval',
    'msDS-HostServiceAccountBL', 'msDS-GroupMSAMembership', 'pwdLastSet', 'userAccountControl',
    'msDS-SupportedEncryptionTypes', 'servicePrincipalName', 'whenChanged')

function Get-AccountState([string]$Identity) {
    try {
        $object = Get-ADServiceAccount -Identity $Identity -Server $Server -Properties $accountProperties -ErrorAction Stop
        $fields = [ordered]@{}
        foreach ($name in $accountProperties) {
            $property = $object.PSObject.Properties[$name]
            if (-not $property -or $null -eq $property.Value) { $fields[$name] = [ordered]@{ status = 'absent' }; continue }
            $values = @($property.Value)
            # Binary blobs are recorded as length and digest; their contents are
            # credential material and are never written to evidence.
            if ($name -in @('msDS-ManagedPasswordId', 'msDS-GroupMSAMembership')) {
                $bytes = [byte[]]$values[0]
                $fields[$name] = [ordered]@{ status = 'present'; kind = 'binary'; length = $bytes.Length
                    sha256 = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
                continue
            }
            $fields[$name] = [ordered]@{ status = 'present'; count = $values.Count; values = @($values | ForEach-Object { [string]$_ }) }
        }
        return [ordered]@{ found = $true; dn = $object.DistinguishedName; enabled = $object.Enabled; fields = $fields }
    } catch {
        return [ordered]@{ found = $false; errors = @(Get-LocalError $_) }
    }
}

# Test-ADServiceAccount is the readiness probe under test, so its result and
# any error are both recorded rather than collapsed into a boolean.
function Get-TestResult([string]$Identity) {
    try {
        $value = Test-ADServiceAccount -Identity $Identity -ErrorAction Stop
        return [ordered]@{ ran = $true; result = [bool]$value; errors = @() }
    } catch {
        return [ordered]@{ ran = $false; result = $null; errors = @(Get-LocalError $_) }
    }
}

$assembly = (Get-Command Install-ADServiceAccount).ImplementingType.Assembly.Location
$build = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os = Get-CimInstance Win32_OperatingSystem
$environment = [ordered]@{
    run_id = $runId; lab_id = $LabId.ToString(); domain_sid = $ExpectedDomainSID
    server = $Server; computer = [Environment]::MachineName; os = $os.Caption
    os_build = "$($build.CurrentBuild).$($build.UBR)"; architecture = $env:PROCESSOR_ARCHITECTURE
    powershell = $PSVersionTable.PSVersion.ToString()
    module_version = (Get-Module ActiveDirectory).Version.ToString()
    module_file_version = (Get-Item -LiteralPath $assembly).VersionInfo.FileVersion
    module_sha256 = (Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash.ToLowerInvariant()
    domain_level = $domain.DomainMode.ToString()
    observed_at = [DateTime]::UtcNow.ToString('o')
}

$run = [ordered]@{
    schema_version = 1
    purpose = 'go-sdk-activedirectory-local-service-account-reference'
    run_id = $runId
    provenance = [ordered]@{ source_commit = $SourceCommit; runner_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    environment = $environment
    cases = @()
    passed = $false
    unresolved = @(
        'No secret material is recorded: managed password blobs appear as length and digest only.',
        'Service start/logon with an installed account is not exercised; readiness is not proven by Test alone.',
        'Partial-failure and permission-denied paths are not covered by this initial runner.'
    )
}

# One step: run a command, record directory state and the readiness probe
# before and after, and never stop the run on a command error.
function Invoke-Step([string]$Id, [string]$Command, [hashtable]$Parameters, [string]$Identity) {
    $case = [ordered]@{ id = $Id; command = $Command; parameters = [ordered]@{}; outcome = 'not_run'
        before = [ordered]@{}; after = [ordered]@{}; test_before = $null; test_after = $null; errors = @() }
    foreach ($key in $Parameters.Keys) {
        # Never record a password value, even a generated one.
        if ($key -in @('AccountPassword', 'Password')) { $case.parameters[$key] = '<redacted>' } else { $case.parameters[$key] = "$($Parameters[$key])" }
    }
    $case.before = Get-AccountState $Identity
    $case.test_before = Get-TestResult $Identity
    try {
        & $Command @Parameters -ErrorAction Stop | Out-Null
        $case.outcome = 'success'
    } catch {
        $case.outcome = 'error'
        $case.errors = @(Get-LocalError $_)
    }
    $case.after = Get-AccountState $Identity
    $case.test_after = Get-TestResult $Identity
    return $case
}

$failure = $null
try {
    $member = Get-ADComputer -Identity $env:COMPUTERNAME -Server $Server
    $ouName = "ADSDK-LOCALMSA-$suffix"
    $ou = New-ADOrganizationalUnit -Name $ouName -Path $domain.DistinguishedName -Description $marker -ProtectedFromAccidentalDeletion:$false -Server $Server -PassThru
    $ledger += , ([pscustomobject]@{ kind = 'ou'; dn = $ou.DistinguishedName })
    $ouDN = $ou.DistinguishedName

    # A standalone MSA (sMSA): restricted to a single computer, installed with a
    # host-managed password. This is the subject of issues #47 and #49.
    $smsaName = "sdks$suffix"
    $smsa = New-ADServiceAccount -Name $smsaName -SamAccountName $smsaName -Path $ouDN -Description $marker `
        -RestrictToSingleComputer -Server $Server -PassThru -ErrorAction Stop
    $ledger += , ([pscustomobject]@{ kind = 'account'; dn = $smsa.DistinguishedName })
    $run.cases += , ([ordered]@{ id = 'fixture-smsa'; command = 'New-ADServiceAccount'; parameters = [ordered]@{ RestrictToSingleComputer = 'True' }
        outcome = 'success'; after = (Get-AccountState $smsaName); test_after = (Get-TestResult $smsaName); errors = @() })

    # A group MSA (gMSA): retrievable by this member, for the Install contrast.
    $gmsaName = "sdkg$suffix"
    $gmsa = New-ADServiceAccount -Name $gmsaName -SamAccountName $gmsaName -Path $ouDN -Description $marker `
        -DNSHostName "$gmsaName.$($domain.DNSRoot)" -PrincipalsAllowedToRetrieveManagedPassword $member `
        -Server $Server -PassThru -ErrorAction Stop
    $ledger += , ([pscustomobject]@{ kind = 'account'; dn = $gmsa.DistinguishedName })
    $run.cases += , ([ordered]@{ id = 'fixture-gmsa'; command = 'New-ADServiceAccount'; parameters = [ordered]@{ PrincipalsAllowedToRetrieveManagedPassword = $member.SamAccountName }
        outcome = 'success'; after = (Get-AccountState $gmsaName); test_after = (Get-TestResult $gmsaName); errors = @() })

    # Issue #48: what does Test report before the account is installed?
    # Issue #47: install the gMSA, then re-test.
    $run.cases += , (Invoke-Step 'install-gmsa' 'Install-ADServiceAccount' @{ Identity = $gmsaName } $gmsaName)
    # Issue #49: does Reset work on an installed gMSA, or only a standalone one?
    $run.cases += , (Invoke-Step 'reset-gmsa-installed' 'Reset-ADServiceAccountPassword' @{ Identity = $gmsaName } $gmsaName)
    $run.cases += , (Invoke-Step 'uninstall-gmsa' 'Uninstall-ADServiceAccount' @{ Identity = $gmsaName } $gmsaName)
    # A second uninstall shows whether the operation is idempotent.
    $run.cases += , (Invoke-Step 'uninstall-gmsa-repeat' 'Uninstall-ADServiceAccount' @{ Identity = $gmsaName } $gmsaName)

    # The standalone account needs an explicit password at install time, which
    # is exactly the nullable-credential path the bindings were extended for.
    $password = ConvertTo-SecureString ('Aa9!' + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $run.cases += , (Invoke-Step 'install-smsa-with-password' 'Install-ADServiceAccount' @{ Identity = $smsaName; AccountPassword = $password } $smsaName)
    $run.cases += , (Invoke-Step 'reset-smsa-installed' 'Reset-ADServiceAccountPassword' @{ Identity = $smsaName } $smsaName)
    $run.cases += , (Invoke-Step 'uninstall-smsa' 'Uninstall-ADServiceAccount' @{ Identity = $smsaName } $smsaName)
    # Reset after uninstall distinguishes a directory operation from a local one.
    $run.cases += , (Invoke-Step 'reset-smsa-uninstalled' 'Reset-ADServiceAccountPassword' @{ Identity = $smsaName } $smsaName)
    # Installing an account that does not exist shows the failure shape.
    $run.cases += , (Invoke-Step 'install-missing' 'Install-ADServiceAccount' @{ Identity = "sdkx$suffix" } "sdkx$suffix")
    $run.passed = $true
} catch {
    $failure = $_
    $run.unresolved += @('Fixture preparation failed before all steps were observed.')
    $run.cases += , ([ordered]@{ id = 'runner-failure'; command = ''; outcome = 'error'; errors = @(Get-LocalError $_) })
} finally {
    # Remove only what this run created: accounts first, then the container.
    $cleanup = @()
    foreach ($item in @($ledger | Where-Object kind -eq 'account') + @($ledger | Where-Object kind -eq 'ou')) {
        $state = [ordered]@{ dn = $item.dn; kind = $item.kind; removed = $false; errors = @() }
        try {
            if ($item.kind -eq 'account') {
                # Best effort: an account left installed locally must not be
                # left behind, but a failure here is recorded, not swallowed.
                try { Uninstall-ADServiceAccount -Identity $item.dn -ErrorAction Stop } catch {}
                Remove-ADServiceAccount -Identity $item.dn -Server $Server -Confirm:$false -ErrorAction Stop
            } else {
                Remove-ADOrganizationalUnit -Identity $item.dn -Server $Server -Recursive -Confirm:$false -ErrorAction Stop
            }
            try {
                $null = Get-ADObject -Identity $item.dn -Server $Server -ErrorAction Stop
                $state.errors = @([ordered]@{ type = 'ObjectStillPresent'; message = 'The object was still readable after removal.' })
            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                $state.removed = $true
            }
        } catch { $state.errors = @(Get-LocalError $_) }
        $cleanup += , $state
    }
    $run['cleanup'] = @($cleanup)
    if (@($cleanup | Where-Object { -not $_.removed }).Count) {
        $run.unresolved += @('Owned fixture cleanup did not confirm removal of every object; inspect the lab.')
    }
    Write-DirectoryNewJSON (Join-Path $resultRoot 'local-service-accounts.json') $run
}
if ($failure) { throw 'Local service account reference failed; inspect the retained artifact.' }
Write-Output 'Local service account behaviour captured; evidence remains incomplete.'
