#Requires -Version 5.1
# Execute the actual Remove action with fake Hyper-V/CIM commands. No resources
# are created or removed; this exercises the partial-removal recovery path.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'lab.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Lab script syntax error.' }
$dispatch = $ast.Find({ param($node) $node -is [Management.Automation.Language.SwitchStatementAst] }, $false)
$clause = @($dispatch.Clauses | Where-Object { $_.Item1.Extent.Text -eq "'Remove'" })
if ($clause.Count -ne 1) { throw 'Expected one Remove action.' }
$body = $clause[0].Item2.Extent.Text
$removeAction = [scriptblock]::Create($body.Substring(1, $body.Length - 2))
$helper = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-LabSwitchUnused'
}, $false)
if ($helper) { . ([scriptblock]::Create($helper.Extent.Text)) }

function Test-Removal([string]$Case, [bool]$Allowed, [string]$ExpectedError = '') {
    $ServerVersion = '2025'
    $labRoot = Join-Path $env:TEMP 'ad-sdk-offline-test\server2025'
    $statePath = Join-Path $labRoot 'state.json'
    $switchId = [guid]'a67c7a09-0bc2-416d-80b4-e217ea7a48d6'
    $script:state = [pscustomobject]@{machines=@(); switch_id=$switchId.ToString()}
    $removed = [Collections.Generic.List[string]]::new()
    function Get-OwnedSwitch($State) { return [pscustomobject]@{Id=$switchId} }
    function Get-VMNetworkAdapter { throw 'Unrelated VM breaks host-wide adapter enumeration.' }
    function Get-CimInstance($Namespace, $ClassName, $Filter, $ErrorAction) {
        if ($Case -eq 'query-fails') { throw 'Injected connection query failure.' }
        if ($ClassName -eq 'Msvm_VirtualEthernetSwitch') {
            if ($Case -eq 'missing-switch') { return }
            return [pscustomobject]@{Name=$switchId.ToString()}
        }
        if ($ClassName -ne 'Msvm_EthernetPortAllocationSettingData') { throw 'Unexpected CIM query.' }
        if ($Case -eq 'foreign-offline-connection') {
            return [pscustomobject]@{HostResource=@('\\HOST\root\virtualization\v2:Msvm_VirtualEthernetSwitch.CreationClassName="Msvm_VirtualEthernetSwitch",Name="' + $switchId + '"'); EnabledState=3}
        }
        if ($Case -eq 'unrelated-connection') {
            return [pscustomobject]@{HostResource=@('\\HOST\root\virtualization\v2:Msvm_VirtualEthernetSwitch.Name="d10b18c6-e644-4788-8912-9bd8e0d8953e",CreationClassName="Msvm_VirtualEthernetSwitch"'); EnabledState=2}
        }
        if ($Case -eq 'malformed-connection') {
            return [pscustomobject]@{HostResource=@('\\HOST\root\virtualization\v2:Msvm_VirtualEthernetSwitch.Name="not-a-guid"'); EnabledState=2}
        }
    }
    function Get-CimAssociatedInstance($InputObject, $Association, $ResultClassName, $ErrorAction) {
        if ($Case -eq 'foreign-active-port') { return [pscustomobject]@{Name='owned-by-another-vm'} }
    }
    function Remove-VMSwitch($VMSwitch, [switch]$Force) { $removed.Add('switch') }
    function Get-ChildItem($LiteralPath, [switch]$Force, [switch]$Recurse) {}
    function Assert-LabPath($Path) {
        if (-not ([IO.Path]::GetFullPath($Path)).StartsWith($labRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected cleanup path.' }
    }
    function Remove-Item($LiteralPath, [switch]$Recurse, [switch]$Force) {
        if ($LiteralPath -ne $labRoot) { throw 'Unexpected directory deletion.' }
        $removed.Add('profile')
    }
    function Save-State {}
    $caught = $null
    try { . $removeAction } catch { $caught = $_ }
    if ($Allowed) {
        if ($caught) { throw "$Case failed: $($caught.Exception.Message)" }
        if (($removed -join ',') -ne 'switch,profile') { throw "$Case did not complete the exact removal." }
    } else {
        if (-not $caught -or $caught.Exception.Message -notlike "*$ExpectedError*") { throw "$Case did not reject the unsafe or unverified removal as expected." }
        if ($removed.Count) { throw "$Case removed resources despite a failed precondition." }
    }
    Write-Output ('{0}: passed' -f $Case)
}
Test-Removal 'unrelated-enumeration-error' $true
Test-Removal 'unrelated-connection' $true
Test-Removal 'foreign-offline-connection' $false 'still uses this switch'
Test-Removal 'foreign-active-port' $false 'still uses this switch'
Test-Removal 'query-fails' $false 'Injected connection query failure'
Test-Removal 'missing-switch' $false 'Unable to verify the lab switch'
Test-Removal 'malformed-connection' $false 'Invalid switch reference'
