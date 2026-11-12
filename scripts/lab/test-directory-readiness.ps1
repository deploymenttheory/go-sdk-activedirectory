#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'guest.ps1')

# Execute the real guest readiness block with only its external AD/session
# boundary mocked. A synchronized DC without a RID pool must not be accepted.
$script:attempt=0;$script:closed=0;$script:delays=0;$script:ridReads=0
$script:scenario=''
function Wait-LabGuest { $script:attempt++; return [pscustomobject]@{attempt=$script:attempt} }
function Remove-PSSession { param($Session) $script:closed++ }
function Invoke-Command { param($Session,[scriptblock]$ScriptBlock) & $ScriptBlock }
function Start-Sleep { param($Seconds) $script:delays++; if($script:delays -gt 1){throw 'Readiness failed to accept the healthy second observation.'} }
function Import-Module { param($Name) }
function Get-ADDomain { param($Server) if($Server -ne 'localhost'){throw 'Directory probe escaped the local DC.'}; return @{} }
function Get-Service { return [pscustomobject]@{Name='NTDS';Status='Running'} }
function Get-SmbShare { return @('SYSVOL','NETLOGON') }
function Get-ADRootDSE { return [pscustomobject]@{isSynchronized=@('TRUE')} }
function Get-ADComputer {
    param($Identity,$Properties,$Server)
    if($Server -ne 'localhost' -or $Identity -ne $env:COMPUTERNAME){throw 'RID computer lookup was not local.'}
    if($script:scenario -eq 'missing-reference' -and $script:attempt -eq 1){return [pscustomobject]@{rIDSetReferences=$null}}
    return [pscustomobject]@{rIDSetReferences='CN=RID Set,CN=owned-dc,DC=ad,DC=sdk,DC=test'}
}
function Get-ADObject {
    param($Identity,$Properties,$Server)
    $script:ridReads++
    if($Server -ne 'localhost' -or $Identity -ne 'CN=RID Set,CN=owned-dc,DC=ad,DC=sdk,DC=test'){throw 'RID lookup did not follow the local reference.'}
    if($script:attempt -eq 1) {
        switch($script:scenario) {
            'unallocated' {return [pscustomobject]@{rIDPreviousAllocationPool=0;rIDAllocationPool=0;rIDNextRID=0}}
            'missing-pool' {return [pscustomobject]@{rIDPreviousAllocationPool=$null;rIDAllocationPool=0;rIDNextRID=0}}
            'reversed-pool' {return [pscustomobject]@{rIDPreviousAllocationPool=429496729800;rIDAllocationPool=429496729800;rIDNextRID=200}}
            'exhausted' {return [pscustomobject]@{rIDPreviousAllocationPool=6867652707404;rIDAllocationPool=6867652707404;rIDNextRID=1600}}
            'below-start' {return [pscustomobject]@{rIDPreviousAllocationPool=6867652707404;rIDAllocationPool=6867652707404;rIDNextRID=1099}}
            'invalid-number' {return [pscustomobject]@{rIDPreviousAllocationPool='invalid';rIDAllocationPool=0;rIDNextRID=0}}
            'read-denied' {throw 'Access to RID state denied.'}
            'prefetched' {return [pscustomobject]@{rIDPreviousAllocationPool=6867652707404;rIDAllocationPool=9015136355904;rIDNextRID=1600}}
            'last-free-rid' {return [pscustomobject]@{rIDPreviousAllocationPool=6867652707404;rIDAllocationPool=6867652707404;rIDNextRID=1599}}
        }
    }
    return [pscustomobject]@{rIDPreviousAllocationPool=6867652707404;rIDAllocationPool=6867652707404;rIDNextRID=1103}
}
$credential=[PSCredential]::new('fixture',(ConvertTo-SecureString 'synthetic-offline-only' -AsPlainText -Force))
$cases=@('unallocated','missing-reference','missing-pool','reversed-pool','exhausted','below-start','invalid-number','read-denied','healthy','prefetched','last-free-rid')
foreach($case in $cases) {
    $script:scenario=$case;$script:attempt=0;$script:closed=0;$script:delays=0;$script:ridReads=0
    $session=Wait-LabDirectory ([pscustomobject]@{name='owned-dc'}) $credential
    $expected=if($case -in @('healthy','prefetched','last-free-rid')){1}else{2}
    if($script:attempt -ne $expected -or $session.attempt -ne $expected -or $script:closed -ne ($expected-1) -or $script:delays -ne ($expected-1) -or $script:ridReads -lt 1){throw "RID readiness regression: $case accepted attempt $script:attempt, expected $expected."}
}
Write-Output "Directory readiness: $($cases.Count) cases passed."
