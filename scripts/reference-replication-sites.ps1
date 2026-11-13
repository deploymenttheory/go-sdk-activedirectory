# Read-only collector for explicit existing fixtures; never provisions or moves.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Server,
    [string[]]$SiteDN = @(),
    [string[]]$SubnetDN = @(),
    [string[]]$ServerDN = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
function Observe([string]$Operation,[string]$Identity,[scriptblock]$Read) {
    $items = [Collections.Generic.List[object]]::new()
    try {
        & $Read | ForEach-Object { $items.Add($_) }
        return [ordered]@{ operation=$Operation; identity=$Identity; complete=$true; items=@($items.ToArray()); error=$null }
    } catch {
        return [ordered]@{ operation=$Operation; identity=$Identity; complete=$false; items=@($items.ToArray()); error=[ordered]@{type=$_.Exception.GetType().FullName;message=$_.Exception.Message;id=$_.FullyQualifiedErrorId} }
    }
}
function Values($Object,[string[]]$Names) {
    $result=[ordered]@{distinguished_name=[string]$Object.DistinguishedName;guid=[string]$Object.ObjectGUID}
    foreach($name in $Names){
        $property=$Object.PSObject.Properties[$name]
        if($null -eq $property){$result[$name]=$null}
        elseif($property.Value -is [byte[]]){$result[$name]=@([Convert]::ToBase64String($property.Value))}
        else{$result[$name]=@($property.Value | ForEach-Object { if($_ -is [byte[]]){[Convert]::ToBase64String($_)}else{[string]$_} })}
    }
    return $result
}
$root=Get-ADRootDSE -Server $Server -ErrorAction Stop
$records=@()
foreach($dn in $SiteDN){
    $records+=Observe 'site' $dn { Values (Get-ADReplicationSite -Server $Server -Identity $dn -Properties * -ErrorAction Stop) @('Name','Description','ManagedBy','Subnets','Servers','InterSiteTopologyGenerator','UniversalGroupCachingRefreshSite','AutomaticTopologyGenerationEnabled','AutomaticInterSiteTopologyGenerationEnabled','ScheduleHashingEnabled') }
    $records+=Observe 'settings' $dn {
        $object=Get-ADObject -Server $Server -Identity ('CN=NTDS Site Settings,'+$dn) -Properties options,schedule,interSiteTopologyGenerator,msDS-Preferred-GC-Site,uSNChanged -ErrorAction Stop
        Values $object @('options','schedule','interSiteTopologyGenerator','msDS-Preferred-GC-Site','uSNChanged')
    }
}
foreach($dn in $SubnetDN){$records+=Observe 'subnet' $dn { Values (Get-ADReplicationSubnet -Server $Server -Identity $dn -Properties * -ErrorAction Stop) @('Name','Site','Location','Description') }}
foreach($dn in $ServerDN){
    $records+=Observe 'server' $dn { Values (Get-ADObject -Server $Server -Identity $dn -Properties objectClass,dNSHostName,serverReference,uSNChanged -ErrorAction Stop) @('objectClass','dNSHostName','serverReference','uSNChanged') }
    $records+=Observe 'dsa' $dn { Values (Get-ADObject -Server $Server -Identity ('CN=NTDS Settings,'+$dn) -Properties objectClass,invocationId,options -ErrorAction Stop) @('objectClass','invocationId','options') }
}
$module=Get-Module ActiveDirectory
[ordered]@{schema_version=1;collected_utc=[DateTime]::UtcNow.ToString('o');server=$Server;module_version=[string]$module.Version;module_path=$module.Path;powershell_version=[string]$PSVersionTable.PSVersion;configuration=[string]$root.ConfigurationNamingContext;server_functionality=[string]$root.DomainControllerFunctionality;dns_host_name=[string]$root.DnsHostName;records=$records}|ConvertTo-Json -Depth 15
