#Requires -Version 5.1
# PREPARE ONLY: readonly guest inventory. The reviewed host owns the deadline.
# No config generation, prerequisite changes, child processes, or guest writes.
param([Parameter(Mandatory)][string]$Run)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Read-InventoryItem([string]$Path) {
    try { return Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch { if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $null };throw }
}
function Assert-InventoryPath([string]$Path) {
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.Contains('..') -or $Path.Substring(2).Contains(':')) { throw 'Inventory accepts only explicit local drive paths.' }
    $full=[IO.Path]::GetFullPath($Path)
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        $item=Read-InventoryItem $cursor
        if($null -ne $item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Inventory path traverses a reparse point.' }
    }
    return $full
}
function Read-InventoryFile([string]$Path) {
    $full=Assert-InventoryPath $Path;$item=Read-InventoryItem $full
    if($null -eq $item) { return [ordered]@{path=$full;exists=$false;length=$null;sha256=$null;sddl=$null} }
    if($item.PSIsContainer -or $item.Length -gt 8388608) { throw 'Inventory file type or size differs.' }
    return [ordered]@{path=$full;exists=$true;length=$item.Length;sha256=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash;sddl=(Get-Acl -LiteralPath $full -ErrorAction Stop).Sddl}
}
function Inventory-SID($Value) {
    if($Value -is [Security.Principal.SecurityIdentifier]) { return $Value.Value }
    if($Value -is [byte[]]) { return ([Security.Principal.SecurityIdentifier]::new($Value,0)).Value }
    if($Value -is [string]) { return ([Security.Principal.SecurityIdentifier]::new($Value)).Value }
    throw 'Unrecognized SID representation; membership is unknown.'
}
function Get-InventoryRemovable {
    return @([IO.DriveInfo]::GetDrives() | Where-Object DriveType -eq ([IO.DriveType]::Removable) | Sort-Object Name | ForEach-Object { [ordered]@{root=$_.Name;ready=$_.IsReady} })
}
function Read-CloneConfigOnlineInventory([string]$Run) {
    $record=[ordered]@{schema_version=1;run=$Run;computer=$env:COMPUTERNAME;collected_utc=[DateTime]::UtcNow.ToString('o');powershell=$PSVersionTable.PSVersion.ToString();readonly=$true;completed=$false;phase='identity';directory=$null;files=$null;applications=$null;versions=$null;error=$null}
    try {
        if($Run -cne 'clone-config-reviewed-20261112T215735Z-b4707e3f-online-inventory-v1' -or $env:COMPUTERNAME -cne 'ADSDK25DC1') { throw 'Inventory run or guest identity differs.' }
        Import-Module ActiveDirectory -ErrorAction Stop
        $server='ADSDK25DC1.ad.sdk.test';$sourceDN='CN=ADSDK25DC1,OU=Domain Controllers,DC=ad,DC=sdk,DC=test'
        $root=Get-ADRootDSE -Server $server -ErrorAction Stop
        $domain=Get-ADDomain -Server $server -ErrorAction Stop
        $dc=Get-ADDomainController -Identity $server -Server $server -ErrorAction Stop
        if($root.dnsHostName -ine $server -or $root.defaultNamingContext -cne 'DC=ad,DC=sdk,DC=test' -or $domain.DNSRoot -cne 'ad.sdk.test' -or $domain.PDCEmulator -ine $server -or $dc.ComputerObjectDN -cne $sourceDN) { throw 'Source, domain, or PDC identity differs from the existing probe.' }
        $domainSID=Inventory-SID $domain.DomainSID;$groupSID=$domainSID+'-522'
        $group=Get-ADGroup -Identity $groupSID -Properties member -Server $server -ErrorAction Stop
        $source=Get-ADComputer -Identity $sourceDN -Properties tokenGroups,memberOf -Server $server -ErrorAction Stop
        $groupMembers=@($group.member | Sort-Object);$tokenGroups=@($source.tokenGroups | ForEach-Object { Inventory-SID $_ } | Sort-Object)
        if($groupMembers.Count -gt 1024 -or $tokenGroups.Count -eq 0 -or $tokenGroups.Count -gt 1024 -or (Inventory-SID $group.SID) -cne $groupSID -or $source.DistinguishedName -cne $sourceDN) { throw 'Membership inventory is missing, excessive, or inconsistent.' }
        $memberships=@(Get-ADPrincipalGroupMembership -Identity $sourceDN -Server $server -ErrorAction Stop | ForEach-Object { [ordered]@{dn=$_.DistinguishedName;sid=(Inventory-SID $_.SID)} })
        if($memberships.Count -gt 1024) { throw 'Reference membership count exceeds its bound.' }
        $record.directory=[ordered]@{server=$server;domain_dn=$domain.DistinguishedName;domain_sid=$domainSID;pdc=$domain.PDCEmulator;source_dn=$sourceDN;source_guid=$source.ObjectGUID.ToString();source_sid=(Inventory-SID $source.SID);source_direct_groups=@($source.memberOf | Sort-Object);source_token_groups=$tokenGroups;source_reference_groups=$memberships;source_roles=@($dc.OperationMasterRoles | ForEach-Object {$_.ToString()});source_read_only=[bool]$dc.IsReadOnly;group_dn=$group.DistinguishedName;group_guid=$group.ObjectGUID.ToString();group_sid=$groupSID;group_members=$groupMembers;direct_member=($sourceDN -iin $groupMembers);token_member=($groupSID -cin $tokenGroups);reference_member=($groupSID -cin @($memberships | ForEach-Object {$_.sid}));dc_functionality=$root.domainControllerFunctionality}
        $record.phase='files'
        $parameters=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop
        $dsa=Assert-InventoryPath ([string]$parameters.'DSA Working Directory');$ntds=Assert-InventoryPath (Join-Path $env:windir 'NTDS')
        $allow=$null;if($parameters.PSObject.Properties['AllowListFolder'] -and $parameters.AllowListFolder) { $allow=Assert-InventoryPath ([string]$parameters.AllowListFolder) }
        $removable=@(Get-InventoryRemovable)
        if($removable.Count -gt 26) { throw 'Removable-drive inventory exceeds its bound.' }
        $configDirectories=@($dsa,$ntds | Select-Object -Unique);$customDirectories=@(@($allow,$dsa,$ntds) | Where-Object {$_} | Select-Object -Unique)
        # Do not guess whether removable media is writable. Record it and stop
        # before touching that medium; a separate supported-volume probe is needed.
        $record.files=[ordered]@{dsa_directory=$dsa;windows_ntds=$ntds;allow_list_folder=$allow;removable=$removable;directories=@();default_list=$null;custom_lists=@();clone_configs=@()}
        if($removable.Count) { throw 'Removable media requires a separate readonly writability observation.' }
        foreach($directory in @(@($configDirectories)+@($customDirectories) | Select-Object -Unique)) {
            $item=Read-InventoryItem $directory
            if($null -eq $item -or -not $item.PSIsContainer) { throw 'Configured candidate directory does not exist.' }
            $record.files.directories+=@([ordered]@{path=$directory;attributes=$item.Attributes.ToString();sddl=(Get-Acl -LiteralPath $directory -ErrorAction Stop).Sddl})
        }
        $record.files.default_list=Read-InventoryFile (Join-Path $env:windir 'System32\DefaultDCCloneAllowList.xml')
        if(-not $record.files.default_list.exists) { throw 'Default inclusion file is absent.' }
        foreach($directory in $customDirectories) { $record.files.custom_lists+=@(Read-InventoryFile (Join-Path $directory 'CustomDCCloneAllowList.xml')) }
        foreach($directory in $configDirectories) { $record.files.clone_configs+=@(Read-InventoryFile (Join-Path $directory 'DCCloneConfig.xml')) }
        $record.phase='applications'
        $command=Get-Command Get-ADDCCloningExcludedApplicationList -ErrorAction Stop;$assembly=$command.ImplementingType.Assembly.Location
        $os=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $record.versions=[ordered]@{os_full_build=([string]$os.CurrentBuildNumber+'.'+[string]$os.UBR);module_version=$command.Module.Version.ToString();assembly_version=[Diagnostics.FileVersionInfo]::GetVersionInfo($assembly).FileVersion;assembly_sha256=(Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash}
        $referenceWarnings=@();$referenceInformation=@()
        $entries=@(Get-ADDCCloningExcludedApplicationList -ErrorAction Stop -WarningVariable referenceWarnings -InformationVariable referenceInformation | ForEach-Object { [ordered]@{name=[string]$_.Name;type=[string]$_.Type} })
        if($entries.Count -gt 1024) { throw 'Reference exclusions exceed the inventory bound.' }
        $record.applications=[ordered]@{reference_entries=$entries;warnings=@($referenceWarnings | ForEach-Object {$_.ToString()});information=@($referenceInformation | ForEach-Object {$_.ToString()});vendor_approval_claimed=$false}
        $record.completed=$true;$record.phase='complete'
    } catch { $record.error=[ordered]@{message=$_.Exception.Message;type=$_.Exception.GetType().FullName;fully_qualified_error_id=$_.FullyQualifiedErrorId;category=$_.CategoryInfo.Category.ToString()} }
    return $record
}
$record=Read-CloneConfigOnlineInventory $Run
$payload=$record | ConvertTo-Json -Depth 16 -Compress
if([Text.Encoding]::UTF8.GetByteCount($payload) -gt 2097152) { throw 'Inventory result exceeds its 2MiB transport bound.' }
$payload
