#Requires -Version 5.1
# Functions only. Preserve the module's package layout in retained build inputs.

function Assert-SDKSnapshotPath([string]$Path,[bool]$MustExist=$true) {
    $full=[IO.Path]::GetFullPath($Path)
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) {throw 'Required snapshot path does not exist.'}
    $cursor=$full
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Snapshot paths must not traverse reparse points.'}
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}

function Assert-SDKSnapshotRelativeName([string]$Name) {
    if ($Name -notmatch '\A[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\z') {throw 'Invalid relative snapshot name.'}
    foreach ($part in $Name.Split('/')) {
        if ($part -in @('.','..') -or $part.EndsWith('.')) {throw 'Snapshot names must not contain traversal or ambiguous path segments.'}
    }
}

function Test-SDKSnapshotSourceName([string]$Name) {
    Assert-SDKSnapshotRelativeName $Name
    return $Name -in @('go.mod','go.sum','coverage/inventory.json','coverage/scenario-requirements.json') -or
        $Name.EndsWith('.go',[StringComparison]::Ordinal) -or $Name -match '(?:\A|/)testdata/'
}

function Get-SDKSnapshotFiles([string]$Directory) {
    $root=Assert-SDKSnapshotPath $Directory
    # Walk one directory at a time, rejecting reparse points before descending.
    foreach ($item in (Get-ChildItem -LiteralPath $root -Force | Sort-Object Name)) {
        $null=Assert-SDKSnapshotPath $item.FullName
        if ($item.PSIsContainer) {Get-SDKSnapshotFiles $item.FullName}
        else {$item}
    }
}

function Get-SDKSnapshotHashes([string]$Directory) {
    $root=(Assert-SDKSnapshotPath $Directory).TrimEnd('\','/')
    $hashes=[ordered]@{}
    foreach ($file in (Get-SDKSnapshotFiles $root | Sort-Object FullName)) {
        $name=$file.FullName.Substring($root.Length+1).Replace('\','/')
        Assert-SDKSnapshotRelativeName $name
        $hashes[$name]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    return $hashes
}

function Copy-SDKSourceSnapshot([string]$SourceRoot,[string]$SnapshotRoot) {
    $source=(Assert-SDKSnapshotPath $SourceRoot).TrimEnd('\','/')
    $snapshot=(Assert-SDKSnapshotPath $SnapshotRoot).TrimEnd('\','/')
    $files=@(Get-Item -LiteralPath (Join-Path $source 'go.mod'),(Join-Path $source 'go.sum'))
    foreach ($name in @('activedirectory','conditions','dccloning','internal','testdata')) {
        $directory=Join-Path $source $name
        if (Test-Path -LiteralPath $directory) {
            $files+=@(Get-SDKSnapshotFiles $directory | Where-Object {
                $relative=$_.FullName.Substring($source.Length+1).Replace('\','/')
                Test-SDKSnapshotSourceName $relative
            })
        }
    }
    foreach ($name in @('coverage/inventory.json','coverage/scenario-requirements.json')) {
        $path=Join-Path $source $name
        if (Test-Path -LiteralPath $path) {$files+=Get-Item -LiteralPath $path}
    }
    # Validate the complete input and destination list before copying anything.
    foreach ($file in $files) {
        $null=Assert-SDKSnapshotPath $file.FullName
        $name=$file.FullName.Substring($source.Length+1).Replace('\','/')
        Assert-SDKSnapshotRelativeName $name
        $destination=Assert-SDKSnapshotPath (Join-Path $snapshot $name) $false
        if (Test-Path -LiteralPath $destination) {throw 'Refusing to overwrite a retained source snapshot.'}
    }
    foreach ($file in $files) {
        $name=$file.FullName.Substring($source.Length+1).Replace('\','/')
        $destination=Join-Path $snapshot $name
        $parent=Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $parent)) {$null=New-Item -ItemType Directory -Path $parent -Force}
        Copy-Item -LiteralPath $file.FullName -Destination $destination
    }
}
