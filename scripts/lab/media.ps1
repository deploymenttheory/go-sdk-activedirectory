#Requires -Version 5.1
# Dot-sourced by provision.ps1. No download or VM action occurs on import.

function Resolve-LabInputPath([string]$Path) {
    $provider = $null
    $drive = $null
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem') { throw 'Lab storage and ISO paths must use the filesystem provider.' }
    return [IO.Path]::GetFullPath($resolved)
}

function Assert-MediaPath([string]$Path, [string]$MediaRoot) {
    $resolved = [IO.Path]::GetFullPath($Path)
    $boundary = [IO.Path]::GetFullPath($MediaRoot).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Media path is outside the ISO directory: $resolved"
    }
    $parent = $resolved
    while ($parent) {
        if ((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Reparse point in media path: $parent"
        }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    return $resolved
}

function Get-LabMediaImage([string]$Path, [string]$ServerVersion, [int]$ImageIndex, [string]$ExpectedSHA256) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "ISO does not exist: $Path" }
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($ExpectedSHA256 -and $hash -ne $ExpectedSHA256) { throw 'ISO SHA-256 does not match the expected value.' }
    $disk = Get-DiskImage -ImagePath $Path
    $wasAttached = $disk.Attached
    try {
        if (-not $wasAttached) { $disk = Mount-DiskImage -ImagePath $Path -StorageType ISO -PassThru }
        $volumes = @($disk | Get-Volume | Where-Object DriveLetter)
        if ($volumes.Count -ne 1) { throw 'Expected one readable ISO volume.' }
        $wim = '{0}:\sources\install.wim' -f $volumes[0].DriveLetter
        $selected = Get-WindowsImage -ImagePath $wim -Index $ImageIndex
        if ($selected.ImageName -notlike "Windows Server $ServerVersion *" -or $selected.Architecture -ne 9) {
            throw 'The ISO image must be amd64 Windows Server matching the selected profile.'
        }
        return [pscustomobject][ordered]@{
            path=$Path; sha256=$hash; image_index=$ImageIndex; image_name=$selected.ImageName
            image_version=$selected.Version.ToString(); checked_utc=[DateTime]::UtcNow.ToString('o')
        }
    } finally {
        if (-not $wasAttached) { Dismount-DiskImage -ImagePath $Path | Out-Null }
    }
}

function Save-MediaTransfer($State, [string]$Path, [string]$MediaRoot) {
    $temporary = Assert-MediaPath ($Path + '.tmp') $MediaRoot
    $null = Assert-MediaPath $Path $MediaRoot
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Receive-LabMedia($Transfer, [string]$StatePath, [string]$MediaRoot) {
    Import-Module BitsTransfer
    $destination = Assert-MediaPath $Transfer.destination $MediaRoot
    if ($Transfer.job_id) {
        $jobs = @(Get-BitsTransfer -ErrorAction Stop | Where-Object { $_.JobId.ToString() -eq $Transfer.job_id })
        if ($jobs.Count -ne 1) {
            # Complete-BitsTransfer can finish just before the process stops.
            # The caller must still validate the image before publishing it.
            if (Test-Path -LiteralPath $destination -PathType Leaf) { return }
            throw 'Recorded BITS job is absent; inspect the retained transfer manifest before retrying.'
        }
        $job = $jobs[0]
        $files = @($job.FileList)
        if ($job.DisplayName -ne $Transfer.name -or $files.Count -ne 1 -or
            $files[0].RemoteName -cne $Transfer.source -or $files[0].LocalName -ne $destination) {
            throw 'BITS job ownership does not match the media manifest.'
        }
        if ($job.JobState -in @('Suspended', 'Error', 'TransientError')) {
            Resume-BitsTransfer -BitsJob $job -Asynchronous | Out-Null
        }
    } else {
        if (Test-Path -LiteralPath $destination) { throw 'Untracked download file exists; inspect it before retrying.' }
        $job = Start-BitsTransfer -Source $Transfer.source -Destination $destination -DisplayName $Transfer.name -TransferType Download -Asynchronous
        $Transfer.job_id = $job.JobId.ToString()
        Save-MediaTransfer $Transfer $StatePath $MediaRoot
    }
    $deadline = [DateTime]::UtcNow.AddHours(12)
    while ($true) {
        $job = Get-BitsTransfer -JobId ([guid]$Transfer.job_id) -ErrorAction Stop
        switch ([string]$job.JobState) {
            'Transferred' { Complete-BitsTransfer -BitsJob $job; return }
            'Error' { throw "BITS download failed with code $($job.ErrorCode). Rerun provision.ps1 to retry the recorded job." }
            'Cancelled' { throw 'The recorded media transfer was cancelled.' }
            'Acknowledged' { throw 'The recorded media transfer was completed elsewhere; rerun to validate its output.' }
            'Suspended' { throw 'The media transfer was suspended; rerun provision.ps1 to resume it.' }
        }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Download wait reached 12 hours; the recorded BITS job is retained for the next run.' }
        Write-Progress -Activity 'Downloading Windows Server evaluation ISO' -Status "$($job.JobState): $($job.BytesTransferred) / $($job.BytesTotal) bytes"
        Start-Sleep -Seconds 5
    }
}

function Get-LabMedia {
    [CmdletBinding()]
    param(
        [ValidateSet('2016', '2019', '2022', '2025')][string]$ServerVersion = '2025',
        [string]$StorageRoot = 'H:\ad-sdk-lab',
        [string]$IsoPath,
        [ValidateRange(1, 20)][int]$ImageIndex = 1,
        [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSHA256
    )
    # Explicit media is read-only input: do not download or create a cache.
    if ($IsoPath) {
        return Get-LabMediaImage (Resolve-LabInputPath $IsoPath) $ServerVersion $ImageIndex $ExpectedSHA256
    }
    $mediaRoot = Join-Path (Resolve-LabInputPath $StorageRoot) 'isos'
    $path = Assert-MediaPath (Join-Path $mediaRoot "WindowsServer$ServerVersion-en-us.iso") $mediaRoot
    $statePath = Assert-MediaPath ($path + '.transfer.json') $mediaRoot
    $metadataPath = Assert-MediaPath ($path + '.media.json') $mediaRoot
    $sources = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'media.json') -Raw | ConvertFrom-Json
    $source = $sources.$ServerVersion
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $lockName = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant()))).Replace('-', '') } finally { $hasher.Dispose() }
    $mutex = [Threading.Mutex]::new($false, "Global\GoSDKActiveDirectoryMedia_$lockName")
    $held = $false
    try {
        try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Another process is preparing this ISO.' }
        $null = New-Item -ItemType Directory -Path $mediaRoot -Force
        if (Test-Path -LiteralPath $path) {
            Write-Host "Validating cached ISO: $path"
            $image = Get-LabMediaImage $path $ServerVersion $ImageIndex $ExpectedSHA256
        } else {
            if (Test-Path -LiteralPath $statePath) {
                $transfer = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
                $id = [guid]::ParseExact($transfer.id, 'D').ToString('D')
                $expectedDestination = Join-Path $mediaRoot "WindowsServer$ServerVersion-$id.partial.iso"
                if ($transfer.schema_version -ne 1 -or $transfer.version -ne $ServerVersion -or
                    $transfer.source -cne $source.source -or $transfer.destination -ne $expectedDestination -or
                    $transfer.name -ne "ADSDK-media-$ServerVersion-$id") {
                    throw 'Media transfer manifest does not match this profile/source.'
                }
            } else {
                $id = [guid]::NewGuid().ToString('D')
                $transfer = [pscustomobject][ordered]@{
                    schema_version=1; id=$id; version=$ServerVersion; source=$source.source
                    destination=(Join-Path $mediaRoot "WindowsServer$ServerVersion-$id.partial.iso")
                    name="ADSDK-media-$ServerVersion-$id"; job_id=''
                }
                Save-MediaTransfer $transfer $statePath $mediaRoot
            }
            Receive-LabMedia $transfer $statePath $mediaRoot
            $image = Get-LabMediaImage $transfer.destination $ServerVersion $ImageIndex $ExpectedSHA256
            # Only a complete, inspected image is promoted to the cached name.
            # No -Force: another file must never be silently overwritten.
            Move-Item -LiteralPath $transfer.destination -Destination $path
            $image.path = $path
            Remove-Item -LiteralPath $statePath
        }
        $image | Add-Member -NotePropertyName evaluation_download_page -NotePropertyValue $source.documentation
        $image | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
        return $image
    } finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
        Write-Progress -Activity 'Downloading Windows Server evaluation ISO' -Completed
    }
}
