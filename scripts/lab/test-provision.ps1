#Requires -Version 5.1
# Offline: actual media state machine, fake BITS/mounting/Hyper-V boundaries.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'media.ps1')
$imageInspector = ${function:Get-LabMediaImage}
$testRoot = [IO.Path]::GetFullPath((Join-Path $env:TEMP ('ad-sdk-bootstrap-' + [guid]::NewGuid().ToString('N'))))
$null = New-Item -ItemType Directory -Path $testRoot
$script:job = $null
$script:starts = 0
$script:completions = 0
$script:resumes = 0
$script:nextState = 'Transferred'
$script:contents = 'valid'
$script:mounts = 0
$script:dismounts = 0
$script:attached = $false
$script:imageVersion = '2025'
$script:imageArchitecture = 9

function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Expect-Failure([scriptblock]$Run, [string]$Pattern) {
    $caught = $null
    try { & $Run | Out-Null } catch { $caught = $_ }
    Assert ($null -ne $caught -and $caught.Exception.Message -like "*$Pattern*") "Expected failure: $Pattern; got: $caught"
}
function Import-Module($Name) { Assert ($Name -eq 'BitsTransfer') 'Unexpected module import.' }
function Start-BitsTransfer($Source, $Destination, $DisplayName, $TransferType, [switch]$Asynchronous) {
    $script:starts++
    $script:job = [pscustomobject]@{
        JobId=[guid]::NewGuid(); DisplayName=$DisplayName; JobState=$script:nextState; ErrorCode=-1
        FileList=@([pscustomobject]@{RemoteName=$Source; LocalName=$Destination})
    }
    return $script:job
}
function Get-BitsTransfer($JobId, $ErrorAction) {
    if ($JobId) { Assert ($JobId -eq $script:job.JobId) 'Queried another BITS job.' }
    return $script:job
}
function Resume-BitsTransfer($BitsJob, [switch]$Asynchronous) {
    Assert ($BitsJob.JobId -eq $script:job.JobId) 'Resumed another BITS job.'
    $script:resumes++
    $script:job.JobState = 'Transferred'
}
function Complete-BitsTransfer($BitsJob) {
    Assert ($BitsJob.JobId -eq $script:job.JobId) 'Completed another BITS job.'
    $script:completions++
    Set-Content -LiteralPath $BitsJob.FileList[0].LocalName -Value $script:contents
    $script:job = $null
}
function Get-LabMediaImage($Path, $ServerVersion, $ImageIndex, $ExpectedSHA256) {
    Assert ((Get-Content -LiteralPath $Path -Raw).Trim() -eq 'valid') 'Invalid image.'
    return [pscustomobject]@{path=$Path; sha256='observed'; image_index=$ImageIndex; image_name="Windows Server $ServerVersion Standard"}
}

try {
    $cache = Join-Path $testRoot 'cache'
    $image = Get-LabMedia -StorageRoot $cache
    Assert ($script:starts -eq 1 -and $script:completions -eq 1) 'Missing ISO was not downloaded once.'
    Assert (Test-Path -LiteralPath $image.path) 'Validated ISO was not published.'
    Assert (-not (Test-Path -LiteralPath ($image.path + '.transfer.json'))) 'Completed transfer state was retained.'
    $null = Get-LabMedia -StorageRoot $cache
    Assert ($script:starts -eq 1) 'Cached ISO was downloaded again.'
    Set-Content -LiteralPath $image.path -Value 'invalid'
    Expect-Failure { Get-LabMedia -StorageRoot $cache } 'Invalid image'
    Assert ($script:starts -eq 1) 'Invalid cached media was silently replaced.'
    $outside = Join-Path $testRoot 'provided.iso'
    Set-Content -LiteralPath $outside -Value 'valid'
    $explicit = Get-LabMedia -StorageRoot (Join-Path $testRoot 'unused') -IsoPath $outside
    Assert ($explicit.path -eq $outside -and -not (Test-Path (Join-Path $testRoot 'unused'))) 'Explicit ISO created cache state.'
    Expect-Failure { Assert-MediaPath (Join-Path $testRoot 'escaped.iso') (Join-Path $cache 'isos') } 'outside the ISO directory'
    Write-Output 'missing/cached/invalid/explicit media and containment: passed'

    $retry = Join-Path $testRoot 'retry'
    $script:nextState = 'Error'
    Expect-Failure { Get-LabMedia -StorageRoot $retry } 'BITS download failed'
    $beforeRetry = $script:starts
    $savedRemote = $script:job.FileList[0].RemoteName
    $script:job.FileList[0].RemoteName = 'https://example.invalid/foreign.iso'
    Expect-Failure { Get-LabMedia -StorageRoot $retry } 'ownership does not match'
    Assert ($script:resumes -eq 0 -and $script:starts -eq $beforeRetry) 'Foreign transfer was changed.'
    $script:job.FileList[0].RemoteName = $savedRemote
    $null = Get-LabMedia -StorageRoot $retry
    Assert ($script:starts -eq $beforeRetry -and $script:resumes -eq 1) 'Recorded failed job was not resumed.'
    $script:nextState = 'Transferred'
    $script:contents = 'invalid'
    $invalid = Join-Path $testRoot 'invalid-download'
    Expect-Failure { Get-LabMedia -StorageRoot $invalid } 'Invalid image'
    Assert (-not (Test-Path (Join-Path $invalid 'isos\WindowsServer2025-en-us.iso'))) 'Invalid download was published.'
    Assert (@(Get-ChildItem (Join-Path $invalid 'isos') -Filter '*.partial.iso').Count -eq 1) 'Failed media was not retained.'
    $script:contents = 'valid'
    Write-Output 'failed download/resume/foreign job/invalid staging: passed'

    # Exercise the actual image validator, including detach-on-failure.
    function Get-DiskImage($ImagePath) { return [pscustomobject]@{Attached=$script:attached} }
    function Mount-DiskImage($ImagePath, $StorageType, [switch]$PassThru) { $script:mounts++; return [pscustomobject]@{Attached=$true} }
    function Get-Volume { process { return [pscustomobject]@{DriveLetter='Z'} } }
    function Get-WindowsImage($ImagePath, $Index) { return [pscustomobject]@{ImageName="Windows Server $script:imageVersion Standard"; Architecture=$script:imageArchitecture; Version=[version]'10.0.1.0'} }
    function Dismount-DiskImage($ImagePath) { $script:dismounts++ }
    $actualHash = (Get-FileHash -LiteralPath $outside -Algorithm SHA256).Hash
    $null = & $imageInspector $outside '2025' 1 $actualHash
    Assert ($script:mounts -eq 1 -and $script:dismounts -eq 1) 'ISO mount ownership was not balanced.'
    Expect-Failure { & $imageInspector $outside '2025' 1 ('0' * 64) } 'SHA-256'
    Assert ($script:mounts -eq 1) 'Hash mismatch mounted the image.'
    $script:imageVersion = '2019'
    Expect-Failure { & $imageInspector $outside '2025' 1 '' } 'matching the selected profile'
    Assert ($script:dismounts -eq 2) 'Wrong version leaked a mount.'
    $script:imageVersion = '2025'
    $script:imageArchitecture = 12
    Expect-Failure { & $imageInspector $outside '2025' 1 '' } 'amd64'
    $script:imageArchitecture = 9
    $script:attached = $true
    $detachCount = $script:dismounts
    $null = & $imageInspector $outside '2025' 1 ''
    Assert ($script:dismounts -eq $detachCount) 'Pre-existing ISO mount was detached.'
    Write-Output 'checksum/version/architecture/mount ownership: passed'

    # Execute the real orchestration script in an isolated directory with fake
    # boundaries. Only its elevation requirement is removed for offline CI.
    $orchestration = Join-Path $testRoot 'orchestration'
    $null = New-Item -ItemType Directory -Path $orchestration
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'provision.ps1') -Raw
    $source.Replace('#Requires -RunAsAdministrator', '# Offline boundary test') | Set-Content (Join-Path $orchestration 'provision.ps1')
    @'
function Get-LabMedia($ServerVersion,$StorageRoot,$ImageIndex,$IsoPath,$ExpectedSHA256) {
    Add-Content (Join-Path $StorageRoot 'calls') "media|$ServerVersion|$ImageIndex|$ExpectedSHA256"
    if(Test-Path (Join-Path $StorageRoot 'fail-media')) {throw 'injected media failure'}
    return [pscustomobject]@{path=(Join-Path $StorageRoot 'media.iso')}
}
'@ | Set-Content (Join-Path $orchestration 'media.ps1')
    @'
param($Action,$ServerVersion,$StorageRoot,$IsoPath,$ImageIndex)
Add-Content (Join-Path $StorageRoot 'calls') "$Action|$ServerVersion|$ImageIndex|$IsoPath"
if(Test-Path (Join-Path $StorageRoot "fail-$Action")) {throw "injected $Action failure"}
'@ | Set-Content (Join-Path $orchestration 'lab.ps1')
    foreach ($case in @('success','MediaOnly','media','New','Configure','Reference')) {
        $caseRoot = Join-Path $orchestration $case
        $null = New-Item -ItemType Directory -Path $caseRoot
        if ($case -notin @('success','MediaOnly')) { Set-Content (Join-Path $caseRoot "fail-$case") 'fail' }
        $options = @{ServerVersion='2019';StorageRoot=$caseRoot;ImageIndex=2;ExpectedSHA256=('a'*64);MediaOnly=($case -eq 'MediaOnly')}
        $run = { & (Join-Path $orchestration 'provision.ps1') @options }
        if ($case -in @('success','MediaOnly')) { & $run | Out-Null } else { Expect-Failure $run "injected $case failure" }
        $calls = @(Get-Content (Join-Path $caseRoot 'calls'))
        $expectedCount = switch ($case) {'MediaOnly'{1} 'media'{1} 'New'{2} 'Configure'{3} default{4}}
        Assert ($calls.Count -eq $expectedCount) "Actions continued after $case."
        Assert ($calls[0] -eq ('media|2019|2|' + ('a'*64))) 'Media options were lost.'
        $actions = @('New','Configure','Reference')
        for ($i=1;$i -lt $calls.Count;$i++) {
            Assert ($calls[$i] -eq ($actions[$i-1] + '|2019|2|' + (Join-Path $caseRoot 'media.iso'))) 'Lab action order/options differ.'
        }
    }
    Write-Output 'provision order/options/media-only/fail-fast at every stage: passed'
} finally {
    # The directory is uniquely created above. Check the exact resolved boundary
    # and every descendant before recursively removing only this test fixture.
    $temporaryRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    if (-not $testRoot.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($testRoot) -notmatch '^ad-sdk-bootstrap-[a-f0-9]{32}$') { throw 'Unexpected test cleanup path.' }
    foreach ($item in @(Get-Item -LiteralPath $testRoot) + @(Get-ChildItem -LiteralPath $testRoot -Recurse -Force)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in test cleanup.' }
    }
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
