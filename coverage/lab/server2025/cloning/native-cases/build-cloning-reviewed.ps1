#Requires -Version 5.1
param([Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repository=Join-Path $PSScriptRoot 'work-dc-cloning'
$run='cloning-reviewed-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$directory=Join-Path 'H:\ad-sdk-lab\qualifications' $run
$source=Join-Path $directory 'source'
foreach($path in @($repository,$directory)) {
    $full=[IO.Path]::GetFullPath($path)
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Build path traverses a reparse point.' }
    }
}
if(-not ([IO.Path]::GetFullPath($directory)).StartsWith('H:\ad-sdk-lab\qualifications\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $directory)) { throw 'Unexpected or existing build directory.' }
$kind=git -C $repository cat-file -t $SourceCommit
if($LASTEXITCODE -ne 0 -or $kind -cne 'commit') { throw 'Reviewed source commit is unavailable.' }
# Archive the exact reviewed Git object. Working-tree edits, including a
# concurrently developed test-only checkpoint, never enter this build.
$null=New-Item -ItemType Directory -Path $directory
$archive=Join-Path $directory 'source.zip'
git -C $repository archive --format=zip --output=$archive $SourceCommit
if($LASTEXITCODE -ne 0) { throw 'Source archive failed.' }
Expand-Archive -LiteralPath $archive -DestinationPath $source
$executable=Join-Path $directory 'dccloning.exe'
$testExecutable=Join-Path $directory 'dccloning.test.exe'
$savedEnvironment=@{}
foreach($name in @('GOOS','GOARCH','CGO_ENABLED','GOWORK')) { $savedEnvironment[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location $source
try {
    $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0';$env:GOWORK='off'
    $toolchain=go version
    if($LASTEXITCODE -ne 0) { throw 'Go toolchain unavailable.' }
    go build -mod=readonly -trimpath -buildvcs=false -o $executable ./examples/dccloning *> (Join-Path $directory 'build.log')
    if($LASTEXITCODE -ne 0) { throw 'Native CLI build failed; retain build.log.' }
    go test -c -mod=readonly -trimpath -buildvcs=false -o $testExecutable ./dccloning *> (Join-Path $directory 'test-build.log')
    if($LASTEXITCODE -ne 0) { throw 'Native test build failed; retain test-build.log.' }
} finally {
    Pop-Location
    foreach($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name,$savedEnvironment[$name],'Process') }
}
$manifest=[ordered]@{
    run=$run;directory=$directory;source_commit=$SourceCommit;source_archive_sha256=(Get-FileHash -LiteralPath $archive).Hash
    native_executable=$executable;native_executable_sha256=(Get-FileHash -LiteralPath $executable).Hash
    test_executable=$testExecutable;test_executable_sha256=(Get-FileHash -LiteralPath $testExecutable).Hash
    toolchain=$toolchain;status='built';guest_execution=$null
}
$json=$manifest | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $directory 'build.json'),$json,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'cloning-native-reviewed-run.json'),$json,[Text.UTF8Encoding]::new($false))
$json
