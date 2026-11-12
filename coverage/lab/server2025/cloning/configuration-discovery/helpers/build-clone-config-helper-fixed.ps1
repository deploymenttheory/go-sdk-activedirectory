#Requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$buildRoot='H:\ad-sdk-lab\qualifications\clone-config-reviewed-20261112T215735Z-b4707e3f'
$source=Join-Path $buildRoot 'source'
$manifest=Get-Content -LiteralPath (Join-Path $buildRoot 'build.json') -Raw | ConvertFrom-Json
if($manifest.source_commit -cne 'c72c7b0a4a785f177a70f26729b7d9ffff140a46' -or
    (Get-FileHash -LiteralPath $manifest.source_archive).Hash -cne '79728F456A61AF3F646931DA1A128E072E782D26B50A0453B1D3D6C49BFA9DEE') { throw 'Unexpected source archive.' }
$destination=Join-Path $buildRoot 'helper-v3'
for($cursor=$destination;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
    if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked build ancestor.' }
}
if(Test-Path -LiteralPath $destination) { throw 'Existing build is immutable.' }
$inputs=[ordered]@{
    'clone-config-helper.go'='F4FAA4E4A5D2D8F18333336145DBFE0BFA2A30324BB6DCE876BA94DAB37528D1'
    'clone-config-helper_test.go'='AFB460A86DF41804BE206DB8ED8906231BD33EF7A67EED0EF9FC48904B4AE512'
    'clone-locator-diagnostic.go'='ABA7313F82F314D011F499147CC674D9F9CB537894394C8B57618010A945229E'
}
foreach($name in $inputs.Keys) { if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash -cne $inputs[$name]) { throw 'Reviewed helper source differs.' } }
[void][IO.Directory]::CreateDirectory($destination)
foreach($name in $inputs.Keys) { [IO.File]::WriteAllBytes((Join-Path $destination $name),[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name))) }
$helper=Join-Path $destination 'clone-config-helper.exe'
$locator=Join-Path $destination 'clone-locator-diagnostic.exe'
$saved=@{}
foreach($name in @('GOOS','GOARCH','CGO_ENABLED','GOWORK')) { $saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location $source
try {
    $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0';$env:GOWORK='off'
    go test -count=1 -v -mod=readonly -buildvcs=false (Join-Path $destination 'clone-config-helper.go') (Join-Path $destination 'clone-config-helper_test.go') *> (Join-Path $destination 'helper-tests.log')
    if($LASTEXITCODE -ne 0) { throw 'Helper tests failed.' }
    go build -mod=readonly -trimpath -buildvcs=false -o $helper (Join-Path $destination 'clone-config-helper.go') *> (Join-Path $destination 'helper-build.log')
    if($LASTEXITCODE -ne 0) { throw 'Helper build failed.' }
    go build -mod=readonly -trimpath -buildvcs=false -o $locator (Join-Path $destination 'clone-locator-diagnostic.go') *> (Join-Path $destination 'locator-build.log')
    if($LASTEXITCODE -ne 0) { throw 'Locator build failed.' }
} finally {
    Pop-Location
    foreach($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
}
$record=[ordered]@{source_commit=$manifest.source_commit;source_archive_sha256=$manifest.source_archive_sha256;directory=$destination;source_hashes=$inputs;helper_executable_sha256=(Get-FileHash -LiteralPath $helper).Hash;locator_executable_sha256=(Get-FileHash -LiteralPath $locator).Hash;builder_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash;built_utc=[DateTime]::UtcNow.ToString('o');guest_execution=$null}
$json=$record|ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $destination 'build.json'),$json,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'clone-config-helper-v3-build.json'),$json,[Text.UTF8Encoding]::new($false))
$json
