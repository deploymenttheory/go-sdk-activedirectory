#Requires -Version 7.0

<#
.SYNOPSIS
Owns one isolated Linux client for direct portable SDK qualification.
.DESCRIPTION
Run from the Hyper-V host with approved access. New consumes an independently
verified Ubuntu cloud image and creates a Gen2 VM on an existing private lab
switch. Move restarts a running Linux VM and changes only its single NIC, so
neighbor and DNS caches cannot retain identities from an overlapping profile.
Inventory never authenticates to LDAP or writes directory data. Exec and Upload
control Linux through a pinned
SSH connection from the profile's Windows member, reached by PowerShell Direct.
The Go SSH bridge is lab orchestration, never part of the SDK/provider runtime.
Its public executable is cached on each owned member, checked by SHA256 before
every use, and staged in bounded chunks only when absent. ClearControlCache
removes that public cache separately; Exec never saves its private request.

Private keys and NoCloud seed material remain under StorageRoot/secrets on the
host. The SSH client key is passed to the bridge in memory, never a guest file.
Remove validates VM ID, notes, NIC, and paths before removing owned artifacts;
the downloaded image and independently captured public evidence are preserved.

The selected Windows profile must already be configured and its member running.
The script never starts Windows VMs or changes switch types. Upload verifies the
remote SHA256; Exec returns exit_code/stdout/stderr, which callers must inspect.
Exec accepts up to 64 KiB of exact InputBytes through SSH stdin. InputBytes is
cleared in place after the call, including failed calls. Input is never printed,
saved, or placed in process arguments; runtime JSON/Base64 copies are immutable
and have no guaranteed erasure. Remote programs control their own stdout/stderr.
Inventory is connectivity evidence, not authentication/transport qualification.

NoCloud: https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html
Network: https://docs.cloud-init.io/en/latest/reference/network-config-format-v2.html
SSH keys: https://docs.cloud-init.io/en/latest/reference/modules.html#ssh
.EXAMPLE
./portable-linux.ps1 New
./portable-linux.ps1 Inventory
Provision a fresh client, then verify its pinned identity and direct DC access.
.EXAMPLE
./portable-linux.ps1 Upload -LocalFile ./portabletls-linux-amd64 -RemoteName portabletls
./portable-linux.ps1 Exec -Command '/home/adsdk/acceptance/portabletls --help'
Copy a Linux test binary with digest verification, then execute it under Linux.
.EXAMPLE
./portable-linux.ps1 Move -ServerVersion 2022
./portable-linux.ps1 Inventory
Move the owned client to the existing private 2022 switch and verify the profile.
.EXAMPLE
./portable-linux.ps1 Remove
Independently verify the owned VM/disks/keys are removed; retain public evidence.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position=0)]
    [ValidateSet('New','Status','Start','Move','Inventory','Exec','Upload','ClearControlCache','Stop','Remove')][string]$Action,
    [ValidateSet('2016','2019','2022','2025')][string]$ServerVersion='2025',
    [string]$StorageRoot='H:\ad-sdk-lab\linux-client',
    [string]$LabRoot='H:\ad-sdk-lab',
    [string]$ImagePath='H:\ad-sdk-lab\linux-client\media\ubuntu-noble-20261017-amd64.img',
    [string]$ImageSHA256='04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94',
    [string]$GenIsoImage='C:\Users\Dafydd\github\sdk\go-sdk-activedirectory\tmp\linux-image-tools\extracted\usr\bin\genisoimage',
    [string]$WslDistribution='Ubuntu-24.04',
    [string]$LocalFile,
    [string]$RemoteName,
    [string]$Command,
    [byte[]]$InputBytes=@()
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V
$script:root=[IO.Path]::GetFullPath($StorageRoot).TrimEnd('\')
$script:statePath=Join-Path $script:root 'state.json'
$script:state=$null
$script:session=$null
$script:controlBridge=$null
$script:utf8=[Text.UTF8Encoding]::new($false)

function Assert-LinuxPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($script:root+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Path escaped the owned Linux root.'}
    for ($parent=$full;$parent;$parent=[IO.Path]::GetDirectoryName($parent)) {
        if ((Test-Path -LiteralPath $parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Reparse points are forbidden in Linux lab paths.'
        }
    }
    return $full
}

function Write-LinuxText([string]$Path,[string]$Text) {
    [IO.File]::WriteAllText((Assert-LinuxPath $Path),$Text.Replace("`r`n","`n"),$script:utf8)
}

function Save-LinuxState {
    $temporary=Assert-LinuxPath (Join-Path $script:root 'state.tmp')
    Write-LinuxText $temporary ($script:state | ConvertTo-Json -Depth 12)
    Move-Item -LiteralPath $temporary -Destination (Assert-LinuxPath $script:statePath) -Force
}

function Assert-LinuxState {
    $id=[guid]::Empty
    if ($script:state.schema_version -ne 1 -or $script:state.root -ine $script:root -or
        -not [guid]::TryParse($script:state.id,[ref]$id)) {throw 'Invalid Linux ownership journal.'}
    foreach ($pair in @(
        @('base_disk','disks\base.vhdx'),@('child_disk','disks\client.vhdx'),@('seed_iso','secrets\seed.iso'),
        @('client_key','secrets\client_ed25519'),@('host_key','secrets\host_ed25519')
    )) {
        $expected=Assert-LinuxPath (Join-Path $script:root $pair[1])
        if ($script:state.($pair[0]) -ine $expected) {throw 'An owned artifact path differs from the Linux journal.'}
    }
}

function Protect-LinuxSecrets([string]$Path) {
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath (Assert-LinuxPath $Path) -AclObject $acl
}

function Get-LinuxProfile([string]$Version) {
    $profileRoot=[IO.Path]::GetFullPath((Join-Path $LabRoot "server$Version"))
    $profile=Get-Content -LiteralPath (Join-Path $profileRoot 'state.json') -Raw | ConvertFrom-Json
    if ($profile.root -ine $profileRoot -or $profile.server_version -cne $Version -or $profile.domain -cne 'ad.sdk.test') {
        throw 'Unexpected isolated Windows lab manifest.'
    }
    $switch=Get-VMSwitch -Id ([guid]$profile.switch_id)
    if ($switch.SwitchType -ne 'Private' -or $switch.Name -cne "ad-sdk-$Version" -or $switch.Notes -cne "ad-sdk-lab:$($profile.id)") {
        throw 'The existing lab switch is not the expected owned private switch.'
    }
    return $profile
}

function Get-LinuxVM {
    if (-not $script:state.vm_id) {throw 'The Linux VM has not been journaled.'}
    $vm=Get-VM -Id ([guid]$script:state.vm_id)
    if ($vm.Name -cne 'ADSDKLINUX01' -or $vm.Notes -cne "ad-sdk-linux:$($script:state.id)" -or $vm.Generation -ne 2) {
        throw 'Linux VM identity differs from the ownership journal.'
    }
    $null=Assert-LinuxPath $vm.Path
    $disks=@(Get-VMHardDiskDrive -VM $vm)
    if ($disks.Count -ne 1 -or $disks[0].Path -ine $script:state.child_disk) {throw 'Unexpected Linux VM disk.'}
    $null=Assert-LinuxPath $disks[0].Path
    $disk=Get-VHD -Path $disks[0].Path
    if ($disk.ParentPath -ine $script:state.base_disk) {throw 'Linux differencing disk parent changed.'}
    $nics=@(Get-VMNetworkAdapter -VM $vm)
    if ($nics.Count -ne 1 -or $nics[0].MacAddress -ine $script:state.mac -or $nics[0].SwitchId.ToString() -ine $script:state.switch_id) {
        throw 'Unexpected Linux NIC identity or attachment.'
    }
    $profile=Get-LinuxProfile $script:state.server_version
    if ($profile.switch_id -ine $script:state.switch_id) {throw 'Linux VM is not attached to its journaled private profile.'}
    foreach ($dvd in @(Get-VMDvdDrive -VM $vm)) {
        if ($dvd.Path -and $dvd.Path -ine $script:state.seed_iso) {throw 'Unexpected Linux seed media.'}
    }
    return $vm
}

function ConvertTo-LinuxWslPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if ($full -notmatch '\A([A-Za-z]):\\(.+)\z') {throw 'A local drive path is required.'}
    return '/mnt/'+$Matches[1].ToLowerInvariant()+'/'+$Matches[2].Replace('\','/')
}

function Invoke-LinuxWsl([string[]]$Arguments) {
    & wsl.exe -d $WslDistribution -- @Arguments
    if ($LASTEXITCODE -ne 0) {throw "Linux image tool failed with exit code $LASTEXITCODE."}
}

function New-LinuxClient {
    if (Test-Path -LiteralPath $script:statePath) {
        $script:state=Get-Content -LiteralPath $script:statePath -Raw | ConvertFrom-Json
        Assert-LinuxState
        if ($script:state.phase -cne 'removed') {throw 'An active Linux journal exists. Use Status, Move, or Remove.'}
        foreach ($name in @('vm','disks','secrets','tools')) {
            if (Test-Path -LiteralPath (Assert-LinuxPath (Join-Path $script:root $name))) {throw 'A removed Linux journal still has owned artifacts.'}
        }
        $archive=Assert-LinuxPath (Join-Path $script:root "evidence\removed-$($script:state.id).json")
        if (Test-Path -LiteralPath $archive) {throw 'The old journal has already been archived.'}
        Copy-Item -LiteralPath $script:statePath -Destination $archive
        Remove-Item -LiteralPath (Assert-LinuxPath $script:statePath)
    }
    if (Get-VM -Name ADSDKLINUX01 -ErrorAction SilentlyContinue) {throw 'Refusing to replace an existing VM.'}
    $profile=Get-LinuxProfile $ServerVersion
    $image=Assert-LinuxPath $ImagePath
    if ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -ine $ImageSHA256) {throw 'Cloud image digest mismatch.'}
    $id=[guid]::NewGuid().ToString()
    foreach ($name in @('secrets','disks','vm','tools','evidence')) {
        $path=Assert-LinuxPath (Join-Path $script:root $name)
        if ((Test-Path -LiteralPath $path) -and $name -ne 'evidence') {throw "Refusing to adopt existing $name directory."}
        if (-not (Test-Path -LiteralPath $path)) {$null=New-Item -ItemType Directory -Path $path}
    }
    Protect-LinuxSecrets (Join-Path $script:root 'secrets')
    $script:state=[pscustomobject][ordered]@{
        schema_version=1;id=$id;root=$script:root;created_utc=[DateTime]::UtcNow.ToString('o');phase='preparing'
        vm_name='ADSDKLINUX01';vm_id='';mac='00155D237730';address='10.77.23.30/24';gateway=$null
        server_version=$ServerVersion;switch_id=$profile.switch_id;switch_name=$profile.switch_name
        image=$image;image_sha256=$ImageSHA256;base_disk=(Join-Path $script:root 'disks\base.vhdx')
        child_disk=(Join-Path $script:root 'disks\client.vhdx');seed_iso=(Join-Path $script:root 'secrets\seed.iso')
        client_key=(Join-Path $script:root 'secrets\client_ed25519');host_key=(Join-Path $script:root 'secrets\host_ed25519')
        ssh_host_public_key='';ssh_host_fingerprint='';go_version='';bridge_sha256='';last_inventory=$null
    }
    Save-LinuxState
    foreach ($path in @($script:state.client_key,$script:state.host_key)) {
        $null=Assert-LinuxPath $path
        if (Test-Path -LiteralPath $path) {throw 'Refusing to overwrite a private key.'}
        & ssh-keygen.exe -q -t ed25519 -N '' -C "ad-sdk-linux:$id" -f $path
        if ($LASTEXITCODE -ne 0) {throw 'SSH key generation failed.'}
    }
    $script:state.ssh_host_public_key=(Get-Content -LiteralPath ($script:state.host_key+'.pub') -Raw).Trim()
    $fingerprint=& ssh-keygen.exe -l -f ($script:state.host_key+'.pub')
    if ($LASTEXITCODE -ne 0) {throw 'Host fingerprint calculation failed.'}
    $script:state.ssh_host_fingerprint=($fingerprint -split '\s+')[1]
    Save-LinuxState
    $authorized=(Get-Content -LiteralPath ($script:state.client_key+'.pub') -Raw).Trim()
    $private=(Get-Content -LiteralPath $script:state.host_key -Raw).TrimEnd() -replace '(?m)^','    '
    $userData=@"
#cloud-config
hostname: adsdklinux01
manage_etc_hosts: true
timezone: Etc/UTC
disable_root: true
ssh_pwauth: false
ssh_deletekeys: true
ssh_quiet_keygen: true
ssh_publish_hostkeys: {enabled: false}
ssh_keys:
  ed25519_private: |
$private
  ed25519_public: $($script:state.ssh_host_public_key)
users:
  - name: adsdk
    groups: [adm, sudo]
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $authorized
package_update: false
package_upgrade: false
growpart: {mode: auto, devices: ['/'], ignore_growroot_disabled: false}
resize_rootfs: true
write_files:
  - path: /etc/ssh/sshd_config.d/05-adsdk.conf
    permissions: '0600'
    content: |
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      PermitRootLogin no
      AllowUsers adsdk
      HostKey /etc/ssh/ssh_host_ed25519_key
      AllowTcpForwarding no
      X11Forwarding no
  - path: /etc/adsdk-linux-owner
    permissions: '0644'
    content: '$id'
runcmd:
  - [systemctl, restart, ssh]
"@
    $mac=($script:state.mac -replace '(..)(?!$)','$1:').ToLowerInvariant()
    Write-LinuxText (Join-Path $script:root 'secrets\user-data') ($userData+"`n")
    $userData=$null;$private=$null
    Write-LinuxText (Join-Path $script:root 'secrets\meta-data') "instance-id: adsdk-linux-$id`nlocal-hostname: adsdklinux01`n"
    Write-LinuxText (Join-Path $script:root 'secrets\network-config') @"
version: 2
ethernets:
  lab:
    match: {macaddress: '$mac'}
    set-name: eth0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    addresses: [10.77.23.30/24]
    nameservers:
      addresses: [10.77.23.10, 10.77.23.11]
      search: [ad.sdk.test]
"@
    $seed=ConvertTo-LinuxWslPath $script:state.seed_iso
    $secret=ConvertTo-LinuxWslPath (Join-Path $script:root 'secrets')
    Invoke-LinuxWsl @((ConvertTo-LinuxWslPath $GenIsoImage),'-quiet','-output',$seed,'-volid','CIDATA','-joliet','-rock',
        "$secret/user-data","$secret/meta-data","$secret/network-config")
    Invoke-LinuxWsl @('/usr/bin/qemu-img','convert','-f','qcow2','-O','vhdx','-o','subformat=dynamic',
        (ConvertTo-LinuxWslPath $image),(ConvertTo-LinuxWslPath $script:state.base_disk))
    Resize-VHD -Path (Assert-LinuxPath $script:state.base_disk) -SizeBytes 16GB
    $null=New-VHD -Path (Assert-LinuxPath $script:state.child_disk) -ParentPath $script:state.base_disk -Differencing
    $vm=New-VM -Name ADSDKLINUX01 -Generation 2 -MemoryStartupBytes 2GB -Path (Assert-LinuxPath (Join-Path $script:root 'vm')) `
        -VHDPath $script:state.child_disk -SwitchName $profile.switch_name
    $script:state.vm_id=$vm.Id.ToString();Save-LinuxState
    Set-VM -VM $vm -Notes "ad-sdk-linux:$id" -ProcessorCount 2 -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -AutomaticCheckpointsEnabled $false
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
    Set-VMNetworkAdapter -VMName $vm.Name -StaticMacAddress $script:state.mac
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
    Add-VMDvdDrive -VM $vm -Path $script:state.seed_iso
    $disk=Get-VMHardDiskDrive -VM $vm
    Set-VMFirmware -VM $vm -FirstBootDevice $disk
    $script:state.phase='created';Save-LinuxState
    $null=Get-LinuxVM
    Start-VM -VM $vm
    $script:state.phase='running';Save-LinuxState
    return [pscustomobject]@{vm=$vm.Name;id=$vm.Id;private_switch=$profile.switch_name;address=$script:state.address;host_fingerprint=$script:state.ssh_host_fingerprint}
}

function New-LinuxBridge {
    $directory=Assert-LinuxPath (Join-Path $script:root 'tools')
    $source=Join-Path $directory 'main.go'
    $binary=Join-Path $directory 'sshbridge.exe'
    # This executable carries no secret. Only stdin contains the per-request key.
    Write-LinuxText (Join-Path $directory 'go.mod') "module adsdk-linux-control`n`ngo 1.27.4`n`nrequire golang.org/x/crypto v0.59.0`n"
    Write-LinuxText $source @'
package main

import (
    "bytes"
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "os"
    "time"
    "golang.org/x/crypto/ssh"
)

type request struct { Key, HostKey, Command, Payload string }
type response struct { ExitCode int `json:"exit_code"`; Stdout string `json:"stdout"`; Stderr string `json:"stderr"` }

func run() response {
    var r request
    if err := json.NewDecoder(io.LimitReader(os.Stdin, 48<<20)).Decode(&r); err != nil { return response{255,"","invalid bridge request"} }
    signer, err := ssh.ParsePrivateKey([]byte(r.Key))
    r.Key = ""
    if err != nil { return response{255,"","invalid client key"} }
    host, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.HostKey))
    if err != nil { return response{255,"","invalid pinned host key"} }
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
    defer cancel()
    conn, err := (&net.Dialer{Timeout:10*time.Second}).DialContext(ctx,"tcp","10.77.23.30:22")
    if err != nil { return response{255,"","SSH TCP connection failed: "+err.Error()} }
    defer conn.Close()
    _ = conn.SetDeadline(time.Now().Add(3*time.Minute))
    config := &ssh.ClientConfig{User:"adsdk",Auth:[]ssh.AuthMethod{ssh.PublicKeys(signer)},HostKeyCallback:ssh.FixedHostKey(host),Timeout:10*time.Second}
    sc, chans, reqs, err := ssh.NewClientConn(conn,"10.77.23.30:22",config)
    if err != nil { return response{255,"","pinned SSH handshake failed: "+err.Error()} }
    client := ssh.NewClient(sc,chans,reqs)
    defer client.Close()
    session, err := client.NewSession()
    if err != nil { return response{255,"","SSH session creation failed"} }
    defer session.Close()
    payload, err := base64.StdEncoding.DecodeString(r.Payload)
    if err != nil { return response{255,"","invalid payload"} }
    session.Stdin = bytes.NewReader(payload)
    var out, stderr bytes.Buffer
    session.Stdout = &out
    session.Stderr = &stderr
    code := 0
    if err := session.Run(r.Command); err != nil {
        if exit, ok := err.(*ssh.ExitError); ok { code = exit.ExitStatus() } else { return response{255,"","SSH execution failed: "+err.Error()} }
    }
    return response{code,out.String(),stderr.String()}
}

func main() {
    result := run()
    if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { fmt.Fprintln(os.Stderr,"bridge result failed"); os.Exit(255) }
}
'@
    $oldToolchain=$env:GOTOOLCHAIN
    try {
        $env:GOTOOLCHAIN='go1.27.4'
        Push-Location $directory
        try {
            & go mod tidy
            if ($LASTEXITCODE -ne 0) {throw 'SSH bridge module resolution failed.'}
            & go build -trimpath -o $binary .
            if ($LASTEXITCODE -ne 0) {throw 'SSH bridge build failed.'}
            $script:state.go_version=(& go version)
        } finally {Pop-Location}
    } finally {$env:GOTOOLCHAIN=$oldToolchain}
    $script:state.bridge_sha256=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    Save-LinuxState
    return $binary
}

function Open-LinuxMemberSession([string]$Version) {
    $profile=Get-LinuxProfile $Version
    $member=@($profile.machines | Where-Object role -eq 'member')
    if ($member.Count -ne 1) {throw 'Expected one Windows control member.'}
    $vm=Get-VM -Id ([guid]$member[0].id)
    $nics=@(Get-VMNetworkAdapter -VM $vm)
    if ($vm.Name -cne $member[0].name -or $vm.Notes -cne "ad-sdk-lab:$($profile.id)" -or $vm.State -ne 'Running' -or
        $nics.Count -ne 1 -or $nics[0].SwitchId.ToString() -ine $profile.switch_id) {throw 'The owned Windows control member must be running on its private switch.'}
    $saved=Import-Clixml -LiteralPath (Join-Path ([IO.Path]::GetFullPath($profile.root)) 'credential.clixml')
    $credential=[PSCredential]::new('ADSDK\Administrator',$saved.Password)
    $script:controlMember=$vm.Id.ToString();$script:controlProfile=$profile.id
    return New-PSSession -VMId $vm.Id -Credential $credential
}

function Invoke-LinuxControlCommand($Session,[scriptblock]$Operation,[object[]]$Arguments,[int]$TimeoutSeconds=30) {
    $job=Invoke-Command -Session $Session -ScriptBlock $Operation -ArgumentList $Arguments -AsJob
    try {
        if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) {throw 'Owned Linux control request exceeded its deadline; no retry was performed.'}
        return Receive-Job -Job $job -ErrorAction Stop
    } finally {
        if ($job.State -in @('Running','NotStarted','Blocked')) {Stop-Job -Job $job}
        Remove-Job -Job $job -Force
    }
}

function Get-LinuxControlGuestScript {
    return {
        param($Action,$Spec,$StageId,[long]$Offset,[string]$Encoded,[string]$ChunkHash)
        $ErrorActionPreference='Stop'
        function Get-LinuxControlDirectory([string]$OwnerId) {
            if ($OwnerId -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z') {throw 'Invalid public transport owner.'}
            return 'C:\adsdk-linux-control-cache\'+$OwnerId
        }
        function Assert-LinuxControlCacheOwner($Owner,$Expected,[bool]$CheckPayload=$true) {
            foreach ($name in @('owner_id','member_id','profile_id')) {
                if ($Owner.$name -cne $Expected.$name) {throw 'Public transport cache ownership differs.'}
            }
            if ($Owner.schema_version -ne 1 -or $Owner.purpose -cne 'adsdk-public-ssh-control') {throw 'Unexpected public transport cache.'}
            if ($CheckPayload -and ($Owner.sha256 -cne $Expected.sha256 -or $Owner.bytes -ne $Expected.bytes)) {throw 'Public transport cache source differs; reconcile before replacing it.'}
        }
        function Write-LinuxControlChunk([IO.Stream]$Stream,[long]$Position,[string]$Base64,[string]$ExpectedHash,[long]$MaximumLength=33554432) {
            if ($Base64.Length -gt 349528 -or $ExpectedHash -cnotmatch '\A[0-9a-f]{64}\z') {throw 'Invalid bounded public transport chunk.'}
            $data=[Convert]::FromBase64String($Base64)
            if ($data.Length -eq 0 -or $data.Length -gt 262144) {throw 'Public transport chunk must contain between 1 and 262144 bytes.'}
            $algorithm=[Security.Cryptography.SHA256]::Create()
            try {$actual=([BitConverter]::ToString($algorithm.ComputeHash($data))).Replace('-','').ToLowerInvariant()} finally {$algorithm.Dispose()}
            if ($actual -cne $ExpectedHash -or $Position -lt 0 -or $Position -gt $MaximumLength-$data.Length -or $Stream.Length -ne $Position) {throw 'Public transport chunk hash, bound or exact offset differs; no append retry is permitted.'}
            $Stream.Position=$Position;$Stream.Write($data,0,$data.Length);$Stream.Flush()
            return [pscustomobject]@{offset=$Position;bytes=$data.Length;sha256=$actual}
        }
        function Assert-LinuxControlEntries($Entries,[string]$Stage,[bool]$Legacy=$false) {
            $allowed=if($Legacy){@('sshbridge.exe')}else{@('owner.json','sshbridge.exe',('stage-'+$Stage+'.part'))}
            foreach ($entry in @($Entries)) {
                if ($entry.PSIsContainer -or $entry.Name -cnotin $allowed -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Unexpected public transport cache entry; no deletion performed.'}
            }
        }
        $directory=Get-LinuxControlDirectory $Spec.owner_id
        foreach ($id in @($Spec.member_id,$Spec.profile_id)) {if($id -cnotmatch '\A[0-9a-f-]{36}\z'){throw 'Invalid member/profile transport identity.'}}
        if ($env:COMPUTERNAME -cne $Spec.computer -or $Spec.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $Spec.bytes -le 0 -or $Spec.bytes -gt 32MB) {throw 'Public transport target or source differs.'}
        foreach ($path in @('C:\adsdk-linux-control-cache',$directory)) {
            if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Public transport paths cannot be reparse points.'}
        }
        $ownerPath=Join-Path $directory 'owner.json';$binary=Join-Path $directory 'sshbridge.exe'
        $owner=if(Test-Path -LiteralPath $ownerPath){Get-Content -LiteralPath $ownerPath -Raw|ConvertFrom-Json}else{$null}
        if ($owner) {Assert-LinuxControlCacheOwner $owner $Spec ($Action -cne 'Clear')}
        elseif ((Test-Path -LiteralPath $directory) -and @(Get-ChildItem -LiteralPath $directory -Force).Count) {throw 'Unowned public transport directory is not replaced.'}
        if ($Action -ceq 'Inspect') {
            if (-not $owner) {return [pscustomobject]@{ready=$false;path=$binary}}
            if ($owner.phase -cne 'complete') {throw 'An incomplete public transport stage requires explicit reconciliation; no retry was performed.'}
            if (-not(Test-Path -LiteralPath $binary) -or (Get-Item -LiteralPath $binary -Force).Attributes -band [IO.FileAttributes]::ReparsePoint -or (Get-Item -LiteralPath $binary).Length -ne $Spec.bytes -or (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Spec.sha256) {throw 'Cached public transport bytes differ.'}
            return [pscustomobject]@{ready=$true;path=$binary;sha256=$Spec.sha256;bytes=$Spec.bytes}
        }
        if ($Action -ceq 'Clear') {
            foreach ($legacy in @($false,$true)) {
                $target=if($legacy){'C:\adsdk-linux-control\'+$Spec.owner_id}else{$directory}
                $base=if($legacy){'C:\adsdk-linux-control'}else{'C:\adsdk-linux-control-cache'}
                if (-not [IO.Path]::GetFullPath($target).StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Control cleanup escaped the exact owned root.'}
                foreach($path in @($base,$target)){if((Test-Path -LiteralPath $path)-and((Get-Item -LiteralPath $path -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Unsafe public transport cleanup path.'}}
                if (-not(Test-Path -LiteralPath $target)) {continue}
                if (-not $legacy -and -not $owner) {throw 'Unowned cache cannot be removed.'}
                $entries=@(Get-ChildItem -LiteralPath $target -Force)
                Assert-LinuxControlEntries $entries $(if($owner){[string]$owner.stage_id}else{''}) $legacy
                $active=@(Get-CimInstance Win32_Process -Filter "Name='sshbridge.exe'"|Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)})
                if ($active.Count) {throw 'An owned SSH control process is active; no cache cleanup performed.'}
                foreach($entry in $entries){Remove-Item -LiteralPath $entry.FullName -Force}
                Remove-Item -LiteralPath $target
                if(Test-Path -LiteralPath $target){throw 'Owned public transport cache remains.'}
            }
            return [pscustomobject]@{verified=$true;public_transport_cache_absent=$true;private_material_ever_staged=$false}
        }
        if ($StageId -cnotmatch '\A[0-9a-f-]{36}\z') {throw 'Invalid fresh transport stage identity.'}
        $stage=Join-Path $directory ('stage-'+$StageId+'.part')
        if ($Action -ceq 'Begin') {
            if ($owner -or (Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $binary)) {throw 'A prior cache/stage prevents a new attempt.'}
            $null=New-Item -ItemType Directory -Path $directory -Force
            $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
            foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
            Set-Acl -LiteralPath $directory -AclObject $acl
            $owner=[pscustomobject]@{schema_version=1;purpose='adsdk-public-ssh-control';owner_id=$Spec.owner_id;member_id=$Spec.member_id;profile_id=$Spec.profile_id;sha256=$Spec.sha256;bytes=$Spec.bytes;stage_id=$StageId;phase='staging';acknowledged_bytes=0;chunks=0;private_material_staged=$false}
            $owner|ConvertTo-Json|Set-Content -LiteralPath $ownerPath -Encoding utf8
            $file=[IO.File]::Open($stage,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$file.Dispose()
            return
        }
        if (-not $owner -or $owner.phase -cne 'staging' -or $owner.stage_id -cne $StageId) {throw 'Exact active transport stage differs.'}
        if ($Action -ceq 'Chunk') {
            if ($owner.acknowledged_bytes -ne $Offset -or (Get-Item -LiteralPath $stage -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'The acknowledged transport offset differs; no retry allowed.'}
            $stream=[IO.File]::Open($stage,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try {$receipt=Write-LinuxControlChunk $stream $Offset $Encoded $ChunkHash $Spec.bytes;$stream.Flush($true)}finally{$stream.Dispose()}
            $owner.acknowledged_bytes+=$receipt.bytes;$owner.chunks++
            $owner|ConvertTo-Json|Set-Content -LiteralPath $ownerPath -Encoding utf8
            return $receipt
        }
        if ($Action -cne 'Finish' -or $owner.acknowledged_bytes -ne $Spec.bytes -or (Get-Item -LiteralPath $stage).Length -ne $Spec.bytes -or (Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Spec.sha256) {throw 'Complete public transport source hash/length differs.'}
        Move-Item -LiteralPath $stage -Destination $binary
        $owner.phase='complete';$owner|ConvertTo-Json|Set-Content -LiteralPath $ownerPath -Encoding utf8
        return [pscustomobject]@{ready=$true;path=$binary;sha256=$Spec.sha256;bytes=$Spec.bytes;chunks=$owner.chunks}
    }
}

function Get-LinuxControlSpec([string]$Bridge) {
    $vm=Get-VM -Id ([guid]$script:controlMember)
    return [pscustomobject]@{owner_id=$script:state.id;member_id=$script:controlMember;profile_id=$script:controlProfile;computer=$vm.Name;sha256=$script:state.bridge_sha256;bytes=(Get-Item -LiteralPath $Bridge).Length}
}

function Get-LinuxControlSession {
    if ($script:session) {return $script:session}
    $null=Get-LinuxVM
    $script:session=Open-LinuxMemberSession $script:state.server_version
    $bridge=Assert-LinuxPath (Join-Path $script:root 'tools\sshbridge.exe')
    if (-not (Test-Path -LiteralPath $bridge)) {$bridge=New-LinuxBridge}
    if ((Get-FileHash -LiteralPath $bridge -Algorithm SHA256).Hash -ine $script:state.bridge_sha256) {throw 'The owned SSH bridge digest changed.'}
    $spec=Get-LinuxControlSpec $bridge;$operation=Get-LinuxControlGuestScript
    $cached=Invoke-LinuxControlCommand $script:session $operation @('Inspect',$spec)
    if (-not $cached.ready) {
        $stage=[guid]::NewGuid().ToString();$null=Invoke-LinuxControlCommand $script:session $operation @('Begin',$spec,$stage)
        $stream=[IO.File]::OpenRead($bridge);$algorithm=[Security.Cryptography.SHA256]::Create()
        try {
            $buffer=[byte[]]::new(262144);[long]$offset=0
            while(($length=$stream.Read($buffer,0,$buffer.Length))-gt0){
                $hash=([BitConverter]::ToString($algorithm.ComputeHash($buffer,0,$length))).Replace('-','').ToLowerInvariant()
                $receipt=Invoke-LinuxControlCommand $script:session $operation @('Chunk',$spec,$stage,$offset,[Convert]::ToBase64String($buffer,0,$length),$hash)
                if($receipt.offset-ne$offset-or$receipt.bytes-ne$length-or$receipt.sha256-cne$hash){throw 'Public transport chunk acknowledgement differs; no retry performed.'}
                $offset+=$length
            }
        } finally {$algorithm.Dispose();$stream.Dispose()}
        $cached=Invoke-LinuxControlCommand $script:session $operation @('Finish',$spec,$stage)
    }
    if(-not$cached.ready-or$cached.sha256-cne$spec.sha256-or$cached.bytes-ne$spec.bytes){throw 'Verified public transport cache is required before SSH.'}
    $script:controlBridge=$cached.path
    return $script:session
}

function Clear-LinuxControlCache {
    $script:session=Open-LinuxMemberSession $ServerVersion
    $bridge=Assert-LinuxPath (Join-Path $script:root 'tools\sshbridge.exe')
    if((Get-FileHash -LiteralPath $bridge -Algorithm SHA256).Hash -ine $script:state.bridge_sha256){throw 'Public transport source changed.'}
    $spec=Get-LinuxControlSpec $bridge
    return Invoke-LinuxControlCommand $script:session (Get-LinuxControlGuestScript) @('Clear',$spec)
}

function Invoke-LinuxSSH([string]$RemoteCommand,[byte[]]$Payload=@(),[string]$PinnedHostKey='') {
    $control=Get-LinuxControlSession
    if (-not $PinnedHostKey) {$PinnedHostKey=$script:state.ssh_host_public_key}
    $request=@{Key=[IO.File]::ReadAllText($script:state.client_key);HostKey=$PinnedHostKey;Command=$RemoteCommand;Payload=[Convert]::ToBase64String($Payload)} | ConvertTo-Json -Compress
    try {
        $operation={
            param($Bridge,$Request)
            $ErrorActionPreference='Stop'
            $info=[Diagnostics.ProcessStartInfo]::new()
            $info.FileName=$Bridge;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
            $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $process=[Diagnostics.Process]::new();$process.StartInfo=$info
            try {
                $null=$process.Start()
                $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
                $process.StandardInput.Write($Request);$process.StandardInput.Close();$Request=$null
                if (-not $process.WaitForExit(200000)) {$process.Kill();throw 'SSH control bridge timed out.'}
                if ($process.ExitCode -ne 0) {throw 'SSH control bridge failed.'}
                return $stdout.GetAwaiter().GetResult()
            } finally {$process.Dispose()}
        }
        $result=Invoke-LinuxControlCommand $control $operation @($script:controlBridge,$request) 230
        return $result | ConvertFrom-Json
    } finally {$request=$null}
}

function Get-LinuxInventory {
    $null=Get-LinuxVM
    # A valid, deliberately different public key must fail before any SSH auth.
    $parts=$script:state.ssh_host_public_key -split '\s+'
    $wrong=[Convert]::FromBase64String($parts[1]);$wrong[$wrong.Length-1]=$wrong[$wrong.Length-1] -bxor 1
    $negative=Invoke-LinuxSSH 'true' -PinnedHostKey ($parts[0]+' '+[Convert]::ToBase64String($wrong))
    if ($negative.exit_code -ne 255 -or $negative.stderr -notlike '*host key mismatch*') {throw 'SSH did not reject the deliberately wrong pinned host key.'}
    $version=$script:state.server_version.Substring(2)
    $python=@'
import datetime,json,os,platform,socket,subprocess
def cmd(*args):
    p=subprocess.run(args,text=True,capture_output=True,timeout=90)
    return {"exit_code":p.returncode,"stdout":p.stdout.strip(),"stderr":p.stderr.strip()}
result={"os":platform.platform(),"architecture":platform.machine(),"hostname":socket.gethostname(),"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"owner":open("/etc/adsdk-linux-owner").read().strip(),"os_release":open("/etc/os-release").read(),"addresses":json.loads(cmd("ip","-j","address","show")["stdout"]),"routes":json.loads(cmd("ip","-j","route","show")["stdout"]),"dns":cmd("resolvectl","dns"),"cloud_init":cmd("cloud-init","status","--wait","--format","json"),"dns_records":{},"tcp":{}}
for host in ["ADSDK__VERSION__DC1.ad.sdk.test","ADSDK__VERSION__DC2.ad.sdk.test"]:
    try: result["dns_records"][host]=socket.gethostbyname_ex(host)[2]
    except OSError as e: result["dns_records"][host]=str(e)
for address in ["10.77.23.10","10.77.23.11"]:
    result["tcp"][address]={}
    for port in [389,636,3268,3269,88]:
        try:
            with socket.create_connection((address,port),timeout=3): result["tcp"][address][str(port)]=True
        except OSError: result["tcp"][address][str(port)]=False
print(json.dumps(result))
'@
    $python=$python.Replace('__VERSION__',$version)
    $result=Invoke-LinuxSSH 'python3 -' ([Text.Encoding]::UTF8.GetBytes($python))
    if ($result.exit_code -ne 0) {throw ('Linux inventory failed: '+$result.stderr)}
    $inventory=$result.stdout | ConvertFrom-Json
    if ($inventory.owner -cne $script:state.id -or $inventory.architecture -cne 'x86_64' -or $inventory.hostname -cne 'adsdklinux01') {throw 'Unexpected Linux guest identity.'}
    $boot=$inventory.cloud_init.stdout | ConvertFrom-Json
    if ($inventory.cloud_init.exit_code -ne 0 -or $boot.status -cne 'done') {throw 'Linux cloud-init did not finish without errors or warnings.'}
    if (@($inventory.routes | Where-Object dst -eq 'default').Count -ne 0) {throw 'The isolated Linux client acquired a default route.'}
    $addresses=@($inventory.addresses | ForEach-Object {$_.addr_info} | Where-Object family -eq 'inet' | ForEach-Object {$_.local})
    if ($addresses -cnotcontains '10.77.23.30') {throw 'Linux static lab address is missing.'}
    foreach ($pair in @(@("ADSDK${version}DC1.ad.sdk.test",'10.77.23.10'),@("ADSDK${version}DC2.ad.sdk.test",'10.77.23.11'))) {
        if (@($inventory.dns_records.($pair[0])) -cnotcontains $pair[1] -or -not $inventory.tcp.($pair[1]).'389') {throw 'Linux cannot resolve and directly reach an intended domain controller.'}
    }
    $skew=[Math]::Abs(([DateTimeOffset]::UtcNow-[DateTimeOffset]$inventory.utc).TotalSeconds)
    if ($skew -gt 120) {throw 'Linux clock differs from the host by more than two minutes.'}
    $evidence=[pscustomobject][ordered]@{schema_version=1;captured_utc=[DateTime]::UtcNow.ToString('o');profile=$script:state.server_version
        vm_id=$script:state.vm_id;switch_id=$script:state.switch_id;image_sha256=$script:state.image_sha256
        host_fingerprint=$script:state.ssh_host_fingerprint;ssh_host_key_pinned=$true;wrong_ssh_host_key_rejected=$true;clock_skew_seconds=$skew
        directory_authenticated=$false;directory_objects_mutated=$false;qualification_complete=$false;inventory=$inventory}
    $destination=Join-Path $script:root ("evidence\inventory-$($script:state.server_version)-"+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')
    Write-LinuxText $destination ($evidence | ConvertTo-Json -Depth 20)
    $script:state.last_inventory=$destination;Save-LinuxState
    return $evidence
}

function Remove-LinuxClient {
    if ($script:state.vm_id) {
        $vm=Get-LinuxVM
        if ($vm.State -ne 'Off') {Stop-VM -VM $vm -TurnOff -Confirm:$false}
        Remove-VM -VM $vm -Force
        if (Get-VM -Id ([guid]$script:state.vm_id) -ErrorAction SilentlyContinue) {throw 'Owned Linux VM still exists.'}
    } elseif (Get-VM -Name ADSDKLINUX01 -ErrorAction SilentlyContinue) {
        throw 'An unjournaled VM prevents partial provisioning cleanup.'
    }
    foreach ($name in @('vm','disks','secrets','tools')) {
        $path=Assert-LinuxPath (Join-Path $script:root $name)
        if (Test-Path -LiteralPath $path) {Remove-Item -LiteralPath $path -Recurse -Force}
        if (Test-Path -LiteralPath $path) {throw 'Owned Linux artifact removal failed.'}
    }
    $script:state.phase='removed';Save-LinuxState
    return [pscustomobject]@{removed=$true;vm_absent=$true;private_material_absent=$true;media_and_public_evidence_preserved=$true}
}

$mutex=[Threading.Mutex]::new($false,'Local\ADSDKPortableLinux')
$held=$false
try {
    try {$held=$mutex.WaitOne(0)} catch [Threading.AbandonedMutexException] {$held=$true}
    if (-not $held) {throw 'Another Linux lab operation is active.'}
    if ($Action -eq 'New') {New-LinuxClient;return}
    $null=Assert-LinuxPath $script:statePath
    $script:state=Get-Content -LiteralPath $script:statePath -Raw | ConvertFrom-Json
    Assert-LinuxState
    if ($script:state.phase -eq 'removed') {
        if ($Action -eq 'Status') {$script:state;return}
        throw 'The Linux VM has already been removed.'
    }
    switch ($Action) {
        Status {$vm=Get-LinuxVM;[pscustomobject]@{state=$vm.State;manifest=$script:state}}
        Start {$vm=Get-LinuxVM;if ($vm.State -eq 'Off') {Start-VM -VM $vm}}
        Move {
            $vm=Get-LinuxVM;$profile=Get-LinuxProfile $ServerVersion
            $wasRunning=$vm.State -eq 'Running'
            if ($vm.State -notin @('Off','Running')) {throw 'Linux must be stopped or running before moving profiles.'}
            if ($wasRunning) {Stop-VM -VM $vm -Confirm:$false}
            $nic=Get-VMNetworkAdapter -VM $vm
            Connect-VMNetworkAdapter -VMNetworkAdapter $nic -SwitchName $profile.switch_name
            $script:state.server_version=$ServerVersion;$script:state.switch_id=$profile.switch_id;$script:state.switch_name=$profile.switch_name;Save-LinuxState
            $null=Get-LinuxVM
            if ($wasRunning) {Start-VM -VM $vm}
            [pscustomobject]@{vm=$vm.Name;private_switch=$profile.switch_name;address=$script:state.address}
        }
        Inventory {Get-LinuxInventory}
        ClearControlCache {Clear-LinuxControlCache}
        Exec {
            try {
                if (-not $Command) {throw 'Exec requires Command.'}
                if ($null -eq $InputBytes) {$InputBytes=[byte[]]::new(0)}
                if ($InputBytes.Length -gt 65536) {throw 'Exec stdin is limited to 64 KiB.'}
                Invoke-LinuxSSH $Command $InputBytes
            } finally {
                if ($InputBytes) {[Array]::Clear($InputBytes,0,$InputBytes.Length)}
                $InputBytes=$null
            }
        }
        Upload {
            if (-not $LocalFile -or $RemoteName -cnotmatch '\A[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\z') {throw 'Upload requires a local file and a safe RemoteName.'}
            $file=Get-Item -LiteralPath $LocalFile
            if ($file.Length -gt 32MB -or $file.PSIsContainer) {throw 'Upload accepts files up to 32 MiB.'}
            $bytes=[IO.File]::ReadAllBytes($file.FullName)
            $result=Invoke-LinuxSSH "set -e; umask 077; test ! -L /home/adsdk/acceptance; mkdir -p /home/adsdk/acceptance; test ! -L /home/adsdk/acceptance/$RemoteName; cat > /home/adsdk/acceptance/$RemoteName; chmod 700 /home/adsdk/acceptance/$RemoteName; sha256sum /home/adsdk/acceptance/$RemoteName" $bytes
            if ($result.exit_code -ne 0) {throw ('Linux upload failed: '+$result.stderr)}
            $expected=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            if (($result.stdout -split '\s+')[0] -cne $expected) {throw 'Linux upload digest differs from the source.'}
            [pscustomobject]@{path="/home/adsdk/acceptance/$RemoteName";sha256=$expected;remote_digest_verified=$true;bytes=$file.Length}
        }
        Stop {$vm=Get-LinuxVM;if ($vm.State -ne 'Off') {Stop-VM -VM $vm -Confirm:$false}}
        Remove {Remove-LinuxClient}
    }
} finally {
    try {
        if ($InputBytes) {[Array]::Clear($InputBytes,0,$InputBytes.Length)}
        $InputBytes=$null
        if ($script:session) {Remove-PSSession $script:session}
    } finally {
        try {if ($held) {$mutex.ReleaseMutex()}} finally {$mutex.Dispose()}
    }
}
