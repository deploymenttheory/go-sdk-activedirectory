#Requires -Version 7.0

<#
.SYNOPSIS
Validates and installs an authenticated offline MIT client bundle in the owned lab Linux VM.
.DESCRIPTION
These are independent lab reference tools. The SDK never invokes them. Validate
checks the bundle, Debian metadata, Ubuntu signatures and signed package indexes
without installing anything. Install repeats the payload checks inside the guest
before dpkg and refuses a guest package state different from the solver's input.
Verify checks a completed installation against its retained pre-install baseline,
without running dpkg installation again. The selected Linux VM must already be
running on the private server2025 profile.
All evidence and staging directories are fresh; retained inputs are never replaced.
No host packages, network configuration, accounts or domain policies are changed.

The caller pins both bundle and manifest hashes, plus the guest archive keyring.
The existing portable-linux.ps1 helper pins SSH identity and supplies public Python
code through stdin. No credentials are accepted or used by this installer.

References:
https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html
https://docs.python.org/3/library/tarfile.html
https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html
.EXAMPLE
./kerberos-tooling.ps1 Install -BundlePath ./kerberos-reference-tools.tar.gz -ExpectedBundleSHA256 <sha256> -ExpectedManifestSHA256 <sha256> -ExpectedKeyringSHA256 <sha256> -PackageVersion 1.20.1-6ubuntu2.10
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)][ValidateSet('Validate','Install','Verify')][string]$Action='Validate',
    [Parameter(Mandatory)][string]$BundlePath,
    [Parameter(Mandatory)][ValidatePattern('\A[a-f0-9]{64}\z')][string]$ExpectedBundleSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[a-f0-9]{64}\z')][string]$ExpectedManifestSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[a-f0-9]{64}\z')][string]$ExpectedKeyringSHA256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9][A-Za-z0-9.+~-]{1,79}\z')][string]$PackageVersion,
    [string]$ManifestPath,
    [string]$UbuntuKeyringPath,
    [string]$ReleaseDirectory,
    [string]$EvidenceRoot,
    [ValidatePattern('\A[0-9a-f]{32}\z')][string]$ExistingGuestRunId,
    [string]$LinuxStorageRoot='H:\ad-sdk-lab\linux-client',
    [string]$WslDistribution='Ubuntu-24.04'
)

function Get-KerberosToolingPython {
    return @'
import argparse,datetime,email.utils,gzip,hashlib,io,json,os,pathlib,platform,re,shutil,stat,subprocess,sys,tarfile,tempfile,unittest

NAMES={"krb5-user","libgssrpc4t64","libkadm5clnt-mit12","libkadm5srv-mit12","libkdb5-10t64"}
RELEASES={"archive.ubuntu.com_ubuntu_dists_noble_InRelease":"noble","archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease":"noble-updates","security.ubuntu.com_ubuntu_dists_noble-security_InRelease":"noble-security"}
MAX_BYTES=8*1024*1024
SHA=re.compile(r"[a-f0-9]{64}\Z")

def require(condition,message):
    if not condition: raise ValueError(message)

def digest(data): return hashlib.sha256(data).hexdigest()

def file_sha(path):
    h=hashlib.sha256()
    with open(path,"rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""): h.update(block)
    return h.hexdigest()

def unique_json(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,"duplicate JSON field")
        result[key]=value
    return result

def run(arguments,**kwargs):
    result=subprocess.run(arguments,capture_output=True,text=True,timeout=120,**kwargs)
    require(result.returncode==0,"command failed: "+arguments[0]+": "+result.stderr.strip())
    return result.stdout

def fresh(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as stream: stream.write(data)

def read_bundle(blob,expected_bundle,expected_manifest,version):
    require(len(blob)<=MAX_BYTES and digest(blob)==expected_bundle,"bundle SHA256 or size mismatch")
    with gzip.GzipFile(fileobj=io.BytesIO(blob)) as stream: raw=stream.read(MAX_BYTES+1)
    require(len(raw)<=MAX_BYTES,"expanded archive exceeds limit")
    files={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:",ignore_zeros=True) as archive:
        for member in archive:
            require(len(files)<6,"unexpected archive member count")
            name=member.name
            require(name not in files,"duplicate archive member")
            require(name not in (".","..") and "/" not in name and "\\" not in name and ":" not in name,"archive path is not a flat owned filename")
            require(member.isreg() and not member.issparse() and not member.linkname,"archive member is not a regular file")
            require(set(member.pax_headers)<= {"mtime","atime","ctime"},"unexpected extended archive metadata")
            require(0<=member.size<=1024*1024,"archive member exceeds limit")
            stream=archive.extractfile(member)
            data=stream.read(member.size+1)
            require(len(data)==member.size,"archive member size mismatch")
            files[name]=data
    require("tooling-manifest.json" in files,"manifest missing")
    require(digest(files["tooling-manifest.json"])==expected_manifest,"manifest SHA256 mismatch")
    manifest=json.loads(files["tooling-manifest.json"],object_pairs_hook=unique_json)
    require(manifest.get("schema_version")==1 and manifest.get("target")=="Ubuntu24.04 noble amd64","unexpected manifest target")
    require(manifest.get("global_host_packages_changed") is False and manifest.get("guest_network_changes_required") is False,"manifest requests an unsupported mutation")
    require(SHA.fullmatch(manifest.get("guest_dpkg_status_sha256","")) is not None,"invalid solver status digest")
    require(SHA.fullmatch(manifest.get("ubuntu_archive_keyring_sha256","")) is not None,"invalid archive keyring digest")
    packages=manifest.get("packages",[])
    require(len(packages)==5 and {p.get("name") for p in packages}==NAMES,"unexpected package set")
    require(len({p.get("file") for p in packages})==5,"duplicate package filename")
    expected={"tooling-manifest.json"}
    for package in packages:
        name=package["name"]
        filename=name+"_"+version+"_amd64.deb"
        require(package.get("version")==version and package.get("architecture")=="amd64" and package.get("file")==filename,"package identity/version/architecture mismatch")
        require(SHA.fullmatch(package.get("sha256","")) is not None and type(package.get("size")) is int,"invalid package digest or size")
        require(filename in files and 0<package["size"]<=1024*1024 and len(files[filename])==package["size"],"package size mismatch")
        require(digest(files[filename])==package["sha256"],"package SHA256 mismatch")
        require(package.get("repository_path") in ("pool/main/k/krb5/"+filename,"pool/universe/k/krb5/"+filename),"unexpected repository path")
        expected.add(filename)
    require(set(files)==expected,"unexpected archive member")
    return manifest,files

def extract_regular(directory,files):
    directory.mkdir(mode=0o700)
    for name,data in files.items(): fresh(directory/name,data)

def deb_metadata(directory,manifest):
    for package in manifest["packages"]:
        text=run(["/usr/bin/dpkg-deb","-f",str(directory/package["file"]),"Package","Version","Architecture"])
        fields=dict(line.split(": ",1) for line in text.splitlines())
        require(fields=={"Package":package["name"],"Version":package["version"],"Architecture":package["architecture"]},"Debian control metadata mismatch")

def release_hashes(text):
    headers={};hashes={};inside=False
    for line in text.splitlines():
        if line.startswith("-----BEGIN PGP SIGNATURE"): break
        if line=="SHA256:": inside=True;continue
        if inside and line.startswith(" "):
            parts=line.split()
            require(len(parts)==3 and SHA.fullmatch(parts[0]) is not None,"invalid signed SHA256 entry")
            hashes[parts[2]]=(parts[0],int(parts[1]));continue
        if inside: inside=False
        if ": " in line and not line.startswith(" "):
            key,value=line.split(": ",1);headers[key]=value
    return headers,hashes

def host_trust(args):
    require(platform.machine()=="x86_64","host validator must be amd64")
    require(file_sha(args.keyring)==args.keyring_sha,"guest archive keyring SHA256 mismatch")
    blob=pathlib.Path(args.bundle).read_bytes()
    manifest,files=read_bundle(blob,args.bundle_sha,args.manifest_sha,args.version)
    require(pathlib.Path(args.manifest).read_bytes()==files["tooling-manifest.json"],"external manifest differs from authenticated archive")
    require(manifest["ubuntu_archive_keyring_sha256"]==args.keyring_sha,"manifest archive keyring differs from the pinned guest keyring")
    directory=pathlib.Path(args.output)
    require(directory.is_dir(),"fresh evidence directory missing")
    home=directory/"gpgv-home";home.mkdir(mode=0o700)
    stages=directory/"validated-files";extract_regular(stages,files);deb_metadata(stages,manifest)
    release_dir=pathlib.Path(args.releases)
    require({p.name for p in release_dir.glob("*_InRelease")}==set(RELEASES),"unexpected signed repository set")
    declared={r["name"]:r for r in manifest["repository_releases"]}
    require(len(manifest["repository_releases"])==3 and set(declared)==set(RELEASES),"manifest signed repository set differs")
    releases=[];indexes=[];matched={p["name"]:[] for p in manifest["packages"]}
    wanted={p["name"]:p for p in manifest["packages"]}
    for name,suite in RELEASES.items():
        path=release_dir/name
        require(not path.is_symlink() and path.is_file() and file_sha(path)==declared[name]["sha256"],"signed repository digest differs")
        verification=subprocess.run(["gpgv","--homedir",str(home),"--status-fd","1","--keyring",args.keyring,str(path)],capture_output=True,text=True,timeout=30)
        require(verification.returncode==0 and "[GNUPG:] VALIDSIG " in verification.stdout,"Ubuntu release signature verification failed")
        fresh(directory/(name+".independent-gpgv.txt"),(verification.stdout+verification.stderr).encode())
        headers,hashes=release_hashes(path.read_text())
        require(headers.get("Origin")=="Ubuntu" and headers.get("Codename")=="noble" and headers.get("Suite")==suite,"unexpected signed Ubuntu release identity")
        if "Valid-Until" in headers: require(email.utils.parsedate_to_datetime(headers["Valid-Until"])>datetime.datetime.now(datetime.timezone.utc),"signed repository expired")
        fingerprints=[line.split()[2] for line in verification.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        releases.append({"name":name,"sha256":file_sha(path),"signer_fingerprints":fingerprints,"signature_verified":True})
        for component in ("main","universe"):
            relative=component+"/binary-amd64/Packages"
            expected_hash,expected_size=hashes[relative]
            package_index=release_dir/(name.removesuffix("_InRelease")+"_"+component+"_binary-amd64_Packages")
            require(not package_index.is_symlink() and package_index.stat().st_size==expected_size and file_sha(package_index)==expected_hash,"package index differs from signed InRelease")
            indexes.append({"release":name,"path":relative,"sha256":expected_hash,"size":expected_size})
            fields={}
            with open(package_index,encoding="utf-8") as stream:
                for line in stream:
                    if line.strip():
                        if not line[0].isspace() and ": " in line:
                            key,value=line.rstrip("\n").split(": ",1);fields[key]=value
                        continue
                    package=wanted.get(fields.get("Package"))
                    if package and fields.get("Version")==package["version"] and fields.get("Architecture")==package["architecture"]:
                        require(fields.get("SHA256")==package["sha256"] and int(fields.get("Size","-1"))==package["size"] and fields.get("Filename")==package["repository_path"],"package bytes differ from signed package index")
                        matched[package["name"]].append(name+":"+relative)
                    fields={}
    require(all(matched.values()),"a package has no matching signed package-index entry")
    record={"schema_version":1,"captured_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"bundle_sha256":args.bundle_sha,"manifest_sha256":args.manifest_sha,"guest_keyring_sha256":args.keyring_sha,"releases":releases,"signed_indexes":indexes,"package_index_matches":matched,"packages":manifest["packages"],"host_packages_modified":False,"network_downloads_performed":False}
    fresh(directory/"independent-trust.json",(json.dumps(record,indent=2)+"\n").encode())
    print(json.dumps(record))

def network_state():
    addresses=[]
    for link in json.loads(run(["ip","-j","address","show"])):
        for address in link.get("addr_info",[]): addresses.append([link["ifname"],address["family"],address["local"],address["prefixlen"]])
    routes4=json.loads(run(["ip","-j","-4","route","show"]))
    routes6=json.loads(run(["ip","-j","-6","route","show"]))
    require(not any(r.get("dst")=="default" for r in routes4+routes6),"isolated client acquired a default route")
    require(["eth0","inet","10.77.23.30",24] in addresses,"expected isolated client address missing")
    dns=run(["resolvectl","dns"]).strip()
    require("10.77.23.10 10.77.23.11" in dns,"expected private DNS configuration missing")
    return {"addresses":sorted(addresses),"routes4":routes4,"routes6":routes6,"dns":dns}

def package_state():
    text=run(["/usr/bin/dpkg-query","-W","-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"])
    return {line.split("\t")[0]:line.split("\t")[1:] for line in text.splitlines()}

def guest_identity(args):
    require(os.geteuid()==0,"installation requires the existing authorized sudo identity")
    require(platform.machine()=="x86_64" and run(["/usr/bin/dpkg","--print-architecture"]).strip()=="amd64","guest architecture is not amd64")
    release=dict(line.split("=",1) for line in pathlib.Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID","").strip('"')=="ubuntu" and release.get("VERSION_ID","").strip('"')=="24.04" and release.get("VERSION_CODENAME")=="noble","guest is not Ubuntu Noble")
    require(pathlib.Path("/etc/adsdk-linux-owner").read_text().strip()==args.owner,"guest ownership differs from the Hyper-V journal")
    require(re.fullmatch(r"[0-9a-f]{32}",args.run_id) is not None,"invalid install run identity")
    require(file_sha("/usr/share/keyrings/ubuntu-archive-keyring.gpg")==args.keyring_sha,"guest archive keyring differs from the trust anchor")
    path=pathlib.Path(args.bundle)
    require(path.parent==pathlib.Path("/home/adsdk/acceptance") and not path.is_symlink() and path.is_file(),"unexpected uploaded bundle path")
    manifest,files=read_bundle(path.read_bytes(),args.bundle_sha,args.manifest_sha,args.version)
    require(manifest["ubuntu_archive_keyring_sha256"]==args.keyring_sha,"manifest guest keyring differs")
    return manifest,files

def reference_tool(name,command,resolved,package_owner):
    canonical={"kinit":"/usr/bin/kinit.mit","ktutil":"/usr/bin/ktutil.mit","kvno":"/usr/bin/kvno","klist":"/usr/bin/klist.mit"}[name]
    require(command=="/usr/bin/"+name and resolved==canonical,"unexpected MIT command or alternative target")
    require(package_owner in ("krb5-user: "+resolved,"krb5-user:amd64: "+resolved),"MIT binary belongs to an unexpected package")
    return {"command":command,"binary":resolved,"package":"krb5-user"}

def verify_installed(args,manifest,directory,before,network_before,verification_only):
    require(not run(["/usr/bin/dpkg","--audit"]).strip(),"guest package database is not clean after installation")
    after=package_state()
    require(set(after)-set(before)==NAMES and not(set(before)-set(after)),"installation changed an unexpected package set")
    require(all(after[name]==state for name,state in before.items()),"an existing OS package changed")
    for name in NAMES: require(after[name]==[args.version,"amd64","installed"],"reference package is not cleanly installed at its pinned version")
    tools={}
    for name in ("kinit","ktutil","kvno","klist"):
        command=shutil.which(name)
        require(command is not None,"MIT client command is missing")
        resolved=str(pathlib.Path(command).resolve(strict=True))
        require(pathlib.Path(resolved).is_file() and os.access(resolved,os.X_OK),"MIT client binary is not executable")
        owner=run(["/usr/bin/dpkg-query","-S",resolved]).strip()
        tools[name]=reference_tool(name,command,resolved,owner)
    require(not run(["/usr/bin/dpkg","--verify","krb5-user"]).strip(),"MIT client package contents differ from their installed digests")
    version=run(["/usr/bin/klist","-V"]).strip()
    network_after=network_state()
    require(network_before==network_after,"guest network changed during offline tooling installation")
    result={"schema_version":1,"run_id":args.run_id,"captured_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"linux_owner":args.owner,"os":"Ubuntu24.04 noble amd64","bundle_sha256":args.bundle_sha,"manifest_sha256":args.manifest_sha,"solver_guest_status_sha256":manifest["guest_dpkg_status_sha256"],"guest_keyring_sha256":args.keyring_sha,"packages":{name:after[name] for name in sorted(NAMES)},"new_packages":5,"upgrades":0,"removals":0,"package_audit_clean":True,"tools":tools,"mit_version":version,"network_before":network_before,"network_after":network_after,"network_unchanged":True,"guest_apt_invoked":False,"directory_credentials_used":False,"kerberos_authentication_attempted":False,"kdc_daemon_installed":False,"sdk_runtime_dependency":False,"verification_only":verification_only,"dpkg_install_invoked":not verification_only,"retained_guest_directory":str(directory)}
    name=("verified-"+args.verification_id+".json") if verification_only else "installed.json"
    fresh(directory/name,(json.dumps(result,indent=2)+"\n").encode())
    print(json.dumps(result))

def guest_install(args):
    manifest,files=guest_identity(args)
    require(file_sha("/var/lib/dpkg/status")==manifest["guest_dpkg_status_sha256"],"guest dpkg status differs from the isolated solver input")
    require(not run(["/usr/bin/dpkg","--audit"]).strip(),"guest package database is not initially clean")
    before=package_state();network_before=network_state()
    require(not (set(before)&NAMES),"a planned new package already has guest state; a fresh solver plan is required")
    directory=pathlib.Path("/home/adsdk")/("kerberos-tooling-"+args.run_id)
    require(not directory.exists() and not directory.is_symlink(),"install run directory already exists")
    extract_regular(directory,files)
    deb_metadata(directory,manifest)
    debs=[str(directory/p["file"]) for p in manifest["packages"]]
    env=os.environ.copy();env.update({"DEBIAN_FRONTEND":"noninteractive","DEBIAN_PRIORITY":"critical","LC_ALL":"C","DPKG_COLORS":"never"})
    # All archive/manifest/control/dependency checks precede this first mutation.
    dry_run=run(["/usr/bin/dpkg","--no-act","--install",*debs],env=env)
    require(file_sha("/var/lib/dpkg/status")==manifest["guest_dpkg_status_sha256"],"guest package state changed during preflight")
    journal={"schema_version":1,"run_id":args.run_id,"linux_owner":args.owner,"phase":"validated","bundle_sha256":args.bundle_sha,"manifest_sha256":args.manifest_sha,"before_packages":before,"network_before":network_before}
    fresh(directory/"pre-install.json",(json.dumps(journal,indent=2)+"\n").encode())
    installation=run(["/usr/bin/dpkg","--install",*debs],env=env)
    fresh(directory/"dpkg-install.txt",installation.encode())
    verify_installed(args,manifest,directory,before,network_before,False)

def guest_verify(args):
    manifest,files=guest_identity(args)
    require(re.fullmatch(r"[0-9a-f]{32}",args.verification_id or "") is not None,"invalid verification identity")
    directory=pathlib.Path("/home/adsdk")/("kerberos-tooling-"+args.run_id)
    require(not directory.is_symlink() and directory.is_dir() and directory.stat().st_uid==0 and stat.S_IMODE(directory.stat().st_mode)==0o700,"retained installation directory ownership differs")
    journal=json.loads((directory/"pre-install.json").read_text(),object_pairs_hook=unique_json)
    require(journal["run_id"]==args.run_id and journal["linux_owner"]==args.owner and journal["bundle_sha256"]==args.bundle_sha and journal["manifest_sha256"]==args.manifest_sha,"retained installation journal differs")
    require((directory/"dpkg-install.txt").is_file(),"no completed dpkg installation log exists")
    for name,data in files.items():
        retained=directory/name
        require(not retained.is_symlink() and retained.is_file() and file_sha(retained)==digest(data),"retained validated input changed")
    deb_metadata(directory,manifest)
    verify_installed(args,manifest,directory,journal["before_packages"],journal["network_before"],True)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=["host-trust","guest-install","guest-verify"])
    for name in ("bundle","bundle-sha","manifest-sha","keyring-sha","version","manifest","keyring","releases","output","owner","run-id","verification-id"): parser.add_argument("--"+name)
    args=parser.parse_args()
    if args.action=="host-trust": host_trust(args)
    elif args.action=="guest-install": guest_install(args)
    else: guest_verify(args)

if __name__=="__main__": main()
'@
}

function Assert-KerberosToolingPath([string]$Path,[bool]$MustExist=$true) {
    $full=[IO.Path]::GetFullPath($Path)
    if($MustExist -and -not(Test-Path -LiteralPath $full)){throw 'A required tooling input does not exist.'}
    for($cursor=$full;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)) {
        if((Test-Path -LiteralPath $cursor)-and((Get-Item -LiteralPath $cursor -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Tooling paths must not traverse reparse points.'}
    }
    return $full
}

function ConvertTo-KerberosToolingWslPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if($full -notmatch '\A([A-Za-z]):\\(.+)\z'){throw 'A local drive tooling path is required.'}
    return '/mnt/'+$Matches[1].ToLowerInvariant()+'/'+$Matches[2].Replace('\','/')
}

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)-or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [Runtime.InteropServices.Architecture]::X64 -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64){throw 'Run this lab orchestrator on Windows amd64.'}
$bundle=Assert-KerberosToolingPath $BundlePath
$inputRoot=[IO.Path]::GetDirectoryName($bundle)
if(-not $ManifestPath){$ManifestPath=Join-Path $inputRoot 'tooling-manifest.json'}
if(-not $UbuntuKeyringPath){$UbuntuKeyringPath=Join-Path $inputRoot 'guest-ubuntu-archive-keyring.gpg'}
if(-not $ReleaseDirectory){$ReleaseDirectory=Join-Path $inputRoot 'apt\state\lists'}
if(-not $EvidenceRoot){$EvidenceRoot=Join-Path $inputRoot 'independent-verifications'}
$manifest=Assert-KerberosToolingPath $ManifestPath
$keyring=Assert-KerberosToolingPath $UbuntuKeyringPath
$releases=Assert-KerberosToolingPath $ReleaseDirectory
if((Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash -ine $ExpectedBundleSHA256 -or
    (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ine $ExpectedManifestSHA256 -or
    (Get-FileHash -LiteralPath $keyring -Algorithm SHA256).Hash -ine $ExpectedKeyringSHA256){throw 'Pinned host tooling input digest mismatch.'}
$evidence=Assert-KerberosToolingPath $EvidenceRoot $false
if(-not(Test-Path -LiteralPath $evidence)){$null=New-Item -ItemType Directory -Path $evidence}
$runId=[guid]::NewGuid().ToString('N')
$runDirectory=Assert-KerberosToolingPath (Join-Path $evidence $runId) $false
if(-not $runDirectory.StartsWith($evidence.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Tooling evidence escaped its root.'}
$null=New-Item -ItemType Directory -Path $runDirectory
$utf8=[Text.UTF8Encoding]::new($false)
$python=Get-KerberosToolingPython
$pythonPath=Join-Path $runDirectory 'validator.py.txt'
[IO.File]::WriteAllText($pythonPath,$python,$utf8)
$hostArgs=@('python3',(ConvertTo-KerberosToolingWslPath $pythonPath),'host-trust','--bundle',(ConvertTo-KerberosToolingWslPath $bundle),
    '--bundle-sha',$ExpectedBundleSHA256,'--manifest-sha',$ExpectedManifestSHA256,'--keyring-sha',$ExpectedKeyringSHA256,'--version',$PackageVersion,
    '--manifest',(ConvertTo-KerberosToolingWslPath $manifest),'--keyring',(ConvertTo-KerberosToolingWslPath $keyring),
    '--releases',(ConvertTo-KerberosToolingWslPath $releases),'--output',(ConvertTo-KerberosToolingWslPath $runDirectory))
$trust=& wsl.exe -d $WslDistribution -- @hostArgs
if($LASTEXITCODE -ne 0){throw 'Independent offline Ubuntu trust verification failed.'}
$trustRecord=$trust|ConvertFrom-Json
if($Action -eq 'Validate') {[pscustomobject]@{validated=$true;evidence_directory=$runDirectory;trust=$trustRecord};return}
$linuxHelper=Join-Path $PSScriptRoot 'portable-linux.ps1'
$status=& $linuxHelper Status -StorageRoot $LinuxStorageRoot
if($status.state -ne 'Running' -or $status.manifest.server_version -cne '2025'){throw 'The owned Linux client must already run on the private 2025 profile.'}
$owner=$status.manifest.id
if($owner -cnotmatch '\A[0-9a-f-]{36}\z'){throw 'Unexpected Linux ownership identity.'}
$bridge=Assert-KerberosToolingPath (Join-Path $LinuxStorageRoot 'tools\sshbridge.exe')
if((Get-FileHash -LiteralPath $bridge -Algorithm SHA256).Hash -ine $status.manifest.bridge_sha256){throw 'The existing lab SSH bridge digest differs from its journal.'}
$remoteName='kerberos-reference-'+$runId+'.tar.gz'
$upload=& $linuxHelper Upload -StorageRoot $LinuxStorageRoot -LocalFile $bundle -RemoteName $remoteName
if($upload.sha256 -cne $ExpectedBundleSHA256 -or -not $upload.remote_digest_verified){throw 'Pinned guest bundle upload failed.'}
$guestAction=if($Action -eq 'Verify'){'guest-verify'}else{'guest-install'}
if($Action -eq 'Verify' -and -not $ExistingGuestRunId){throw 'Verify requires ExistingGuestRunId from the retained installation.'}
$guestRunId=if($Action -eq 'Verify'){$ExistingGuestRunId}else{$runId}
$command='sudo -n python3 - '+$guestAction+' --bundle /home/adsdk/acceptance/'+$remoteName+
    ' --bundle-sha '+$ExpectedBundleSHA256+' --manifest-sha '+$ExpectedManifestSHA256+' --keyring-sha '+$ExpectedKeyringSHA256+
    ' --version '+$PackageVersion+' --owner '+$owner+' --run-id '+$guestRunId+' --verification-id '+$runId
$inputBytes=$utf8.GetBytes($python)
if($inputBytes.Length -gt 65536){throw 'Tooling validator exceeds the bounded SSH stdin limit.'}
try {$result=& $linuxHelper Exec -StorageRoot $LinuxStorageRoot -Command $command -InputBytes $inputBytes}
finally {[Array]::Clear($inputBytes,0,$inputBytes.Length)}
if($result.exit_code -ne 0){
    [IO.File]::WriteAllText((Join-Path $runDirectory 'guest-failure.txt'),$result.stderr,$utf8)
    throw ('Offline guest client installation failed: '+$result.stderr)
}
$installed=$result.stdout|ConvertFrom-Json
if(-not $installed.network_unchanged -or -not $installed.package_audit_clean -or $installed.new_packages -ne 5 -or $installed.upgrades -ne 0 -or $installed.removals -ne 0){throw 'Guest installation evidence does not match the approved narrow plan.'}
[IO.File]::WriteAllText((Join-Path $runDirectory 'guest-install.json'),($installed|ConvertTo-Json -Depth 15),$utf8)
[IO.File]::WriteAllText((Join-Path $runDirectory 'orchestration.json'),([ordered]@{
    schema_version=1;run_id=$runId;vm_id=$status.manifest.vm_id;linux_owner=$owner;profile='2025'
    ssh_host_fingerprint=$status.manifest.ssh_host_fingerprint;host_architecture='windows/amd64'
    host_packages_changed=$false;host_network_mutations=$false;reference_tools_only=$true
}|ConvertTo-Json),$utf8)
[pscustomobject]@{installed=$true;evidence_directory=$runDirectory;trust=$trustRecord;guest=$installed}
