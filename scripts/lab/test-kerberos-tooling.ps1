#Requires -Version 7.0

# Offline adversarial archive tests; no install, sudo, SSH or networking.
# dpkg-deb only builds/parses disposable synthetic archives for metadata checks.
[CmdletBinding()]
param([string]$WslDistribution='Ubuntu-24.04')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'kerberos-tooling.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'The tooling installer does not parse.'}
$definition=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]-and$node.Name -ceq 'Get-KerberosToolingPython'},$true)
if(-not$definition){throw 'The production archive validator is missing.'}
Invoke-Expression $definition.Extent.Text
$python=Get-KerberosToolingPython
$tests=@'

class BundleGuardTests(unittest.TestCase):
    version="1.20.1-6ubuntu2.10"
    def setUp(self):
        self.payloads={name+"_"+self.version+"_amd64.deb":("synthetic "+name).encode() for name in NAMES}
        self.manifest={"schema_version":1,"target":"Ubuntu24.04 noble amd64","guest_dpkg_status_sha256":"a"*64,"ubuntu_archive_keyring_sha256":"b"*64,"global_host_packages_changed":False,"guest_network_changes_required":False,"packages":[{"name":name,"version":self.version,"architecture":"amd64","file":name+"_"+self.version+"_amd64.deb","size":len(self.payloads[name+"_"+self.version+"_amd64.deb"]),"sha256":digest(self.payloads[name+"_"+self.version+"_amd64.deb"]),"repository_path":"pool/main/k/krb5/"+name+"_"+self.version+"_amd64.deb"} for name in sorted(NAMES)]}
    def members(self,manifest=None):
        encoded=json.dumps(self.manifest if manifest is None else manifest).encode()
        return [("tooling-manifest.json",encoded,tarfile.REGTYPE,{})]+[(name,data,tarfile.REGTYPE,{}) for name,data in sorted(self.payloads.items())]
    def bundle(self,members):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode="w:gz") as archive:
            for name,payload,kind,pax in members:
                info=tarfile.TarInfo(name);info.type=kind;info.size=len(payload) if kind==tarfile.REGTYPE else 0;info.pax_headers=pax
                if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE): info.linkname="/etc/owned-by-someone-else"
                archive.addfile(info,io.BytesIO(payload) if kind==tarfile.REGTYPE else None)
        return data.getvalue()
    def verify(self,members):
        blob=self.bundle(members)
        manifest=next((data for name,data,_,_ in members if name=="tooling-manifest.json"),b"")
        return read_bundle(blob,digest(blob),digest(manifest),self.version)
    def test_valid_flat_regular_payload(self):
        manifest,files=self.verify(self.members())
        self.assertEqual(set(p["name"] for p in manifest["packages"]),NAMES)
        self.assertEqual(len(files),6)
    def test_traversal_absolute_windows_and_nested_paths(self):
        for name in ("../outside.deb","/etc/outside.deb","C:outside.deb","..\\outside.deb","nested/package.deb"):
            with self.subTest(name=name):
                members=self.members();members[1]=(name,members[1][1],tarfile.REGTYPE,{})
                with self.assertRaisesRegex(ValueError,"flat owned filename"): self.verify(members)
    def test_symlink_hardlink_directory_device_fifo(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.DIRTYPE,tarfile.CHRTYPE,tarfile.BLKTYPE,tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                members=self.members();name,data,_,_=members[1];members[1]=(name,data,kind,{})
                with self.assertRaisesRegex(ValueError,"regular file"): self.verify(members)
    def test_duplicate_member(self):
        members=self.members();members[2]=members[1]
        with self.assertRaisesRegex(ValueError,"duplicate archive member"): self.verify(members)
    def test_unexpected_and_missing_members(self):
        members=self.members();members.append(("unrequested.deb",b"unexpected",tarfile.REGTYPE,{}))
        with self.assertRaisesRegex(ValueError,"member count"): self.verify(members)
        with self.assertRaisesRegex(ValueError,"size mismatch"): self.verify(self.members()[:-1])
        with self.assertRaisesRegex(ValueError,"manifest missing"): self.verify(self.members()[1:])
    def test_unexpected_pax_metadata(self):
        members=self.members();name,data,kind,_=members[1];members[1]=(name,data,kind,{"path":name})
        with self.assertRaisesRegex(ValueError,"extended archive metadata"): self.verify(members)
    def test_bundle_and_manifest_digests(self):
        members=self.members();blob=self.bundle(members)
        with self.assertRaisesRegex(ValueError,"bundle SHA256"): read_bundle(blob,"0"*64,digest(members[0][1]),self.version)
        with self.assertRaisesRegex(ValueError,"manifest SHA256"): read_bundle(blob,digest(blob),"0"*64,self.version)
    def test_package_digest_and_size(self):
        members=self.members();name,data,kind,pax=members[1];members[1]=(name,b"x"*len(data),kind,pax)
        with self.assertRaisesRegex(ValueError,"package SHA256"): self.verify(members)
        self.manifest["packages"][0]["size"]+=1
        with self.assertRaisesRegex(ValueError,"package size"): self.verify(self.members())
    def test_package_identity_version_architecture_and_repository(self):
        for field,value in (("name","krb5-kdc"),("version","1.0-malicious"),("architecture","arm64"),("repository_path","pool/other/evil.deb")):
            with self.subTest(field=field):
                manifest=json.loads(json.dumps(self.manifest));manifest["packages"][0][field]=value
                with self.assertRaises(ValueError): self.verify(self.members(manifest))
    def test_duplicate_packages_and_json_fields(self):
        manifest=json.loads(json.dumps(self.manifest));manifest["packages"][1]=manifest["packages"][0]
        with self.assertRaisesRegex(ValueError,"package set"): self.verify(self.members(manifest))
        members=self.members();members[0]=("tooling-manifest.json",b'{"schema_version":1,"schema_version":1}',tarfile.REGTYPE,{})
        with self.assertRaisesRegex(ValueError,"duplicate JSON field"): self.verify(members)
    def test_wrong_target_and_missing_solver_hash(self):
        for field,value in (("target","Ubuntu24.04 noble arm64"),("guest_dpkg_status_sha256","invalid"),("global_host_packages_changed",True),("guest_network_changes_required",True)):
            with self.subTest(field=field):
                manifest=json.loads(json.dumps(self.manifest));manifest[field]=value
                with self.assertRaises(ValueError): self.verify(self.members(manifest))
    def test_archive_expansion_limit(self):
        blob=gzip.compress(b"\0"*(MAX_BYTES+1024))
        with self.assertRaisesRegex(ValueError,"expanded archive"): read_bundle(blob,digest(blob),"a"*64,self.version)
    def test_archive_member_limit(self):
        members=self.members();name,_,kind,pax=members[1];members[1]=(name,b"x"*(1024*1024+1),kind,pax)
        with self.assertRaisesRegex(ValueError,"member exceeds limit"): self.verify(members)
    def test_mit_alternatives_use_the_owned_binary_not_generated_alias(self):
        for name in ("kinit","ktutil","kvno","klist"):
            with self.subTest(tool=name):
                command="/usr/bin/"+name
                binary=command if name=="kvno" else command+".mit"
                result=reference_tool(name,command,binary,"krb5-user: "+binary)
                self.assertEqual(result["command"],command)
                self.assertEqual(result["binary"],binary)
    def test_mit_alternative_cannot_redirect_to_another_path_or_package(self):
        for command,binary,owner in (("/home/adsdk/bin/kinit","/usr/bin/kinit.mit","krb5-user: /usr/bin/kinit.mit"),("/usr/bin/kinit","/tmp/kinit","krb5-user: /tmp/kinit"),("/usr/bin/kinit","/usr/bin/kinit.mit","unrelated-package: /usr/bin/kinit.mit")):
            with self.subTest(command=command,binary=binary,owner=owner):
                with self.assertRaises(ValueError): reference_tool("kinit",command,binary,owner)
    def test_actual_debian_control_metadata_is_checked_before_install(self):
        with tempfile.TemporaryDirectory(prefix="adsdk-offline-deb-guards-") as temporary:
            root=pathlib.Path(temporary)
            for field,value in ((None,None),("Package","unrequested-package"),("Version","1.0"),("Architecture","arm64")):
                with self.subTest(field=field):
                    manifest=json.loads(json.dumps(self.manifest));directory=root/(field or "valid");directory.mkdir()
                    for index,package in enumerate(manifest["packages"]):
                        content=directory/("source-"+str(index));control=content/"DEBIAN";control.mkdir(parents=True)
                        metadata={"Package":package["name"],"Version":package["version"],"Architecture":package["architecture"],"Maintainer":"Synthetic Fixture <fixture@example.invalid>","Description":"Not installable lab test data"}
                        if index==0 and field: metadata[field]=value
                        (control/"control").write_text("".join(key+": "+text+"\n" for key,text in metadata.items()))
                        target=directory/package["file"]
                        run(["/usr/bin/dpkg-deb","--build",str(content),str(target)])
                        data=target.read_bytes();package["size"]=len(data);package["sha256"]=digest(data)
                    encoded=json.dumps(manifest).encode()
                    members=[("tooling-manifest.json",encoded,tarfile.REGTYPE,{})]+[(p["file"],(directory/p["file"]).read_bytes(),tarfile.REGTYPE,{}) for p in manifest["packages"]]
                    parsed,_=self.verify(members)
                    if field:
                        with self.assertRaisesRegex(ValueError,"Debian control metadata mismatch"): deb_metadata(directory,parsed)
                    else: deb_metadata(directory,parsed)

unittest.main(argv=["offline-tooling-guards"],verbosity=2)
'@
# Evaluate the real validator definitions as a library, never its installer main.
$program=$python.Replace('if __name__=="__main__": main()','')+$tests
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tmp'))
$directory=[IO.Path]::GetFullPath((Join-Path $root ('kerberos-tooling-guards-'+[guid]::NewGuid().ToString('N'))))
if(-not$directory.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Guard-test artifact escaped the task tmp root.'}
$null=New-Item -ItemType Directory -Path $directory
$path=Join-Path $directory 'offline-guards.py.txt'
[IO.File]::WriteAllText($path,$program,[Text.UTF8Encoding]::new($false))
if($path -notmatch '\A([A-Za-z]):\\(.+)\z'){throw 'A local drive artifact is required.'}
$linux='/mnt/'+$Matches[1].ToLowerInvariant()+'/'+$Matches[2].Replace('\','/')
& wsl.exe -d $WslDistribution -- python3 $linux
if($LASTEXITCODE -ne 0){throw 'Offline tooling archive guards failed.'}
Write-Output 'PASS: real bundle guards reject malformed members, links, traversal, duplicate data, mismatched metadata and expansion limits without privileged operations.'
