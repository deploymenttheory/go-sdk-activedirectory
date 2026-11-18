"""Read-only independent metadata and SSH-only secret export for one owned run."""
import base64,datetime,hashlib,json,os,pathlib,re,stat,subprocess,sys

value=json.load(sys.stdin)
run=value['run_id']
if set(value)!={'run_id','linux_owner'} or not re.fullmatch(r'[a-z0-9][a-z0-9-]{5,39}',run):raise RuntimeError('Invalid owned export request')
if pathlib.Path('/etc/adsdk-linux-owner').read_text().strip()!=value['linux_owner']:raise RuntimeError('Owned Linux client required')
directory=pathlib.Path('/home/adsdk/acceptance')/('mit-'+run)
for entry in [directory,*directory.parents]:
    info=entry.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):raise RuntimeError('Unsafe owned reference path')
if directory.stat().st_uid!=os.getuid() or stat.S_IMODE(directory.stat().st_mode)!=0o700:raise RuntimeError('Unsafe reference directory ownership/mode')
env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','KRB5_CONFIG':str(directory/'krb5.conf')}
principal='sdkkrb'+hashlib.sha256(run.encode()).hexdigest()[:12]+'@AD.SDK.TEST'
manifest={'schema_version':1,'run_id':run,'principal':principal,'directory':str(directory),'linux_owner':value['linux_owner'],
          'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sdk_runtime_used':False,'metadata':{},'short_cache_before_expiry':None}
payload={}
expiry_only = sys.argv[1:] == ['--expiry-only']
if sys.argv[1:] not in ([], ['--expiry-only']):raise RuntimeError('Unsupported reference export action')
names=['expiry-probe-2m.ccache'] if expiry_only else ['client.keytab','tgt-only.ccache','password.ccache','keytab.ccache','expiry-probe-2m.ccache']
for name in names:
    path=directory/name
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as source:
        info=os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>1024*1024:raise RuntimeError('Unsafe reference credential file')
        raw=source.read(1024*1024+1)
    digest=hashlib.sha256(raw).hexdigest()
    flags=['-k','-t','-e',str(path)] if name.endswith('.keytab') else ['-c','-e','-f','FILE:'+str(path)]
    result=subprocess.run(['/usr/bin/klist',*flags],env=env,text=True,capture_output=True,timeout=15)
    if result.returncode!=0 or principal not in result.stdout:raise RuntimeError('MIT reference listing/identity failed')
    record={'path':str(path),'sha256':digest,'bytes':len(raw),'mode':'0600','mit_listing':result.stdout}
    if name.endswith('.ccache'):
        status=subprocess.run(['/usr/bin/klist','-s','-c','FILE:'+str(path)],env=env,capture_output=True,timeout=15)
        record['klist_s_exit']=status.returncode
        allowed=(1,) if expiry_only else ((0,1) if name=='expiry-probe-2m.ccache' else (0,))
        if status.returncode not in allowed:raise RuntimeError('Reference cache real validity differs from expected state')
    manifest['metadata'][name]=record
    if not expiry_only:payload[name]=base64.b64encode(raw).decode()
    raw=None
reference_path=directory/'reference.json'
if reference_path.is_file():
    reference=json.loads(reference_path.read_text())
    before=reference['short_cache_before_expiry']
    probe={'valid_before':before['klist_s_exit'],'observed_utc':before['observed_utc'],'requested_lifetime':before['requested_lifetime'],
           'file':reference['secret_files']['expiry-probe-2m.ccache'],'listing':reference['mit_listings']['expiry-probe-2m.ccache']}
else:
    # Retained first-run compatibility: the independent probe predated this entry point.
    probe=json.loads((directory/'expiry-probe-2m.json').read_text())
if probe['valid_before']!=0 or probe['file']['sha256']!=manifest['metadata']['expiry-probe-2m.ccache']['sha256']:raise RuntimeError('Short-lived cache bytes changed since valid-before observation')
manifest['short_cache_before_expiry']=probe
manifest['expiry_scope']='MIT-issued TGT local-expiry path; no short-lived LDAP service acquisition or server-side expiry is claimed'
manifest['clock_changed']=False
manifest['expiry_observed']=manifest['metadata']['expiry-probe-2m.ccache']['klist_s_exit']==1
manifest['exporter_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
# Do not persist this envelope: it carries actual keytab and ticket bytes.
print(json.dumps({'manifest':manifest,'secret_payload':payload}))
