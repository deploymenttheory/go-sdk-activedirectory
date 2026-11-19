import datetime
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
source_revision = 'ebb11a2aae28187c72ec0ea665bb5fe02aa451ed'
destination = root / 'tmp/worktrees/sdk-07/docs/research/portable-replication-evidence/canonical-ebb-live-server2025'
read = lambda path: json.loads(path.read_text(encoding='utf-8-sig'))
lab = Path('H:/ad-sdk-lab/portable-replication')
cases = [
    ('windows', 'server', 'sdk07-p25-20261119t011049167z', 1, 0),
    ('windows', 'explicit-servers', 'sdk07-p25-20261119t010957359z', 2, 0),
    ('windows', 'domain', 'sdk07-p25-20261119t010446173z', 2, 1),
    ('windows', 'forest', 'sdk07-p25-20261119t010621945z', 2, 2),
    ('windows', 'site', 'sdk07-p25-20261119t010707606z', 2, 3),
    ('linux', 'server', 'sdk07-p25-20261119t010956746z', 1, 0),
    ('linux', 'explicit-servers', 'sdk07-p25-20261119t011048526z', 2, 0),
    ('linux', 'domain', 'sdk07-p25-20261119t010521227z', 2, 1),
    ('linux', 'forest', 'sdk07-p25-20261119t010622239z', 2, 2),
    ('linux', 'site', 'sdk07-p25-20261119t010710240z', 2, 3),
]
ledger, rows = {}, []
def preserve(source, relative):
    payload = source.read_bytes()
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        assert target.read_bytes() == payload, target
    else:
        target.write_bytes(payload)
    ledger[relative] = {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(), 'source': str(source)}

diagnostics = protections = 0
for client, scope, run, count, enum in cases:
    capture = lab / run / (client + '-portable-password')
    result = read(capture / 'result.json')
    assert result['source_revision'] == source_revision and result['source_label_matches'] and result['success']
    assert result['run_id'] == run and result['platform'] == client + '/amd64' and result['toolchain'] == 'go1.27.4'
    assert result['backend'] == 'portable' and result['credential_source'] == 'password' and result['transport'] == 'ldap-seal'
    assert read(capture / 'process.json')['exit_code'] == 0
    assert [q['kind'] for q in result['queries']] == ['partners', 'failures', 'queue']
    for query in result['queries']:
        value = query['result']
        assert query['complete'] and value['Complete'] and value['Targets']['Complete']
        assert not query.get('error_class') and not query.get('statuses')
        selection = value['Targets']['Requested']
        assert selection['Scope'] == enum and len(value['Servers']) == count
        assert bool(selection['Servers']) == (scope == 'explicit-servers')
        for i, server in enumerate(value['Servers']):
            observation = server['Observation']
            assert observation['Complete'] and observation['Endpoint']['Host'].lower() == f'adsdk25dc{i+1}.ad.sdk.test'
            assert observation['Endpoint']['Port'] == 389
            mappings = [entry for host, entry in selection['ServicePrincipals'].items() if host.casefold() == observation['Endpoint']['Host'].casefold()]
            assert len(mappings) == 1
            stages = observation['rpc_protection']
            assert len(stages) == 2
            for j, stage in enumerate(stages):
                assert stage['stage'] == ['endpoint-map', 'drs'][j]
                assert stage['service_principal'] == mappings[0]['endpoint_mapper' if j == 0 else 'drs']
                assert stage['endpoint']['Host'] == observation['Endpoint']['Host']
                assert stage['endpoint']['Port'] == 135 if j == 0 else 0 < stage['endpoint']['Port'] <= 65535
                assert stage['realm'] == 'AD.SDK.TEST' and stage['encryption_type'] == 18 and stage['cipher_bits'] == 256
                assert all(stage[key] for key in ('mutual_authentication', 'header_signed', 'confidential', 'complete'))
                assert datetime.datetime.fromisoformat(stage['expires_at'].replace('Z', '+00:00')) > datetime.datetime.fromisoformat(observation['RootDSE']['CurrentTime'].replace('Z', '+00:00'))
                protections += 1
            categories = ['Inbound', 'Outbound'] if query['kind'] == 'partners' else ['Connections', 'Links'] if query['kind'] == 'failures' else ['State']
            assert all(server[category][key] for category in categories for key in ('Requested', 'Available', 'Complete'))
            diagnostics += 1
    if client == 'linux':
        transfer = read(capture / 'result-transfer.json')
        assert transfer['verified'] and transfer['host_result_sha256'] == transfer['remote_result_sha256'] == hashlib.sha256((capture / 'result.json').read_bytes()).hexdigest()
    for source in sorted(capture.iterdir()):
        if source.is_file() and source.suffix in ('.json', '.txt'):
            preserve(source, client + '/' + scope + '/' + source.name)
    rows.append({'client': client, 'server_version': '2025', 'credential_source': 'password', 'selection': scope, 'run_id': run, 'queries': 3, 'controllers': count, 'passed': True})
native = lab / 'sdk07-p25-20261119t010446173z/windows-native-password'
for source in sorted(native.iterdir()):
    if source.is_file() and source.suffix in ('.json', '.txt'):
        preserve(source, 'windows/native-domain/' + source.name)
proof = read(root / 'tmp/sdk07-live/ebb11a2/source-provenance.json')
agent_proof = read(root / 'tmp/worktrees/sdk-07/tmp/canonical-ebb11a2aae28/source-provenance.json')
assert proof['source_files'] == {name: value['sha256'] for name, value in agent_proof['source_files'].items()}
assert proof['files_verified'] == 4474 and proof['go_module_files'] == 932
build = root / 'tmp/sdk07-live/ebb11a2'
for name in ('source-provenance.json', 'binary-manifest.json', 'portablereplication-windows-amd64.exe.buildinfo.txt', 'portablereplication-linux-amd64.buildinfo.txt'):
    preserve(build / name, 'root-build/' + name)
for name in ('sdk07-ebb-domain-independent-audit.json', 'sdk07-ebb-domain-independent-audit-v2.json', 'audit-sdk07-ebb-domain.py', 'preserve-sdk07-ebb-live.py'):
    preserve(root / 'tmp' / name, 'audit/' + name)
audit = read(root / 'tmp/sdk07-ebb-domain-independent-audit-v2.json')
assert audit['pass'] and len(audit['checks']) == 318 and not audit['failed_checks']
preserve(root / 'tmp/worktrees/sdk-07/tmp/sdk07-canonical-race-mit-ebb11a2.log', 'offline/canonical-linux-race.log')
assert len(rows) == 10 and diagnostics == 54 and protections == 108
coverage = {'source_revision': source_revision, 'canonical_input_hashes_independently_equal': 4474, 'cases': rows, 'public_portable_queries': 30, 'server_diagnostic_reads': diagnostics, 'actual_rpc_stage_observations': protections, 'independent_domain_comparison_checks': 318, 'directory_mutations': 0, 'scope_complete': True, 'full_sdk07_matrix_complete': False, 'pending': ['keytab/cache and ordinary8453/partial live qualification', 'Server2016/2019/2022 Windows/Linux cells', 'final green CI and review'], 'limitations': ['Existing administrative password reads only.', 'Reported crypto facts are not independent packet decryption.', 'No arm64 live or provider-release qualification.']}
(destination / 'coverage-audit.json').write_text(json.dumps(coverage, indent=2) + '\n', encoding='utf-8', newline='\n')
(destination / 'artifact-hashes.json').write_text(json.dumps(ledger, indent=2) + '\n', encoding='utf-8', newline='\n')
(destination / 'README.md').write_text('''# Corrected-source Server 2025 replication scope evidence

Actual canonical source `ebb11a2aae28187c72ec0ea665bb5fe02aa451ed`, Go1.27.4,
Windows/Linux amd64, existing explicit protected administrative password
credentials. Single-server, explicit two-server, domain, forest and site
selection all complete partners/failures/queue through normal public SDK calls.
Thirty public aggregate queries cover54 server diagnostic reads and108 actual
EPM/DRS stage observations, all complete mutual/header-signed/confidential
AES256. Exact per-host registered principal mappings are retained.

The independent Windows-portable/Windows-native/Linux-portable domain audit
passes318 checks: ordered rows, statuses, nullable fields, FILETIME values and
protection facts. Every temporal/USN or session-metadata difference retains its
original values. The first audit failed only because it did not yet classify
the scope-resolution RootDSE time/USN differences; that failed audit remains
beside the corrected v2 audit. No original report was altered or replayed.

Root independently read every committed blob twice before building; all4474
input hashes agree with the separate source-owner freeze. Separately generated
ZIP/build metadata has its own recorded hashes. Both client binaries and all
executed controller/helper sources are individually bound by the original
manifests. Linux result transfers have exact remote/host digest agreement.
The full canonical Linux race log is retained separately from live evidence.

These read-only runs changed no directory account, ACL, policy, password,
network or service setting and created no new private credential fixture.
Existing lab credentials travelled through encrypted PSDirect/pinned SSH and
private process stdin. They were not saved in these public captures.

This is password/Server2025/scope evidence, not full SDK07 completion. Remaining
credential sources, ordinary8453/partial cases and all other server profiles
remain required under#172. Earlier D52 single-server success and failed domain
captures remain unchanged and are not relabelled as this corrected source.
`artifact-hashes.json` indexes byte-preserved originals; `coverage-audit.json`
records the exact tested and pending boundaries.
''', encoding='utf-8', newline='\n')
doc = root / 'tmp/worktrees/sdk-07/docs/research/portable-replication-validation.md'
text = doc.read_text(encoding='utf-8')
text = text.replace('The canonical tested source is\n`d52ac60a8300fdab43d7bc6db718c369efbdc80e`.', 'The initial canonical server-scope source was\n`d52ac60a8300fdab43d7bc6db718c369efbdc80e`.')
text = text.replace('| Windows amd64 | 2025 | Administrative password/server reads and native comparison passed; full cell pending |', '| Windows amd64 | 2025 | Corrected-source password: all five selection variants and domain native comparison pass; other credentials/refusals pending |')
text = text.replace('| Linux amd64 | 2025 | Pending |', '| Linux amd64 | 2025 | Corrected-source password: all five selection variants pass; other credentials/refusals pending |')
if '## Corrected-source live scope qualification' not in text:
    text += '''
## Corrected-source live scope qualification

The corrected canonical source is `ebb11a2aae28187c72ec0ea665bb5fe02aa451ed`.
[Fresh Windows/Linux Server2025 evidence](portable-replication-evidence/canonical-ebb-live-server2025/README.md)
covers all five password selection variants,30 public aggregate queries,
54 server diagnostic reads and108 complete mutual/header-signed/confidential
AES256 EPM/DRS observations. An independent domain-scope comparison against
native Windows and portable Linux passes318 checks with exact temporal and
session-metadata differences retained. Root separately verified all4474 raw
input hashes against the source-owner freeze before building. The canonical
full Linux race suite passed. None of this completes the remaining credentials,
ordinary refusals/partial cases or other server profiles listed above.
'''
doc.write_text(text, encoding='utf-8', newline='\n')
print(json.dumps({'destination': str(destination), 'originals': len(ledger), 'portable_queries': 30, 'server_reads': diagnostics, 'rpc_observations': protections, 'domain_audit_checks': 318, 'full_matrix_complete': False}))
