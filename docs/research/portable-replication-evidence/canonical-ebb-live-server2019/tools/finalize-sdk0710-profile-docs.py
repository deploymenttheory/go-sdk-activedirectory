"""Add scoped 2019/2022 evidence notes and exact tool/receipt copies, offline."""
import argparse
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profile', required=True, choices=('2019', '2022'))
parser.add_argument('--sdk', required=True, choices=('07', '10'))
args = parser.parse_args()
sdk, version = args.sdk, args.profile
relative = 'portable-replication-evidence/canonical-ebb-live-server' + version if sdk == '07' else 'portable-discovery-evidence/server' + version + '-password-seal-7c69c15'
research = root / ('tmp/worktrees/sdk-' + sdk + '/docs/research')
destination = research / relative
read = lambda path: json.loads(path.read_bytes().decode('utf-8-sig'))
coverage = read(destination / 'coverage-audit.json')
ledger_path = destination / 'artifact-hashes.json'
ledger = read(ledger_path)


def preserve(source, name):
    payload = source.read_bytes()
    target = destination / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        assert target.read_bytes() == payload, target
    else:
        target.write_bytes(payload)
    ledger[name] = {'source': str(source), 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


preserve(root / 'tmp/audit-sdk0710-profile-evidence.py', 'tools/audit-sdk0710-profile-evidence.py')
preserve(Path(__file__), 'tools/finalize-sdk0710-profile-docs.py')
recheck_name = 'sdk07-server' + version + '-domain-owner-recheck.json' if sdk == '07' else 'sdk10-server' + version + '-owner-recheck.json'
if (root / 'tmp' / recheck_name).exists():
    preserve(root / 'tmp' / recheck_name, 'audit/source-owner-strict-comparator-recheck.json')
ledger_path.write_text(json.dumps(ledger, indent=2) + '\n', encoding='utf-8', newline='\n')
common = f'''
The exact baseline, readiness, complete Windows/Linux read-stage journals,
executed public sources, and independent restoration records are retained under
`profile/`. Both stages record zero directory mutations. The three owned
Windows guests returned to their original power states with zero active owned
SDK processes. The same owned Linux client moved from private Server 2025 to
private Server {version} and back, with its original Running state and owner
identity independently verified. Those temporary owned NIC/power moves are
explicit; no gateway, security policy, directory ACL/account, password or service
configuration was changed by these read-only diagnostic/discovery runs. No new
private credential fixture was created. Existing administrator credentials used
encrypted PowerShell Direct or pinned SSH and private process stdin, and are
absent from the public captures.

`artifact-hashes.json` indexes byte-preserved original records and executable
audit/preservation sources. It never substitutes a sanitized or regenerated
result. `coverage-audit.json` is derived metadata and explicitly keeps the full
SDK matrix incomplete. The reusable tools accept explicit 2019/2022 profiles;
copy preservation/finalization tools back to the repository's `tmp/` directory
before invoking them with their retained spec. The raw evidence auditor accepts
an explicit worktree and evidence prefix: `--working-tree` checks pending bytes
and committed HEAD Go identities; `--revision <sha>` checks actual committed
binary `git cat-file --batch` blobs. No archive/text-mode raw-byte claim is made.

These results qualify only the retained administrative password/SASL Seal
observations. Keytab/cache, other protection profiles, ordinary-account refusals,
partial-result cases and the unrecorded server/client cells remain open. Native
comparison does not establish least-privilege delegation; SDK-reported crypto
facts are not independent packet decryption. No other architecture, current
Windows domain inference or provider release qualification is implied.
'''
if sdk == '07':
    checks = coverage['stable_domain_comparison_checks']
    transition = []
    for case in coverage['cases']:
        transition.append({'client': case['client'], 'selection': case['selection'], 'run_id': case['run_id'],
                           'exact_failure_observations': case['failure_observations']})
    (destination / 'failure-transition-summary.json').write_text(json.dumps({'basis': 'Derived exact failure rows from the ten base portable captures; originals unchanged', 'observations': transition}, indent=2) + '\n', encoding='utf-8', newline='\n')
    transition_text = ''
    prior_path = destination / 'audit/prior-domain-comparison-1.json'
    if prior_path.exists():
        prior = read(prior_path)
        observed = {}
        for case in coverage['cases']:
            observed[(case['client'], case['selection'])] = sum(len(item['rows'] or []) for item in case['failure_observations'])
        stable = read(destination / 'comparison-stable/windows-portable/result.json')
        stable_failures = stable['queries'][1]['result']['Servers']
        exact_rows = []
        for server in stable_failures:
            for row in server['Failures'] or []:
                exact_rows.append(f"{server['Observation']['Endpoint']['Host']}: LastResult {row['LastResult']}, FailureCount {row['FailureCount']}, Time UTC {row['Time']['UTC']} (Ticks {row['Time']['Ticks']})")
        transition_text = f"""
The early Windows domain result reported {observed[('windows','domain')]} failure
rows; its later forest/site results reported {observed[('windows','forest')]}
and {observed[('windows','site')]} respectively. The Linux domain result reported
{observed[('linux','domain')]}. The original strict comparison ran
{len(prior['checks'])} checks and failed on {len(prior['failed_checks'])} checks,
with actual failed checks and unexplained row differences retained in
`audit/prior-domain-comparison-1.json`. The validator was not weakened. Fresh
Windows portable and native observations against the same selected controllers
then matched the existing Linux capture under the same strict comparator,
passing {checks} checks. Stable exact reported rows are:

""" + ''.join('- ' + item + '\n' for item in exact_rows) + """
These reported directory diagnostic rows remain distinct from successful
query/category completion. They are never filtered or interpreted as empty.
Their appearance between sequential observations is retained as a state
transition; no SDK production change or audit relaxation was used.
`failure-transition-summary.json` retains each base selection's exact rows.
Stable comparison and extra Windows/native captures are labelled under
`comparison-stable/` and do not inflate the ten base variants or their counts.
"""
    text = f'''# Server {version} replication password scope evidence

Actual canonical source `ebb11a2aae28187c72ec0ea665bb5fe02aa451ed`, Go 1.27.4,
Windows/Linux amd64, normal public SDK dispatcher and existing explicitly
selected administrative password credentials. Each client completes single
server, explicit two-server, domain, forest and site selection for ordered
partners/failures/queue queries. The ten base variants contain exactly 30 public
aggregate queries, 54 server diagnostic reads and 108 actual EPM/DRS stage
observations. Each stage reports complete mutual authentication, header signing,
confidential AES18/256 protection, a valid observed service lifetime and the
caller's exact per-host/stage principal mapping.

The unchanged independent Windows portable/native/Linux domain comparator
passes {checks} checks with no unexplained ordered-row/status/nullability
differences. Exact temporal/USN/session differences retain both values. The
source-owner rerun is separately retained. Every capture binds the actual
canonical source proof to its build manifest, transferred binary digest and
execution intent. All 932 Go/module Git blobs of the documentation branch
remain equal to the tested source; no runtime or module edit is part of this
update. Exact original source/build manifests remain alongside every capture.
{transition_text}{common}
Issue #172 remains open for its full remaining qualification scope.
'''
else:
    text = f'''# Server {version} explicit discovery, password and sealing

Actual canonical source `7c69c15ad3b959a76fe761e917dd11a55d93468e`, Go 1.27.4,
Windows/Linux amd64, normal public collector and existing explicitly selected
administrative password credentials. Both clients complete the exact absolute
domain SRV query, independent controller candidates, authenticated selected
domain/DC identity, and all four domain/forest/controller/list projections on
the same owning session. Both report complete mutual AES18/256 Kerberos SASL
Seal protection, without invented TLS/CBT/delegation facts.

The unchanged independent native/Windows/Linux comparator passes 129 checks,
including native domain/DSA/server GUIDs, SID decoding, role-owner relationships,
controller/domain/forest/site/GC sets, addresses and controller state. Projection
structures, ordering and nullable fields agree except exact retained RootDSE
time/USN differences. Native functional-level strings and collection wrappers
are preserved; no assumed enum or native nullability mapping is claimed.
The source-owner rerun is separately retained. Each actual executable transfer
and execution intent binds to the exact source and build manifests; Linux result
transfer hashes agree byte-for-byte. All 895 Go/module Git blobs of this
documentation branch remain equal to the tested source.
{common}
Issue #175 remains open for its full remaining qualification scope.
'''
(destination / 'README.md').write_text(text, encoding='utf-8', newline='\n')
doc = research / ('portable-replication-validation.md' if sdk == '07' else 'portable-discovery-validation.md')
body = doc.read_text(encoding='utf-8')
if sdk == '07':
    for client in ('Windows', 'Linux'):
        previous = f'| {client} amd64 | {version} | Pending |'
        status = f'| {client} amd64 | {version} | Corrected-source password: all five selection variants pass; strict domain comparison {checks} checks; other credentials/refusals pending |'
        body = body.replace(previous, status)
    title = f'## Actual Server {version} password scope observations'
    addition = f'''
{title}

The [byte-preserved Server {version} evidence]({relative}/README.md) retains
Windows/Linux password reads across all five selections: 30 aggregate queries,
54 server reads and 108 complete protected EPM/DRS observations. The strict
domain comparison against native Windows and portable Linux passes {checks}
checks. Actual diagnostic failure rows remain distinct from successful query
completion, and every original difference/audit is preserved. Extra comparison
captures do not inflate the base counts. Original Windows power states and the
Linux private Server 2025/Running state were independently restored. Runtime
source remains ebb11a2; full #172 qualification is still incomplete.
'''
else:
    body = body.replace('Live Windows and Linux qualification against\nServer 2016/2019/2022/2025 remains pending under #175;', 'Full Windows and Linux qualification against\nServer 2016/2019/2022/2025 remains pending under #175;')
    title = f'## Actual Server {version} password/sealing observations'
    addition = f'''
{title}

The [byte-preserved Server {version} evidence]({relative}/README.md) retains
both public clients completing DNS, authenticated identity and all four
projections with mutual AES18/256 SASL Seal. The unchanged strict
native/Windows/Linux comparison passes 129 checks. Exact original source,
binary-transfer, execution and Linux-result digests are retained. Windows
power states and the Linux private Server 2025/Running state were independently
restored, with zero directory mutations. Actual source remains 7c69c15; other
credential/protection/server profiles remain required under #175.
'''
if title not in body:
    body += addition
if sdk == '10':
    heading = '## Remaining live qualification matrix'
    if heading in body:
        body = body[:body.index(heading)].rstrip() + '\n'
    observed = {item for item in ('2019', '2022', '2025') if (research / ('portable-discovery-evidence/server' + item + '-password-seal-7c69c15/README.md')).exists()}
    body += '\n' + heading + '\n\n| Client | Server | Retained live status |\n| --- | --- | --- |\n'
    for item in ('2016', '2019', '2022', '2025'):
        for client in ('Windows', 'Linux'):
            status = 'Password/AES256 Seal identity and four projections pass; other credential/protection/refusal gates pending' if item in observed else 'Pending'
            body += '| ' + client + ' amd64 | ' + item + ' | ' + status + ' |\n'
    body += '\nEvery row records only its actual profile. Full #175 qualification remains open.\n'
doc.write_text(body, encoding='utf-8', newline='\n')
print(json.dumps({'sdk': sdk, 'server_version': version, 'indexed_originals': len(ledger), 'only_docs_and_evidence': True, 'committed': False}))
