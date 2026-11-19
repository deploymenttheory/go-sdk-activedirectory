import datetime
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
worktree = root / 'tmp/worktrees/sdk-12'
destination = worktree / 'docs/research/portable-delegation-evidence/corrected-0750264-offline'
read = lambda path: json.loads(path.read_text(encoding='utf-8-sig'))
source = '075026493693067e0b0c8daf3b686a699c4cb3ca'
full_log = root / 'tmp/sdk12-root-0750264-fresh-full-race-vet.log'
focus_log = root / 'tmp/sdk12-original-0750264-mit-pass-full-race-interrupted.log'
full = full_log.read_text(encoding='utf-8-sig')
focus = focus_log.read_text(encoding='utf-8-sig')
assert '--- PASS: TestPortableDelegationIndependentMITAcceptor/false' in focus
assert '--- PASS: TestPortableDelegationIndependentMITAcceptor/true' in focus
assert '--- FAIL:' not in focus and '--- SKIP:' not in focus
records = [json.loads(line) for line in full.splitlines() if line.startswith('{')]
assert records[-1] == {'full_race_and_vet_exit_code': 0, 'live_directory_calls': 0}
assert records[-2]['phase'] == 'after_offline_checks' and records[-2]['exact_linux_inputs_verified'] == 4325
assert records[-2]['source_revision'] == source and 'go version go1.27.4 linux/amd64' in full
raw_proof = read(root / 'tmp/sdk12-root-independent-source-0750264.json')
assert raw_proof['raw_git_zip_equal'] and raw_proof['files_verified'] == 4325 and raw_proof['go_module_files'] == 891
ledger = {}
def preserve(path, relative):
    payload = path.read_bytes()
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        assert target.read_bytes() == payload, target
    else:
        target.write_bytes(payload)
    ledger[relative] = {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(), 'source': str(path)}
for name, relative in [
    ('tmp-sdk12-canonical-linux-race-MIT.log', 'historical/d8-initial-setup-no-qualification.log.txt'),
    ('tmp-sdk12-canonical-linux-offline-race-MIT.log', 'historical/d8-actual-forwarding-failure.log.txt'),
    ('tmp-sdk12-MIT-diagnostic-271ce9f.log', 'historical/271-actual-forwarding-diagnostic-failure.log.txt'),
    ('tmp-sdk12-KRBCred-DER-red.log', 'historical/krb-cred-standard-der-red.log.txt'),
]:
    preserve(worktree / name, relative)
for phase, folder in [('historical/d8-source', 'qualified-d8c5e47'), ('historical/271-source', 'diagnostic-271ce9f'), ('corrected-source', 'qualified-0750264')]:
    for name in ('source-provenance.json', 'manifest.json'):
        preserve(worktree / 'tmp' / folder / name, phase + '/' + name)
for path, relative in [
    (focus_log, 'corrected/actual-focused-mit-pass-full-race-interrupted.log.txt'),
    (full_log, 'corrected/root-full-race-vet.log.txt'),
    (root / 'tmp/sdk12-root-0750264-full-race-vet.log', 'corrected/recovery-preflight-missing-old-temporary-source-no-tests.log.txt'),
    (root / 'tmp/run-sdk12-root-offline.sh', 'corrected/root-executed-offline-source.sh.txt'),
    (root / 'tmp/sdk12-root-independent-source-0750264.json', 'corrected/root-independent-raw-git-zip-proof.json'),
    (root / 'tmp/verify-agent-canonical-freeze.py', 'audit/verify-agent-canonical-freeze.py'),
    (Path(__file__), 'audit/preserve-sdk12-offline-0750264.py'),
]:
    preserve(path, relative)
receipt = {'source_revision': source, 'go': 'go1.27.4 linux/amd64', 'distribution': 'Ubuntu-24.04', 'tool_session_id': 71458, 'actual_terminal_exit_code': 0, 'invocation': ['wsl', '-d', 'Ubuntu-24.04', '--exec', 'sh', '/mnt/c/Users/Dafydd/github/sdk/go-sdk-activedirectory/tmp/run-sdk12-root-offline.sh'], 'executed_source_sha256': hashlib.sha256((root / 'tmp/run-sdk12-root-offline.sh').read_bytes()).hexdigest(), 'log_sha256': hashlib.sha256(full_log.read_bytes()).hexdigest(), 'all_linux_source_inputs_verified_before_and_after': 4325, 'root_raw_git_zip_inputs_verified': 4325, 'all_go_module_inputs': 891, 'live_directory_calls': 0, 'receipt_observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'note': 'Actual tool terminal0 and final script records observed. No shell start/end timestamps are invented. Original worker focusedMIT pass and interrupted full-suite log remain separately preserved.'}
checks = [{'check': label, 'pass': True} for label in ['actual independent MIT default/nondelegating control passes', 'actual independent MIT explicit forwarding passes', 'corrected root full Go race suite and vet terminal0', 'all4325 Linux source inputs unchanged before/after checks', 'all4325 canonical ZIP inputs match committed raw Git', 'no live directory or privileged operation in this offline qualification']]
audit = {'source_revision': source, 'scope': 'Offline Linuxamd64 MIT GSS default/forwarding plus full SDK race/vet only; no AD server, cross-domain move or live credential/profile qualification.', 'passed': True, 'checks': checks, 'failed_checks': [], 'unexplained_differences': [], 'limitations': ['MIT accepts the actual emitted AP-REQ and delegated credential; the owned SDK peer separately completes LDAP mutual/SASL/final acknowledgement.', 'Missing same-forest second-domain/RID-master infrastructure remains required under LAB-03/#177.', 'Positive user/computer moves, password preservation and all applicable Windows/Linux×server-profile live gates remain unqualified.']}
for name, value in [('root-invocation-receipt.json', receipt), ('independent-offline-audit.json', audit), ('artifact-hashes.json', ledger)]:
    (destination / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8', newline='\n')
(destination / 'README.md').write_text('''# Corrected forwarding interoperability and offline checks

Actual corrected source `075026493693067e0b0c8daf3b686a699c4cb3ca`, Go 1.27.4
Linux/amd64. The independent installed MIT GSS library accepts both the default
nondelegating and explicit forwarding AP-REQs. It validates actual GSS identity,
delegated credential flags/profile/expiry and imports the credential into an
owned MEMORY cache without the SDK's ASN.1 decoder. The owned SDK LDAP peer
separately completes mutual/SASL/final acknowledgement. This is an offline
protocol gate, not MIT LDAP-server or live AD qualification.

Original d8 and diagnostic271 runs passed the default control but failed real
forwarding. Independent standard DER parsing exposed an unset explicit [2]
ticket-container tag; the owned RawValue decoder had accepted its own malformed
encoding. The correction emits [2] and rejects the wrong tag. Original failed
logs and their exact source manifests remain unchanged here.

The corrected worker's focused MIT test passed, but its subsequent full-suite
execution was interrupted without a terminal result. Root verified there was
no active Go process. Its first recovery stopped before tests because the old
temporary extraction was absent; that failed preflight is also retained. Root
then independently verified all 4,325 ZIP inputs against raw Git, extracted a
fresh owned Linux snapshot, and completed the full race suite plus vet with
actual terminal0. All 4,325 source bytes remain unchanged before/after testing.
The invocation receipt binds the executed source and log hashes.

All keys/tickets are synthetic owned offline fixtures. No live directory,
account grant, lab SSH call or user credential operation occurred. Executables,
credential payloads and private fixture material are excluded from these public
records. `artifact-hashes.json` indexes byte-preserved originals.

Full SDK12 completion remains pending: same-forest second-domain/RID fixtures,
real delegated source/destination execution, user/computer password preservation,
refusal/uncertainty/cleanup and applicable Windows/Linux server-profile evidence.
Missing infrastructure is not counted as unsupported or passing.
''', encoding='utf-8', newline='\n')
doc = worktree / 'docs/research/portable-move-delegation-design.md'
text = doc.read_text(encoding='utf-8')
if '## Actual independent offline qualification' not in text:
    text += '''
## Actual independent offline qualification

Corrected source `075026493693067e0b0c8daf3b686a699c4cb3ca` now passes the
actual opt-in MIT GSS default/forwarding cases and root's full Go 1.27.4 Linux
race/vet checks, with all 4,325 raw-Git inputs verified before and unchanged
afterward. The [retained evidence](portable-delegation-evidence/corrected-0750264-offline/README.md)
keeps the original independent failures, concrete DER finding, interrupted
worker run and fresh successful root run distinct. No AD server or move was
tested by this offline gate; all advanced live prerequisites remain required.
'''
doc.write_text(text, encoding='utf-8', newline='\n')
print(json.dumps({'originals': len(ledger), 'root_full_race_vet': 'PASS terminal0', 'actual_independent_MIT': 'default and forwarding PASS', 'all_raw_git_and_linux_inputs_verified': 4325, 'go_module_inputs': 891, 'live_calls': 0, 'full_sdk12_complete': False}))
