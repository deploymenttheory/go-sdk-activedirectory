import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
destination = root / 'tmp/worktrees/sdk-10/docs/research/portable-discovery-evidence/server2025-password-seal-7c69c15'
lab = Path('H:/ad-sdk-lab/portable-discovery')
read = lambda path: json.loads(path.read_text(encoding='utf-8-sig'))
audit = read(root / 'tmp/sdk10-server2025-independent-audit.json')
assert audit['passed'] and len(audit['checks']) == 129 and not audit['failed_checks'] and not audit['unexplained_differences']
ledger = {}
def preserve(source, relative):
    payload = source.read_bytes()
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        assert target.read_bytes() == payload, target
    else:
        target.write_bytes(payload)
    ledger[relative] = {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(), 'source': str(source)}
for client, run in [('windows', 'sdk10-p25-20261119t012010167z'), ('linux', 'sdk10-p25-20261119t012326753z')]:
    capture = lab / run
    result = read(capture / 'result.json')
    assert result['source_revision'] == '7c69c15ad3b959a76fe761e917dd11a55d93468e' and result['source_label_matches'] and result['success']
    assert result['platform'] == client + '/amd64' and result['toolchain'] == 'go1.27.4'
    assert result['identity']['Complete'] and result['identity']['Protection']['SASLEncryptionType'] == 18
    assert read(capture / 'process.json')['exit_code'] == 0
    if client == 'linux':
        transfer = read(capture / 'result-transfer.json')
        assert transfer['verified'] and transfer['remote_result_sha256'] == transfer['host_result_sha256'] == hashlib.sha256((capture / 'result.json').read_bytes()).hexdigest()
    for source in sorted(capture.iterdir()):
        if source.is_file() and source.suffix in ('.json', '.txt'):
            preserve(source, client + '/' + source.name)
for source in sorted(lab.glob('sdk10-p25-20261119t01*')):
    if source.is_dir() and not (source / 'result.json').exists():
        files = list(source.iterdir())
        assert len(files) == 1 and files[0].name == 'host-execution-source.ps1.txt'
        assert "canonical-'+$revision.Substring(0,12)" in files[0].read_text(encoding='utf-8-sig')
        preserve(files[0], 'caller-preflight-only/' + source.name + '/' + files[0].name)
for name in ('sdk10-server2025-independent-audit.json', 'sdk10-root-independent-source-7c69c15.json', 'audit-sdk10-server2025.py', 'verify-agent-canonical-freeze.py', 'preserve-sdk10-server2025.py'):
    preserve(root / 'tmp' / name, 'audit/' + name)
proof = read(root / 'tmp/sdk10-root-independent-source-7c69c15.json')
assert proof['raw_git_zip_and_extraction_equal'] and proof['files_verified'] == 4369 and proof['go_module_files'] == 895
(destination / 'artifact-hashes.json').write_text(json.dumps(ledger, indent=2) + '\n', encoding='utf-8', newline='\n')
(destination / 'README.md').write_text('''# Server 2025 explicit discovery, password and sealing

Actual canonical public source `7c69c15ad3b959a76fe761e917dd11a55d93468e`,
Go 1.27.4, Windows/Linux amd64, existing explicit administrative password
credentials and mutual AES256 Kerberos SASL sealing. Both read-only runs observe
the exact absolute SRV query, independently advertised controllers, the selected
authenticated domain/DC identity and all four domain/forest/controller/list
projections on the selected owning session.

The independent native/Windows/Linux audit passes 129 checks. It verifies native
domain and DSA GUID/SID identities, exact controller relationships, domain and
forest role ownership, domains/sites/GC/controller sets, reported addresses and
controller state. All Windows/Linux identity/projection structures, ordering
and nullable values agree except explicitly retained RootDSE time/USN changes.
Native functional-level strings and collection wrappers remain unchanged; no
assumed numeric enum mapping or native nullability equivalence is claimed.
SDK-reported crypto facts are not independent packet decryption.

Root independently verified every one of the 4,369 ZIP and extracted source
files against committed raw Git blobs before live execution, including all 895
Go/module inputs. Build/provenance manifests and actual executable hashes bind
the source-owner binaries. Linux result bytes have exact remote/host SHA256
agreement. Byte-preserved originals and executed controller sources are indexed
by `artifact-hashes.json`; no private input, credential or executable is included.

The earlier forced-Go-DNS failure remains separately retained and unqualified.
The correction uses the normal configured OS resolver without changing a
gateway, DNS, network, account, ACL, policy, password or service setting. Its
bounded caller cancellation discards late OS-query results; an underlying OS
query may itself finish later. No authentication or endpoint fallback occurs.
These runs create no new private credential fixture.

The caller-preflight-only directory retains one aborted controller attempt:
its old manifest-key expectation failed before credential access or SDK calls.
Only its executed source exists; the fresh successful runs are separate.

This is two-client Server 2025 password/sealing evidence, not full SDK10 matrix
completion or release qualification. Other credential/protection profiles and
Server 2016/2019/2022 cells remain required under #175. No native-current-domain,
other-architecture live or provider-release support is inferred.
''', encoding='utf-8', newline='\n')
doc = root / 'tmp/worktrees/sdk-10/docs/research/portable-discovery-validation.md'
text = doc.read_text(encoding='utf-8')
if '## Actual Server 2025 password/sealing observations' not in text:
    text += '''
## Actual Server 2025 password/sealing observations

The corrected canonical source `7c69c15ad3b959a76fe761e917dd11a55d93468e`
passes public Windows/Linux amd64 DNS, authenticated identity and all four
topology projections. The [byte-preserved live records](portable-discovery-evidence/server2025-password-seal-7c69c15/README.md)
include a passing 129-check independent native/Windows/Linux comparison and
root's independent verification of all 4,369 raw-Git ZIP/extracted inputs before
live use. Both sessions report complete mutual AES256 SASL sealing. No lab
network, DNS, directory or service setting was changed. These are password/Seal
observations only; the other credentials, protection profiles and server
versions remain required under #175. Historical failures stay unqualified.
'''
doc.write_text(text, encoding='utf-8', newline='\n')
print(json.dumps({'originals': len(ledger), 'independent_checks': 129, 'client_server': ['Windowsamd64/2025', 'Linuxamd64/2025'], 'profile': 'administrative password/AES256Seal only', 'full_matrix_complete': False}))
