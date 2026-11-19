"""Preserve two exact public native reference captures; no guest/lab calls."""
import hashlib
import json
from pathlib import Path

repo = Path(__file__).resolve().parent.parent
source_repo = Path('C:/Users/Dafydd/github/sdk/go-sdk-activedirectory')
destination = repo / 'docs/research/portable-security-descriptor-evidence/server2025-full-comparison'
lab = Path('H:/ad-sdk-lab/portable-security-descriptors')
runs = {'scope-failure-0c641': 'sdk06-cas2-20261119t022715454z-m15',
        'full15-ddcb6975': 'sdk06-cas2-20261119t023520965z-m15'}
hashes = {'scope-failure-0c641': '0c6414e4f76835f05dda9b4e18d2b36702f733a13b05d68a66b755a326d8fd7e',
          'full15-ddcb6975': 'ddcb697567cf9345578de34c23b0a59a28e8eaa5994592a226d7338212a2ae80'}
ledger = {}


def preserve(source, relative, payload=None, basis='Original raw file bytes'):
    data = source.read_bytes() if payload is None else payload
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        assert target.read_bytes() == data, target
    else:
        with target.open('xb') as handle:
            handle.write(data)
    ledger[relative] = {'source': str(source), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'basis': basis}


for label, run_id in runs.items():
    capture = lab / run_id
    files = sorted(path for path in capture.rglob('*') if path.is_file())
    assert files
    for source in files:
        assert not source.is_symlink() and source.suffix in ('.json', '.txt'), source
        assert not any(part.lower() in ('secrets', 'private') for part in source.relative_to(capture).parts), source
        preserve(source, label + '/' + source.relative_to(capture).as_posix())
    source = capture / 'host-reviewed-helper.ps1.txt'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == hashes[label]
    preserve(source, 'sources/probe-' + hashes[label][:8] + '.ps1.txt')

notes = ['sdk06-atomic-acl-protocol-notes.md', 'sdk06-atomic-acl-diagnosis-and-probe.md',
         'sdk06-atomic-acl-primary-source-research.md', 'sdk06-ntsd-compare-primary-followup.md',
         'sdk06-ntsd-compare-diagnosis-and-next-probe.md', 'sdk06-ntsd-full15-compare-observation.json']
for name in notes:
    preserve(source_repo / 'tmp' / name, 'research/' + name)
for name in ['sdk06-atomic-acl-probe-review.json', 'sdk06-atomic-acl-probe-review-ddcb6975.json']:
    preserve(source_repo / 'tmp' / name, 'offline/' + name)
for folder in ['sdk06-atomic-final-ps7-20261119', 'sdk06-atomic-final-ps51-20261119',
               'sdk06-atomic-fixed-scope-ps7-20261119', 'sdk06-atomic-fixed-scope-ps51-20261119']:
    preserve(source_repo / 'tmp' / folder / 'offline-result.json', 'offline/' + folder + '.json')
for name in ['sdk06-atomic-entry-scope-ps7.json', 'sdk06-atomic-entry-scope-ps51.json']:
    preserve(source_repo / 'tmp' / name, 'offline/' + name)
for name in ['test-sdk06-atomic-acl-probe.ps1', 'test-sdk06-atomic-entry-scope.ps1']:
    preserve(source_repo / 'tmp' / name, 'sources/' + name + '.txt')

# The original pre-invocation review names the initial README before its later
# scope-correction appendix. Recover only that exact immutable byte prefix and
# require its recorded length/hash; do not rewrite the root temporary source.
old_review = json.loads((source_repo / 'tmp/sdk06-atomic-acl-probe-review.json').read_bytes())
expected = next(item for item in old_review['files'] if item['path'].endswith('probe-README.md'))
readme = source_repo / expected['path']
current = readme.read_bytes()
original = current[:expected['bytes']]
assert hashlib.sha256(original).hexdigest() == expected['sha256']
preserve(readme, 'sources/pre-invocation-probe-README.md', original,
         'Exact original prefix recovered from appended document; independently matches recorded pre-invocation length and SHA256')
preserve(readme, 'sources/current-probe-README.md')
preserve(Path(__file__), 'tools/preserve-atomic-reference.py')
audit_tool = repo / 'tmp/audit-atomic-reference.py'
if audit_tool.exists():
    preserve(audit_tool, 'tools/audit-atomic-reference.py')
destination.mkdir(parents=True, exist_ok=True)
(destination / 'artifact-hashes.json').write_text(json.dumps(ledger, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps({'destination': str(destination), 'indexed_originals': len(ledger), 'runs': runs, 'lab_calls': 0}))
