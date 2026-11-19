import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--worktree', required=True)
parser.add_argument('--canonical', required=True)
parser.add_argument('--revision', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
worktree = Path(args.worktree).resolve()
canonical = Path(args.canonical).resolve()
proof_path = canonical / 'source-provenance.json'
proof = json.loads(proof_path.read_text(encoding='utf-8-sig'))
assert proof['source_revision'] == args.revision
files = proof['source_files']
assert len(files) == proof['files_verified']
requests = [args.revision + ':' + name for name in files]
data = subprocess.check_output(['git', '-C', str(worktree), 'cat-file', '--batch'], input=('\n'.join(requests) + '\n').encode())
archive_path = canonical / 'source.zip'
assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == proof['source_archive_sha256']
offset = 0
with zipfile.ZipFile(archive_path) as archive:
    assert len(archive.namelist()) == len(files) and set(archive.namelist()) == set(files)
    for name, expected in files.items():
        end = data.index(b'\n', offset)
        header = data[offset:end].decode().split()
        assert len(header) == 3 and header[1] == 'blob', (name, header)
        offset = end + 1
        content = data[offset:offset + int(header[2])]
        offset += int(header[2])
        assert data[offset:offset + 1] == b'\n'
        offset += 1
        path = (canonical / 'source' / name).resolve()
        assert path.is_relative_to(canonical / 'source')
        digest = expected['sha256'] if isinstance(expected, dict) else expected
        assert hashlib.sha256(content).hexdigest() == digest, name
        assert content == path.read_bytes() == archive.read(name), name
assert offset == len(data)
result = {'source_revision': args.revision, 'raw_git_zip_and_extraction_equal': True, 'files_verified': len(files), 'go_module_files': sum(name.endswith('.go') or name.rsplit('/', 1)[-1] in ('go.mod', 'go.sum') for name in files), 'source_archive_sha256': proof['source_archive_sha256'], 'source_provenance_sha256': hashlib.sha256(proof_path.read_bytes()).hexdigest(), 'qualification_claimed': False}
with Path(args.output).open('x', encoding='utf-8', newline='\n') as handle:
    json.dump(result, handle, indent=2)
    handle.write('\n')
print(json.dumps(result))
