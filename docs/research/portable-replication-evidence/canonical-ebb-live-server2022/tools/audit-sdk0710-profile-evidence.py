"""Audit retained originals and exact committed Go/module identities, offline.

--working-tree verifies the pending evidence bytes and HEAD source identities;
it does not claim that pending evidence is committed. --revision audits actual
binary cat-file Git blobs. No git-show/archive text conversion is used.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def require(value, label):
    if not value:
        raise ValueError(label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worktree', required=True)
    parser.add_argument('--sdk', required=True, choices=('07', '10'))
    parser.add_argument('--profile', required=True, choices=('2019', '2022'))
    parser.add_argument('--evidence-prefix', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--working-tree', action='store_true')
    mode.add_argument('--revision')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    worktree = Path(args.worktree).resolve()
    prefix = args.evidence_prefix.rstrip('/') + '/'
    require(prefix.startswith('docs/research/portable-') and '..' not in Path(prefix).parts, 'Invalid evidence prefix')

    def git(*parts, data=None):
        return subprocess.check_output(['git', '-c', 'safe.directory=' + worktree.as_posix(), '-C', str(worktree), *parts], input=data)

    head = git('rev-parse', args.revision or 'HEAD').decode().strip()

    def blobs(paths):
        payload = git('cat-file', '--batch', data=('\n'.join(head + ':' + prefix + name for name in paths) + '\n').encode())
        offset, result = 0, {}
        for name in paths:
            end = payload.index(b'\n', offset)
            header = payload[offset:end].decode().split()
            require(len(header) == 3 and header[1] == 'blob', 'Missing/invalid raw Git blob: ' + name)
            size = int(header[2]);offset = end + 1
            result[name] = payload[offset:offset + size];offset += size
            require(payload[offset:offset + 1] == b'\n', 'Invalid cat-file boundary')
            offset += 1
        require(offset == len(payload), 'Trailing raw Git data')
        return result

    def contents(name):
        return (worktree / prefix / name).read_bytes() if args.working_tree else blobs([name])[name]

    ledger = json.loads(contents('artifact-hashes.json'))
    originals = {name: contents(name) for name in ledger} if args.working_tree else blobs(list(ledger))
    for name, expected in ledger.items():
        payload = originals[name]
        require(len(payload) == expected['bytes'] and hashlib.sha256(payload).hexdigest() == expected['sha256'], 'Original bytes/hash mismatch: ' + name)

    def tree(revision):
        result = {}
        for row in git('ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
            if row:
                metadata, path = row.split(b'\t', 1);name = path.decode()
                if name.endswith('.go') or name.rsplit('/', 1)[-1] in ('go.mod', 'go.sum'):
                    result[name] = metadata.decode().split()[2]
        return result

    source = {'07': 'ebb11a2aae28187c72ec0ea665bb5fe02aa451ed', '10': '7c69c15ad3b959a76fe761e917dd11a55d93468e'}[args.sdk]
    source_tree = tree(source)
    count = {'07': 932, '10': 895}[args.sdk]
    require(len(source_tree) == count and source_tree == tree(head), 'Actual Go/module raw Git blob identities differ from tested source')
    bound_captures = 0
    for name in originals:
        if not name.endswith('/result.json'):
            continue
        report = json.loads(originals[name])
        if 'platform' not in report or 'source_revision' not in report:
            continue
        parent = name.rsplit('/', 1)[0] + '/'
        proof_bytes = originals[parent + 'source-provenance.json']
        source_proof = json.loads(proof_bytes)
        manifest = json.loads(originals[parent + 'binary-manifest.json'])
        require(source_proof['source_revision'] == manifest['source_revision'] == report['source_revision'] == source, 'Actual capture/source/build revision mismatch')
        require(source_proof['files_verified'] == {'07': 4474, '10': 4369}[args.sdk] and source_proof['go_module_files'] == count, 'Canonical proof counts differ')
        require(manifest['source_provenance_sha256'] == hashlib.sha256(proof_bytes).hexdigest(), 'Binary manifest is not bound to exact retained source proof')
        platform = report['platform']
        if args.sdk == '07':
            selected = [entry for entry in manifest['binaries'] if entry['platform'] == platform]
            require(len(selected) == 1, 'Ambiguous/missing binary platform')
            binary = selected[0]
        else:
            filename = 'portablediscovery-' + platform.replace('/', '-') + ('.exe' if platform.startswith('windows/') else '')
            binary = manifest['artifacts'][filename]
            info = originals[parent + filename + '.buildinfo.txt']
            require(hashlib.sha256(info).hexdigest() == binary['buildinfo_sha256'], 'Actual discovery buildinfo differs')
        transfers = [json.loads(payload) for key, payload in originals.items() if key.startswith(parent) and '/' not in key[len(parent):] and key.endswith('binary-transfer.json')]
        intents = [json.loads(payload) for key, payload in originals.items() if key.startswith(parent) and '/' not in key[len(parent):] and key.endswith('execution-intent.json')]
        require(len(transfers) == len(intents) == 1, 'Missing/ambiguous actual transfer or execution intent')
        require(transfers[0]['sha256'] == intents[0]['binary_sha256'] == binary['sha256'] and transfers[0]['bytes'] == binary['bytes'], 'Actual executed/transferred binary differs from canonical manifest')
        require(intents[0]['source_revision'] == source and intents[0]['run_id'] == report['run_id'], 'Execution intent belongs to another source/run')
        bound_captures += 1
    coverage = json.loads(contents('coverage-audit.json'))
    require(coverage['source_revision'] == source and coverage['server_version'] == args.profile and coverage['directory_mutations'] == 0 and not coverage['full_sdk_matrix_complete'], 'Coverage metadata misstates source/scope')
    require(coverage['profile_power_restored'] and coverage['linux_original_profile_state_restored'], 'Restoration not verified')
    if args.sdk == '07':
        audit = json.loads(contents('audit/stable-domain-comparison.json'))
        require(audit['pass'] and not audit['failed_checks'] and all(item['pass'] for item in audit['checks']) and not any(item['unexplained_differences'] for item in audit['comparisons']), 'Stable replication audit is not strict/pass')
        require(len(coverage['cases']) == 10 and coverage['public_portable_queries'] == 30 and coverage['server_diagnostic_reads'] == 54 and coverage['actual_rpc_stage_observations'] == 108, 'Replication base counts inflated or missing')
        checks = len(audit['checks'])
    else:
        audit = json.loads(contents('audit/discovery-independent-comparison.json'))
        require(audit['passed'] and not audit['failed_checks'] and not audit['unexplained_differences'] and all(item['pass'] for item in audit['checks']), 'Discovery strict audit did not pass')
        require(len(coverage['cases']) == 2 and coverage['public_client_calls'] == 2 and coverage['complete_public_projections'] == 8 and len(audit['checks']) == 129, 'Discovery base counts inflated or missing')
        checks = 129
    proof = {'schema_version': 1, 'sdk': args.sdk, 'server_version': args.profile,
             'audit_basis': 'pending working-tree originals plus committed HEAD Go identities' if args.working_tree else 'committed raw Git blobs via binary cat-file',
             'reviewed_git_head': head, 'runtime_source': source, 'hash_verified_originals': len(ledger),
             'capture_source_binary_transfer_bindings_verified': bound_captures,
             'go_module_git_blobs_equal_tested_source': count, 'strict_independent_comparison_checks': checks,
             'directory_mutations': 0, 'windows_and_linux_original_state_restored': True,
             'passed': True, 'full_sdk_matrix_complete': False}
    output = Path(args.output)
    with output.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(proof, handle, indent=2);handle.write('\n')
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
