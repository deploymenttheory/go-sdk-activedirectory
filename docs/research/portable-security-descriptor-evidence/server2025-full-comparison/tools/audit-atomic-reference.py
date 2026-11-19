"""Audit immutable SDK06 reference evidence and ALL raw Go/module Git blobs.

No network, LDAP, guest, VM or SSH calls. --working-tree checks pending evidence
bytes and current HEAD runtime identities. --revision audits actual raw Git blobs.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

BASE = '0cab072e56a3c60e8a7c3a9a17b5c52fde2cb898'
PREFIX = 'docs/research/portable-security-descriptor-evidence/server2025-full-comparison/'
ORIGINAL = '0c6414e4f76835f05dda9b4e18d2b36702f733a13b05d68a66b755a326d8fd7e'
FIXED = 'ddcb697567cf9345578de34c23b0a59a28e8eaa5994592a226d7338212a2ae80'


def require(value, detail):
    if not value:
        raise ValueError(detail)


def audit(read, ledger):
    checks = []

    def check(condition, label):
        require(condition, label)
        checks.append(label)

    available = {(item['bytes'], item['sha256']) for item in ledger.values()}
    for name, item in ledger.items():
        raw = read(name)
        check(len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256'], 'Exact original bytes: ' + name)
        if name.endswith('.json'):
            json.loads(raw.decode('utf-8-sig'))
    parsed = lambda name: json.loads(read(name).decode('utf-8-sig'))
    for label, expected in [('scope-failure-0c641', ORIGINAL), ('full15-ddcb6975', FIXED)]:
        for filename in ['host-reviewed-helper.ps1.txt', 'guest-journal/probe-source.ps1.txt']:
            check(hashlib.sha256(read(label + '/' + filename)).hexdigest() == expected, 'Exact executed source: ' + label + '/' + filename)
    old = parsed('scope-failure-0c641/guest-journal/event-000002.json')
    check(old['phase'] == 'probe-stopped-no-replay' and old['stop_type'] == 'System.Management.Automation.CommandNotFoundException', 'Original private child-scope failure preserved')
    check(len(old['objects']) == 5 and all(not item['create_submitted'] and item['guid'] is None for item in old['objects']) and not old['cases'], 'Original failure preceded all creation and CAS')
    old_cleanup = parsed('scope-failure-0c641/independent-no-created-objects.json')
    check(old_cleanup['verified'] and old_cleanup['all_creation_intents_false'] and old_cleanup['actual_cas_cases_submitted'] == 0 and len(old_cleanup['observations']) == 2 and all(item['verified'] and item['root_dn_absent'] and item['matching_marker_objects'] == 0 for item in old_cleanup['observations']), 'Original both-DC no-created-object proof')
    final = parsed('full15-ddcb6975/guest-journal/event-000038.json')
    check(final['collection_complete'] and final['phase'] == 'cleanup-stopped-no-replay' and final['cleanup_complete'] is False, 'Historical helper cleanup flag remains false')
    check(final['old_snapshot_mask'] == 15 and final['source_sha256'] == FIXED and final['sdk_runtime_used'] is False and final['qualified'] is False, 'Full15 native reference, not SDK/runtime qualification')
    check(final['requested_native_security'] == {'authentication': 'Kerberos', 'signing': True, 'sealing': True, 'observed_cipher_claimed': False}, 'Requested native security is distinct from measured crypto')
    check(final['directory_context']['permissive_known'] and not final['directory_context']['permissive_modify'] and not final['directory_context']['heuristic_written'], 'Strict semantics preflight did not write dSHeuristics')
    check(len(final['objects']) == 5 and all(item['guid'] and item['create_status']['response_received'] and item['create_status']['code'] == 0 and item['delete_status']['response_received'] and item['delete_status']['code'] == 0 for item in final['objects']), 'Five exact create and five leaf delete LDAP0 acknowledgements')
    check(len(final['cases']) == 4 and all(not item['cas_submitted'] and item['cas_status'] is None and item['setup_status'] is None for item in final['cases']), 'Zero CAS and zero independent stale-setup requests')
    measurements = []
    for case in final['cases']:
        check([value['read_mask'] for value in case['before']] == [4, 7, 15], 'All three measured masks: ' + case['id'])
        for value in case['before']:
            snapshot = value['snapshot'];status = value['compare_status']
            check(value['read_status']['response_received'] and value['read_status']['code'] == 0, 'Actual descriptor read LDAP0: ' + case['id'] + '/' + str(value['read_mask']))
            check(snapshot['bytes'] == {4: 1688, 7: 1744, 15: 1864}[value['read_mask']], 'Exact returned descriptor length')
            check(status['response_received'] and status['code'] == 53 and status['diagnostic'].startswith('00002095:') and status['request_controls'] == [] and value['compare_control'] == 'absent', 'Actual standalone no-control Compare LDAP53/generic8341')
            if value['read_mask'] == 15:
                check(snapshot['control'] == 0x8c14 and (snapshot['owner_offset'], snapshot['group_offset'], snapshot['sacl_offset'], snapshot['dacl_offset']) == (1808, 1836, 20, 140), 'Exact full15 section offsets/control')
            measurements.append(value)
    check(len(measurements) == 12, 'Twelve actual reads and twelve Compare refusals')
    cleanup = parsed('full15-ddcb6975/independent-scoped-cleanup-audit.json')
    check(cleanup['verified'] and cleanup['directory_mutations'] == 0 and cleanup['original_cleanup_manifest_unchanged'] and len(cleanup['observations']) == 2, 'Independent read-only cleanup verification is additive')
    check({item['server'] for item in cleanup['observations']} == {'adsdk25dc1.ad.sdk.test', 'adsdk25dc2.ad.sdk.test'}, 'Both explicit controllers independently observed')
    for observed in cleanup['observations']:
        rows = observed['guid_and_dn']
        check(len(rows) == 10 and all(item['ldap_code'] == 32 and item['absent'] for item in rows), 'Every known GUID and DN actual LDAP32 on ' + observed['server'])
        for expected in final['objects']:
            check({item['identity'] for item in rows if item['guid'] == expected['guid'] and item['role'] == expected['role']} == {'guid', 'dn'}, 'Cleanup pins exact expected GUID/DN identity')
        unscoped = [item for item in observed['marker_searches'] if not item['domain_scope_control']]
        scoped = [item for item in observed['marker_searches'] if item['domain_scope_control']]
        check(len(unscoped) == 1 and unscoped[0]['ldap_code'] == 0 and len(unscoped[0]['references']) == 3 and unscoped[0]['used_for_absence'] is False, 'Unscoped referrals remain explicitly excluded from absence proof')
        check(len(scoped) == 1 and scoped[0]['ldap_code'] == 0 and scoped[0]['objects'] == 0 and scoped[0]['references'] == [] and scoped[0]['used_for_absence'] is True, 'Scoped domain marker search confirms zero objects/references')
    for name in ['offline/sdk06-atomic-acl-probe-review.json', 'offline/sdk06-atomic-acl-probe-review-ddcb6975.json']:
        review = parsed(name)
        for item in review['files']:
            check((item['bytes'], item['sha256']) in available, 'Review-listed frozen source/document preserved: ' + item['path'])
        for item in review['offline_receipts']:
            digest = item.get('result_sha256', item.get('sha256'))
            check(any(value['sha256'] == digest for value in ledger.values()), 'Original offline receipt hash preserved')
    for name in ['sdk06-atomic-final-ps7-20261119', 'sdk06-atomic-final-ps51-20261119', 'sdk06-atomic-fixed-scope-ps7-20261119', 'sdk06-atomic-fixed-scope-ps51-20261119']:
        receipt = parsed('offline/' + name + '.json')
        check(receipt['passed'] and receipt['checks'] == 79 and receipt['native_ldap_calls'] == 0 and receipt['helper_sha256'] == (FIXED if 'fixed' in name else ORIGINAL), '79 mocked guard receipt, exact source: ' + name)
    for shell in ['ps7', 'ps51']:
        receipt = parsed('offline/sdk06-atomic-entry-scope-' + shell + '.json')
        check(receipt['passed'] and receipt['native_ldap_calls'] == 0 and receipt['helper_sha256'] == FIXED and len(receipt['cases']) == 2 and receipt['cases'][0]['expected_resolution_failure'] and receipt['cases'][1]['checks'] == 8 and receipt['cases'][1]['passed'], 'Eight real child-entry/lifetime checks: ' + shell)
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worktree', default=str(Path(__file__).resolve().parent.parent))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--working-tree', action='store_true')
    mode.add_argument('--revision')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    worktree = Path(args.worktree).resolve()

    def git(*parts, data=None):
        return subprocess.check_output(['git', '-c', 'safe.directory=' + worktree.as_posix(), '-C', str(worktree), *parts], input=data)

    head = git('rev-parse', args.revision or 'HEAD').decode().strip()

    def blobs(names):
        raw = git('cat-file', '--batch', data=('\n'.join(head + ':' + PREFIX + name for name in names) + '\n').encode())
        offset, values = 0, {}
        for name in names:
            end = raw.index(b'\n', offset);header = raw[offset:end].decode().split();offset = end + 1
            require(len(header) == 3 and header[1] == 'blob', 'Missing/invalid raw Git blob: ' + name)
            size = int(header[2]);values[name] = raw[offset:offset + size];offset += size
            require(raw[offset:offset + 1] == b'\n', 'Invalid raw Git boundary');offset += 1
        require(offset == len(raw), 'Unexpected trailing raw Git output')
        return values

    read = lambda name: (worktree / PREFIX / name).read_bytes() if args.working_tree else blobs([name])[name]
    ledger = json.loads(read('artifact-hashes.json'))
    contents = {name: read(name) for name in ledger} if args.working_tree else blobs(list(ledger))
    checks = audit(lambda name: contents[name], ledger)

    def runtime(revision):
        values = {}
        for row in git('ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
            if row:
                metadata, path = row.split(b'\t', 1);name = path.decode()
                if name.endswith('.go') or name.rsplit('/', 1)[-1] in ('go.mod', 'go.sum'):
                    values[name] = metadata.decode().split()[2]
        return values

    original = runtime(BASE)
    require(original and original == runtime(head), 'ALL Go/module raw Git blobs must equal base0cab072')
    proof = {'schema_version': 1, 'audit_basis': 'pending evidence bytes and committed HEAD source identities' if args.working_tree else 'actual committed raw Git blobs via binary cat-file',
             'reviewed_git_head': head, 'runtime_base': BASE, 'all_go_module_git_blobs_equal': len(original),
             'hash_verified_originals': len(ledger), 'checks': len(checks), 'passed': True,
             'original_scope_failure_created_objects': 0, 'original_scope_failure_cas_submitted': 0,
             'full15_objects_created': 5, 'full15_leaf_deletions_ldap0': 5, 'full15_descriptor_reads_ldap0': 12,
             'full15_standalone_compare_ldap53': 12, 'full15_cas_submitted': 0,
             'historical_helper_cleanup_complete': False, 'independently_scoped_both_dc_absence': True,
             'sdk_atomic_route_qualified': False, 'lab_calls_by_auditor': 0}
    with Path(args.output).open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(proof, handle, indent=2);handle.write('\n')
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
