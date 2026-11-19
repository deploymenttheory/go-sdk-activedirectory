"""Retain only explicitly selected public SDK07/10 host captures; no lab calls.

Usage: python preserve-sdk0710-profile.py --config spec.json --sdk 07|10
       --destination <new-or-identical-evidence-directory>
The config pins original journals/audits. Captures come from the complete stage
journals and the independent audit input paths, never directory-wide discovery.
"""
import argparse
import datetime
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {'07': 'ebb11a2aae28187c72ec0ea665bb5fe02aa451ed',
           '10': '7c69c15ad3b959a76fe761e917dd11a55d93468e'}
SELECTORS = {'server': (0, 1), 'explicit-servers': (0, 2),
             'domain': (1, 2), 'forest': (2, 2), 'site': (3, 2)}


def read(path):
    return json.loads(Path(path).read_bytes().decode('utf-8-sig'))


def require(value, detail):
    if not value:
        raise ValueError(detail)


def immutable(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        require(path.read_bytes() == payload, 'Existing evidence differs: ' + str(path))
    else:
        with path.open('xb') as handle:
            handle.write(payload)


def save_json(path, value):
    immutable(path, (json.dumps(value, indent=2) + '\n').encode())


def verify_times(value):
    if isinstance(value, dict):
        if 'Ticks' in value and 'UTC' in value:
            ticks, utc = value['Ticks'], value['UTC']
            if ticks in (None, 0):
                require(utc is None, 'Unreported/zero FILETIME lost nullable UTC')
            else:
                match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?Z', utc or '')
                require(match, 'Invalid reported FILETIME UTC')
                delta = datetime.datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S') - datetime.datetime(1601, 1, 1)
                expected = (delta.days * 86400 + delta.seconds) * 10000000 + int((match[2] or '').ljust(7, '0'))
                require(ticks == expected, 'Actual FILETIME/UTC mismatch')
        for item in value.values():
            verify_times(item)
    elif isinstance(value, list):
        for item in value:
            verify_times(item)


def validate_replication(capture, client, scope, version):
    report = read(capture / 'result.json')
    require(report['success'] and report['source_label_matches'] and report['source_revision'] == SOURCES['07'], 'Replication actual source/success differs')
    require(report['platform'] == client + '/amd64' and report['toolchain'] == 'go1.27.4', 'Replication platform/toolchain differs')
    require(report['backend'] == 'portable' and report['credential_source'] == 'password' and report['transport'] == 'ldap-seal', 'Replication profile differs')
    require(read(capture / 'process.json')['exit_code'] == 0, 'Replication process failed')
    require([q['kind'] for q in report['queries']] == ['partners', 'failures', 'queue'], 'Missing/extra diagnostics')
    enum, count = SELECTORS[scope]
    observations, failures = 0, []
    for query in report['queries']:
        value = query['result']
        require(query['complete'] and value['Complete'] and value['Targets']['Complete'] and not query.get('error_class') and not query.get('statuses'), 'Incomplete aggregate diagnostic')
        selection = value['Targets']['Requested']
        require(selection['Scope'] == enum and len(value['Servers']) == count and bool(selection['Servers']) == (scope == 'explicit-servers'), 'Scope/controller selection differs')
        for i, server in enumerate(value['Servers']):
            observation = server['Observation']
            host = f'adsdk{version[2:]}dc{i+1}.ad.sdk.test'
            require(observation['Complete'] and observation['Endpoint']['Host'].casefold() == host and observation['Endpoint']['Port'] == 389, 'Observed selected controller differs')
            mappings = [entry for name, entry in selection['ServicePrincipals'].items() if name.casefold() == host]
            require(len(mappings) == 1, 'Ambiguous/missing explicit principal mapping')
            stages = observation['rpc_protection']
            require(len(stages) == 2, 'Missing/extra authenticated RPC stages')
            for j, stage in enumerate(stages):
                require(stage['stage'] == ['endpoint-map', 'drs'][j] and stage['service_principal'] == mappings[0]['endpoint_mapper' if j == 0 else 'drs'], 'Actual RPC stage/principal differs')
                require(stage['endpoint']['Host'] == observation['Endpoint']['Host'], 'RPC redirected selected host')
                require(stage['endpoint']['Port'] == 135 if j == 0 else 0 < stage['endpoint']['Port'] <= 65535, 'Invalid stage port')
                require(stage['realm'] == 'AD.SDK.TEST' and stage['encryption_type'] == 18 and stage['cipher_bits'] == 256, 'Actual stage realm/AES profile differs')
                require(all(stage[key] for key in ('mutual_authentication', 'header_signed', 'confidential', 'complete')), 'Incomplete actual RPC protection')
                require(datetime.datetime.fromisoformat(stage['expires_at'].replace('Z', '+00:00')) > datetime.datetime.fromisoformat(observation['RootDSE']['CurrentTime'].replace('Z', '+00:00')), 'Expired observed stage lifetime')
                observations += 1
            categories = ['Inbound', 'Outbound'] if query['kind'] == 'partners' else ['Connections', 'Links'] if query['kind'] == 'failures' else ['State']
            require(all(server[category][key] for category in categories for key in ('Requested', 'Available', 'Complete')), 'Incomplete requested category')
            verify_times(server)
            if query['kind'] == 'failures':
                failures.append({'host': observation['Endpoint']['Host'], 'rows': server['Failures']})
    verify_transfer(capture, client)
    return {'client': client, 'server_version': version, 'selection': scope, 'run_id': report['run_id'], 'credential_source': 'password', 'queries': 3, 'controllers': count, 'rpc_stage_observations': observations, 'failure_observations': failures, 'passed': True}


def verify_transfer(capture, client):
    if client == 'linux':
        transfer = read(capture / 'result-transfer.json')
        digest = hashlib.sha256((capture / 'result.json').read_bytes()).hexdigest()
        require(transfer['verified'] and transfer['remote_result_sha256'] == transfer['host_result_sha256'] == digest, 'Linux result transfer differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--sdk', required=True, choices=('07', '10'))
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    spec_path = Path(args.config).resolve()
    spec = read(spec_path)
    version = spec['server_version']
    require(version in ('2019', '2022'), 'Only explicitly reviewed 2019/2022 profiles accepted')
    lab = Path(spec['replication_lab_root']).resolve()
    discovery = Path(spec['discovery_lab_root']).resolve()
    require(lab == Path('H:/ad-sdk-lab/portable-replication').resolve() and discovery == Path('H:/ad-sdk-lab/portable-discovery').resolve(), 'Unexpected public lab roots')
    destination = Path(args.destination).resolve()
    expected_root = ROOT / f'tmp/worktrees/sdk-{args.sdk}/docs/research'
    require(destination.is_relative_to(expected_root.resolve()), 'Destination is outside the leased evidence tree')
    ledger = {}

    def preserve(source, relative):
        source = Path(source)
        require(source.is_file() and not source.is_symlink() and source.suffix in ('.json', '.txt', '.py'), 'Not an allowed public source: ' + str(source))
        require(not any(part.lower() in ('secrets', 'private') for part in source.parts), 'Private source directory refused')
        payload = source.read_bytes()
        immutable(destination / relative, payload)
        ledger[relative] = {'source': str(source), 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}

    def capture_files(capture, relative):
        capture = Path(capture).resolve()
        require(capture.is_relative_to(lab) or capture.is_relative_to(discovery), 'Capture escaped public root')
        for source in sorted(capture.iterdir()):
            require(source.is_file() and source.suffix in ('.json', '.txt'), 'Unexpected capture entry: ' + str(source))
            preserve(source, relative + '/' + source.name)

    baseline_path = Path(spec['baseline']).resolve()
    require(baseline_path.parent == lab and baseline_path.name.startswith('profile-power-' + version + '-'), 'Wrong explicit profile baseline')
    baseline = read(baseline_path)
    require(baseline['server_version'] == version and baseline['purpose'] == 'readonly-sdk07-sdk10-profile' and baseline['phase'] == 'started' and len(baseline['machines']) == 3, 'Invalid profile start journal')
    restoration = read(str(baseline_path) + '.restoration.json')
    require(restoration['verified'] and restoration['profile_id'] == baseline['profile_id'] and restoration['server_version'] == version and restoration['baseline'] == str(baseline_path).replace('\\', '/'), 'Profile restoration does not match baseline')
    require({item['Name']: item['state'] for item in restoration['after']} == {item['name']: item['original'] for item in baseline['machines']}, 'Original Windows power states not restored')
    require(len(restoration['process_observations']) == 3 and all(item['active_owned_sdk_processes'] == 0 for item in restoration['process_observations']), 'Owned SDK process remains active')
    for source in sorted(lab.glob(baseline_path.name + '*')):
        preserve(source, 'profile/' + source.name)
    moves = []
    for direction, move_name in zip(('start', 'restore'), spec['linux_moves']):
        move_path = (lab / move_name).resolve()
        require(move_path.parent == lab, 'Move escaped explicit public root')
        intent, result = read(move_path / 'intent.json'), read(move_path / 'result.json')
        require(result['verified'] and result['owner_id'] == intent['owner_id'] and result['state'] == intent['original_state'] == 'Running', 'Linux move ownership/state not verified')
        require(intent['from'] == ('2025' if direction == 'start' else version) and intent['to'] == (version if direction == 'start' else '2025') and result['profile'] == intent['to'], 'Linux profile not restored')
        capture_files(move_path, 'profile/linux-' + direction)
        moves.append({'intent': intent, 'result': result})
    require(len(moves) == 2 and moves[0]['intent']['owner_id'] == moves[1]['intent']['owner_id'], 'Linux ownership changed between moves')
    stages = []
    for client in ('windows', 'linux'):
        stage = read(str(baseline_path) + '.' + client + '-reads.json')
        require(stage['phase'] == 'complete' and stage['client'].casefold() == client and stage['server_version'] == version and stage['directory_mutations'] == 0 and all(row['exit_code'] == 0 for row in stage['calls']), 'Incomplete or mutating stage')
        stages.append((client, stage))
    coverage = {'source_revision': SOURCES[args.sdk], 'server_version': version, 'directory_mutations': 0,
                'profile_power_restored': True, 'linux_original_profile_state_restored': True,
                'full_sdk_matrix_complete': False, 'qualified_credentials': ['existing administrative password'],
                'qualified_application_protection': ['Kerberos AES18/256 SASL Seal'], 'cases': []}
    if args.sdk == '07':
        for client, stage in stages:
            rows = [row for row in stage['calls'] if row['sdk'] == '07']
            require([row['selection'] for row in rows] == list(SELECTORS), 'Missing/extra scope variants in stage')
            for row in rows:
                capture = Path(row['capture'])
                coverage['cases'].append(validate_replication(capture, client, row['selection'], version))
                capture_files(capture, client + '/' + row['selection'])
            for row in stage['calls']:
                if row['sdk'] == '07-native-reference':
                    capture_files(Path(row['capture']), 'windows/native-initial-domain')
        audit = read(spec['sdk07_stable_audit'])
        require(audit['pass'] and not audit['failed_checks'] and all(item['pass'] for item in audit['checks']) and not any(item['unexplained_differences'] for item in audit['comparisons']), 'Stable replication audit failed')
        for lane, item in audit['inputs'].items():
            payload = Path(item['path']).read_bytes()
            require(hashlib.sha256(payload).hexdigest() == item['sha256'] and len(payload) == item['bytes'], 'Audit input original changed')
            capture_files(Path(item['path']).parent, 'comparison-stable/' + lane)
        preserve(Path(spec['sdk07_stable_audit']), 'audit/stable-domain-comparison.json')
        for i, path in enumerate(spec.get('sdk07_prior_audits', [])):
            preserve(Path(path), 'audit/prior-domain-comparison-' + str(i + 1) + '.json')
        preserve(ROOT / 'tmp/audit-sdk07-profile-domain.py', 'tools/audit-sdk07-profile-domain.py')
        coverage.update(public_portable_queries=sum(row['queries'] for row in coverage['cases']),
                        server_diagnostic_reads=sum(row['queries'] * row['controllers'] for row in coverage['cases']),
                        actual_rpc_stage_observations=sum(row['rpc_stage_observations'] for row in coverage['cases']),
                        stable_domain_comparison_checks=len(audit['checks']),
                        additional_comparison_lanes_counted_in_base_queries=False)
        require(coverage['public_portable_queries'] == 30 and coverage['server_diagnostic_reads'] == 54 and coverage['actual_rpc_stage_observations'] == 108, 'Unexpected base query counts')
    else:
        for client, stage in stages:
            rows = [row for row in stage['calls'] if row['sdk'] == '10']
            require(len(rows) == 1, 'Missing/extra discovery stage')
            capture = Path(rows[0]['capture']);report = read(capture / 'result.json')
            require(report['source_revision'] == SOURCES['10'] and report['source_label_matches'] and report['success'] and report['toolchain'] == 'go1.27.4' and report['platform'] == client + '/amd64', 'Discovery source/platform/success differs')
            require(read(capture / 'process.json')['exit_code'] == 0, 'Discovery process failed')
            verify_transfer(capture, client)
            capture_files(capture, client)
            coverage['cases'].append({'client': client, 'server_version': version, 'run_id': report['run_id'], 'credential_source': 'password', 'projections': 4, 'passed': True})
        audit = read(spec['sdk10_audit'])
        require(audit['passed'] and not audit['failed_checks'] and not audit['unexplained_differences'] and all(item['pass'] for item in audit['checks']), 'Discovery native/Windows/Linux audit failed')
        require(len(audit['checks']) == 129, 'Unexpected discovery audit count')
        preserve(Path(spec['sdk10_audit']), 'audit/discovery-independent-comparison.json')
        preserve(ROOT / 'tmp/audit-sdk10-profile.py', 'tools/audit-sdk10-profile.py')
        coverage.update(independent_native_windows_linux_checks=129, public_client_calls=2,
                        complete_public_projections=8)
    preserve(Path(__file__), 'tools/preserve-sdk0710-profile.py')
    preserve(spec_path, 'tools/profile-preservation-spec.json')
    save_json(destination / 'coverage-audit.json', coverage)
    save_json(destination / 'artifact-hashes.json', ledger)
    print(json.dumps({'sdk': args.sdk, 'server_version': version, 'originals': len(ledger), 'directory_mutations': 0,
                      'windows_and_linux_restoration_verified': True, 'full_matrix_complete': False}))


if __name__ == '__main__':
    main()
