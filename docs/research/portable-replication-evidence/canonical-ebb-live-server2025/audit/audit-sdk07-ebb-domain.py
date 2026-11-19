import base64
import datetime
import hashlib
import json
import re
from pathlib import Path

root = Path(__file__).resolve().parent
base = Path('H:/ad-sdk-lab/portable-replication')
paths = {
    'windows-portable': base / 'sdk07-p25-20261119t010446173z/windows-portable-password/result.json',
    'windows-native': base / 'sdk07-p25-20261119t010446173z/windows-native-password/result.json',
    'linux-portable': base / 'sdk07-p25-20261119t010521227z/linux-portable-password/result.json',
}
raw = {name: path.read_bytes() for name, path in paths.items()}
values = {name: json.loads(data) for name, data in raw.items()}
checks, failures = [], []
def check(condition, label):
    checks.append({'check': label, 'pass': bool(condition)})
    if not condition:
        failures.append(label)

def differences(a, b, path=''):
    if type(a) != type(b):
        return [{'path': path, 'left': a, 'right': b}]
    if isinstance(a, dict):
        result = []
        for key in sorted(set(a) | set(b)):
            child = path + '/' + key
            if key not in a or key not in b:
                result.append({'path': child, 'left_present': key in a, 'right_present': key in b, 'left': a.get(key), 'right': b.get(key)})
            else:
                result.extend(differences(a[key], b[key], child))
        return result
    if isinstance(a, list):
        if len(a) != len(b):
            return [{'path': path, 'left': a, 'right': b}]
        return sum((differences(one, two, path + '/' + str(i)) for i, (one, two) in enumerate(zip(a, b))), [])
    return [] if a == b else [{'path': path, 'left': a, 'right': b}]

def nulls(value, path=''):
    if value is None:
        return [path]
    if isinstance(value, dict):
        return sum((nulls(item, path + '/' + key) for key, item in sorted(value.items())), [])
    if isinstance(value, list):
        return sum((nulls(item, path + '/' + str(i)) for i, item in enumerate(value)), [])
    return []

def verify_times(value, label):
    if isinstance(value, dict):
        if 'Ticks' in value and 'UTC' in value:
            ticks, utc = value['Ticks'], value['UTC']
            if ticks in (None, 0):
                check(utc is None, label + ' reported-zero/unreported time keeps null UTC')
            else:
                match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?Z', utc or '')
                check(match is not None, label + ' FILETIME UTC format')
                if match:
                    delta = datetime.datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S') - datetime.datetime(1601, 1, 1)
                    expected = (delta.days * 86400 + delta.seconds) * 10000000 + int((match[2] or '').ljust(7, '0'))
                    check(ticks == expected, label + ' exact FILETIME/UTC agreement')
        for key, item in value.items():
            verify_times(item, label + '/' + key)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            verify_times(item, label + '/' + str(i))

for name, report in values.items():
    check(report['success'] and report['source_label_matches'] and report['source_revision'] == 'ebb11a2aae28187c72ec0ea665bb5fe02aa451ed', name + ' exact source/success')
    check(report['platform'] == ('linux/amd64' if name.startswith('linux') else 'windows/amd64') and report['toolchain'] == 'go1.27.4', name + ' exact toolchain/platform')
    check(report['backend'] == ('native' if name.endswith('native') else 'portable') and report['credential_source'] == 'password', name + ' explicit backend/credential source')
    check([q['kind'] for q in report['queries']] == ['partners', 'failures', 'queue'], name + ' all three ordered diagnostics')
    for query in report['queries']:
        label = name + '/' + query['kind']
        result = query['result']
        check(query['complete'] and result['Complete'] and result['Targets']['Complete'] and not query.get('error_class') and not query.get('statuses'), label + ' complete scope/no hidden refusal')
        check(len(result['Servers']) == 2, label + ' both controllers retained')
        for i, server in enumerate(result['Servers']):
            tag = label + '/' + str(i)
            observation = server['Observation']
            check(observation['Complete'], tag + ' complete server observation')
            check(observation['Endpoint']['Host'].lower() == f'adsdk25dc{i+1}.ad.sdk.test' and observation['Endpoint']['Port'] == 389, tag + ' exact ordered endpoint')
            verify_times(server, tag)
            categories = ['Inbound', 'Outbound'] if query['kind'] == 'partners' else ['Connections', 'Links'] if query['kind'] == 'failures' else ['State']
            for category in categories:
                check(all(server[category][key] for key in ('Requested', 'Available', 'Complete')), tag + '/' + category + ' complete category')
            if not name.endswith('native'):
                stages = observation.get('rpc_protection', [])
                check(len(stages) == 2, tag + ' exactly two authenticated RPC stages')
                host = observation['Endpoint']['Host']
                selections = [value for key, value in result['Targets']['Requested']['ServicePrincipals'].items() if key.casefold() == host.casefold()]
                check(len(selections) == 1, tag + ' unambiguous explicit host principal map')
                if len(selections) != 1:
                    continue
                selected = selections[0]
                for j, stage in enumerate(stages):
                    principal = selected['endpoint_mapper' if j == 0 else 'drs']
                    check(stage['stage'] == ['endpoint-map', 'drs'][j] and stage['service_principal'] == principal and stage['endpoint']['Host'] == host, tag + '/' + str(j) + ' actual selected stage identity')
                    check(stage['realm'] == 'AD.SDK.TEST' and stage['encryption_type'] == 18 and stage['cipher_bits'] == 256, tag + '/' + str(j) + ' AES256/realm')
                    check(all(stage[key] for key in ('mutual_authentication', 'header_signed', 'confidential', 'complete')), tag + '/' + str(j) + ' complete mutual/header/confidential facts')
                    check(stage['endpoint']['Port'] == 135 if j == 0 else 0 < stage['endpoint']['Port'] <= 65535, tag + '/' + str(j) + ' bounded correct endpoint port')
                    expiry = datetime.datetime.fromisoformat(stage['expires_at'].replace('Z', '+00:00'))
                    observed = datetime.datetime.fromisoformat(observation['RootDSE']['CurrentTime'].replace('Z', '+00:00'))
                    check(expiry > observed, tag + '/' + str(j) + ' valid observed service lifetime')

comparisons = []
for peer in ('windows-native', 'linux-portable'):
    for a, b in zip(values['windows-portable']['queries'], values[peer]['queries']):
        rows = differences(a['result'], b['result'])
        unexpected = []
        for row in rows:
            path = row['path']
            if path == '/Targets/Requested/ServicePrincipals' or re.fullmatch(r'/Servers/\d+/Observation/rpc_protection(?:/.*)?', path):
                row['classification'] = 'explicit independently checked backend/session protection metadata'
            elif re.fullmatch(r'/(?:Servers/\d+|Targets)/Observation/RootDSE/(?:CurrentTime|HighestCommittedUSN|Attributes/(?:currenttime|highestcommittedusn)/0)', path) or re.fullmatch(r'/Servers/\d+/Partners/\d+/(?:LastObjectUSN|AttributeFilterUSN|LastSuccess/(?:Ticks|UTC)|LastAttempt/(?:Ticks|UTC))', path):
                row['classification'] = 'observed non-atomic temporal/USN change, both values retained'
                if '/Attributes/' in path:
                    row['left_decoded'] = base64.b64decode(row['left']).decode()
                    row['right_decoded'] = base64.b64decode(row['right']).decode()
            else:
                row['classification'] = 'unexplained'
                unexpected.append(row)
        check(not unexpected, peer + '/' + a['kind'] + ' no unexplained structural/ordered row/status differences')
        for i, (left, right) in enumerate(zip(a['result']['Servers'], b['result']['Servers'])):
            key = {'partners': 'Partners', 'failures': 'Failures', 'queue': 'Operations'}[a['kind']]
            check(nulls(left[key]) == nulls(right[key]), peer + '/' + a['kind'] + '/' + str(i) + ' every row nullable field position')
        comparisons.append({'peer': peer, 'kind': a['kind'], 'all_exact_differences': rows, 'unexplained_differences': unexpected})

proof = {'schema_version': 1, 'source_revision': 'ebb11a2aae28187c72ec0ea665bb5fe02aa451ed', 'scope': 'Windows/Linux25 administrative password/domain scope only; host-only independent public-JSON audit', 'inputs': {name: {'path': str(paths[name]), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in raw.items()}, 'pass': not failures, 'checks': checks, 'failed_checks': failures, 'comparisons': comparisons, 'limitations': ['Sequential observations are not an atomic snapshot; temporal changes retain both values.', 'Protection facts are SDK-reported, not independent packet decryption.', 'No other credentials, scopes, server profiles, least-privilege or provider release are qualified by this audit.']}
path = root / 'sdk07-ebb-domain-independent-audit-v2.json'
with path.open('x', encoding='utf-8', newline='\n') as handle:
    json.dump(proof, handle, indent=2)
    handle.write('\n')
print(json.dumps({'audit': str(path), 'pass': proof['pass'], 'checks': len(checks), 'failed': failures, 'unexpected_paths': [[row['path'] for row in comparison['unexplained_differences']] for comparison in comparisons]}))
raise SystemExit(bool(failures))
