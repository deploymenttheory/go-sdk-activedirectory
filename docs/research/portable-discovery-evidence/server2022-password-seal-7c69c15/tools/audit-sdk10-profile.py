import argparse
import base64
import hashlib
import json
import re
import struct
import uuid
from pathlib import Path

root = Path(__file__).resolve().parent
lab = Path('H:/ad-sdk-lab/portable-discovery')
parser = argparse.ArgumentParser()
parser.add_argument('--windows-capture', required=True)
parser.add_argument('--linux-capture', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
paths = {'windows': Path(args.windows_capture) / 'result.json', 'linux': Path(args.linux_capture) / 'result.json'}
raw = {key: path.read_bytes() for key, path in paths.items()}
reports = {key: json.loads(value) for key, value in raw.items()}
reference = json.loads((paths['windows'].parent / 'independent-native-reference.json').read_text(encoding='utf-8-sig'))
checks, failed = [], []
def check(value, label):
    checks.append({'check': label, 'pass': bool(value)})
    if not value:
        failed.append(label)
def guid(value):
    return str(uuid.UUID(bytes_le=base64.b64decode(value)))
def sid(value):
    data = base64.b64decode(value)
    assert len(data) == 8 + 4 * data[1]
    return '-'.join(['S', str(data[0]), str(int.from_bytes(data[2:8], 'big')), *(str(x) for x in struct.unpack('<' + 'I' * data[1], data[8:]))])
def names(values):
    return sorted(value.casefold() for value in values or [])
native_controllers = {item['HostName'].casefold(): item for item in reference['controllers']}
for client, report in reports.items():
    check(report['success'] and report['source_label_matches'] and report['source_revision'] == '7c69c15ad3b959a76fe761e917dd11a55d93468e', client + ' exact source/success')
    check(report['platform'] == client + '/amd64' and report['toolchain'] == 'go1.27.4', client + ' actual platform/toolchain')
    check(not any(report.get(key) for key in ('error_class', 'identity_mismatch', 'ambiguous', 'no_candidates', 'ldap_status', 'kerberos_status')), client + ' no hidden identity/DNS/LDAP/Kerberos error')
    dns = report['dns']
    check(dns['Complete'] and dns['QueryName'] == '_ldap._tcp.dc._msdcs.ad.sdk.test.' and dns['CanonicalName'].casefold() == dns['QueryName'].casefold(), client + ' exact complete absolute SRV query')
    candidates = dns['Candidates']
    check(names(item['Endpoint']['Host'] for item in candidates) == sorted(native_controllers), client + ' exact two native controller candidate hosts')
    for candidate in candidates:
        host = candidate['Endpoint']['Host'].casefold()
        native = native_controllers[host]
        check(candidate['Endpoint']['Port'] == native['LdapPort'] == 389 and candidate['DomainDNS'] == 'ad.sdk.test', client + '/' + host + ' advertised LDAP port/domain')
        check(native['IPv4Address'] in candidate['Addresses'], client + '/' + host + ' independently reported IPv4 address present')
    identity = report['identity']
    check(identity['Complete'] and identity['Observation']['Complete'], client + ' complete authenticated identity')
    for key, expected in [('DomainDNS', 'ad.sdk.test'), ('DomainDN', reference['domain']['DistinguishedName']), ('DomainGUID', reference['domain_guid']), ('DomainSID', reference['domain_sid']), ('DSAGUID', reference['dsa_guid']), ('HostName', reference['controller']['HostName']), ('ServerDN', reference['controller']['ServerObjectDN']), ('DSADN', reference['controller']['NTDSSettingsObjectDN']), ('ComputerDN', reference['controller']['ComputerObjectDN'])]:
        check(identity[key] == expected, client + ' native identity/' + key)
    protection = identity['Protection']
    check(protection['Complete'] and protection['Backend'] == 1 and protection['Authentication'] == 2 and protection['Transport'] == 0, client + ' explicit portable Kerberos/LDAP protection')
    check(protection['MutualAuthentication'] and protection['SASLProtection'] == 3 and protection['SASLEncryptionType'] == 18 and protection['SASLCipherBits'] == 256, client + ' actual mutual AES256 sealing')
    check(not any(protection[key] for key in ('TLSVerified', 'ChannelBindingSent', 'ChannelBound', 'Delegated')), client + ' no TLS/CBT/delegation claim')
    check([item['kind'] for item in report['projections']] == ['domain', 'forest', 'controller', 'controllers'] and all(item['complete'] and not item.get('error_class') and not item.get('ldap_status') for item in report['projections']), client + ' exact four complete projections')
    projections = {item['kind']: item['result'] for item in report['projections']}
    for kind, projected in projections.items():
        check(projected['Observation']['Complete'], client + '/' + kind + ' complete original observation')
        check(projected['Observation']['Source']['Host'].casefold() == reference['server'] and projected['Observation']['Source']['Port'] == 389, client + '/' + kind + ' same explicitly selected owning session endpoint')
    domain = projections['domain']
    check(guid(domain['ObjectGUID']) == reference['domain_guid'] and sid(domain['ObjectSID']) == reference['domain_sid'], client + ' native domain GUID/SID byte decoding')
    for key in ('Name', 'DNSRoot', 'NetBIOSName', 'PublicKeyRequiredPasswordRolling'):
        check(domain[key] == reference['domain'][key], client + '/domain/' + key + ' native value')
    check(domain['ForestDNSRoot'] == reference['domain']['Forest'], client + '/domain native forest')
    for role in ('PDCEmulator', 'RIDMaster', 'InfrastructureMaster'):
        check(domain[role]['HostName'].casefold() == reference['domain'][role].casefold(), client + '/domain/' + role + ' native role owner')
    check(names(domain['SubordinateReferences']) == names(reference['domain']['SubordinateReferences']), client + '/domain native subordinate NC set')
    forest = projections['forest']
    check(forest['Name'] == reference['forest']['Name'] and forest['RootDomainDN'] == reference['domain']['DistinguishedName'], client + '/forest native name/root')
    for role in ('DomainNamingMaster', 'SchemaMaster'):
        check(forest[role]['HostName'].casefold() == reference['forest'][role].casefold(), client + '/forest/' + role + ' native role owner')
    check(names(item['DNSRoot'] for item in forest['Domains']) == names(reference['forest']['Domains']), client + '/forest native domain set')
    check(names(item['Name'] for item in forest['Sites']) == names(reference['forest']['Sites']), client + '/forest native site set')
    check(names(item['HostName'] for item in forest['GlobalCatalogs']) == names(reference['forest']['GlobalCatalogs']), client + '/forest native GC set')
    controllers = projections['controllers']
    check(not controllers['LimitReached'] and names(item['HostName'] for item in controllers['Controllers']) == sorted(native_controllers), client + ' complete native controller set/no limit')
    for item in [projections['controller']['Controller'], *controllers['Controllers']]:
        native = native_controllers[item['HostName'].casefold()]
        for key in ('IsReadOnly', 'IsGlobalCatalog'):
            check(item[key] == native[key], client + '/' + item['HostName'] + '/' + key + ' native state')
        check(item['Settings']['DistinguishedName'] == native['NTDSSettingsObjectDN'] and item['Server']['DistinguishedName'] == native['ServerObjectDN'], client + '/' + item['HostName'] + ' native DSA/server relationship')
    controller = projections['controller']['Controller']
    for key in ('Enabled', 'SiteName', 'OperatingSystem', 'OperatingSystemVersion'):
        native_key = 'Site' if key == 'SiteName' else key
        check(controller[key] == reference['controller'][native_key], client + '/controller/' + key + ' native value')
    check(guid(controller['InvocationID']) == reference['controller']['InvocationId'], client + '/controller native invocation GUID')
    check(guid(controller['ServerObjectGUID']) == reference['controller']['ServerObjectGuid'], client + '/controller native server GUID')
    check(names(controller['OperationMasterRoles']) == names(reference['controller']['OperationMasterRoles']), client + '/controller native role set')

def diff(a, b, path=''):
    if type(a) != type(b):
        return [{'path': path, 'windows': a, 'linux': b}]
    if isinstance(a, dict):
        result = []
        for key in sorted(set(a) | set(b)):
            if key not in a or key not in b:
                result.append({'path': path + '/' + key, 'windows_present': key in a, 'linux_present': key in b, 'windows': a.get(key), 'linux': b.get(key)})
            else:
                result.extend(diff(a[key], b[key], path + '/' + key))
        return result
    if isinstance(a, list):
        if len(a) != len(b):
            return [{'path': path, 'windows': a, 'linux': b}]
        return sum((diff(left, right, path + '/' + str(i)) for i, (left, right) in enumerate(zip(a, b))), [])
    return [] if a == b else [{'path': path, 'windows': a, 'linux': b}]

differences = diff(reports['windows']['identity'], reports['linux']['identity'], '/identity') + diff(reports['windows']['projections'], reports['linux']['projections'], '/projections')
unexpected = []
for row in differences:
    if re.fullmatch(r'.*/Observation/RootDSE/(?:CurrentTime|HighestCommittedUSN|Attributes/(?:currenttime|highestcommittedusn)/0)', row['path']):
        row['classification'] = 'non-atomic observed RootDSE time/USN change; both values retained'
        if '/Attributes/' in row['path']:
            row['windows_decoded'] = base64.b64decode(row['windows']).decode()
            row['linux_decoded'] = base64.b64decode(row['linux']).decode()
    else:
        row['classification'] = 'unexplained'
        unexpected.append(row)
check(not unexpected, 'Windows/Linux exact identity/projection structure/order/nullability except recorded temporal RootDSE fields')
proof = {'source_revision': '7c69c15ad3b959a76fe761e917dd11a55d93468e', 'scope': 'Windows/Linuxamd64 ' + reference['server'] + ' existing administrative password/AESSeal only', 'inputs': {key: {'path': str(paths[key]), 'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()} for key, value in raw.items()}, 'passed': not failed, 'checks': checks, 'failed_checks': failed, 'all_projection_differences': differences, 'unexplained_differences': unexpected, 'full_sdk10_matrix_complete': False, 'limitations': ['Native set comparisons preserve original collection wrappers; no native nullability equivalence is claimed.', 'Native functional-level strings are retained but not converted by an assumed enum mapping.', 'SDK-reported crypto facts are not independent packet decryption.', 'Other sources/protection profiles/server versions/architectures and provider release remain unqualified.']}
path = Path(args.output)
with path.open('x', encoding='utf-8', newline='\n') as handle:
    json.dump(proof, handle, indent=2)
    handle.write('\n')
print(json.dumps({'audit': str(path), 'passed': proof['passed'], 'checks': len(checks), 'failed': failed, 'unexpected_paths': [row['path'] for row in unexpected]}))
raise SystemExit(bool(failed))
