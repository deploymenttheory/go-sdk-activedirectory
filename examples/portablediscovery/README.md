# Explicit portable discovery

This read-only command uses normal public SDK APIs. It optionally observes DNS
SRV candidates, requires an explicitly selected controller, authenticates that
one endpoint, verifies its AD domain/DC identity, then reads selected topology
projections on the same owning session. It has no Windows gateway, join-state
inference, authentication fallback or automatic candidate retry.

Supply one bounded JSON object through private stdin. This keytab example avoids
a password argument or committed credential payload:

```json
{
  "domain_dns": "example.test",
  "endpoint": "dc.disjoint.test:636",
  "lookup_dns": true,
  "dns_port": 389,
  "transport": "ldaps",
  "authentication": "kerberos",
  "source": "keytab",
  "username": "directory-reader",
  "realm": "EXAMPLE.TEST",
  "ldap_spn": "ldap/dc.disjoint.test",
  "keytab_path": "/private/reader.keytab",
  "ca_file": "/public/private-ca-root.pem",
  "projections": ["domain", "forest", "controller", "controllers"]
}
```

```sh
go run ./examples/portablediscovery < /private/discovery-input.json
```

The domain and controller hostname may use disjoint DNS namespaces. DNS is only
an advertisement: authenticated default NC, domain cross-reference and server/
DSA/computer relationships establish the selected identity. A host with multiple
advertised LDAP ports needs an explicit `dns_port`. DNS's LDAP port does not
silently select TLS; the caller's `transport` and optional endpoint port select
the authenticated connection. In the example, SRV advertises LDAP on 389 and
the caller independently selects LDAPS on 636 for that same host. The SRV
record remains 389 in the result; selecting DNS port 636 would require an actual
636 advertisement. No connection to 389 is attempted for LDAPS.
`lookup_dns: false` supports an explicitly known
DC without invoking any locator. Neither mode invents an SPN or realm.

`transport` accepts verified `ldaps` or `starttls`, and explicit Kerberos
`ldap-sign` or `ldap-seal`. `authentication: simple` requires `source: password`
and verified TLS. Kerberos accepts exactly one password, keytab or file-cache
source with explicit username, realm and LDAP SPN. Use `password_base64` only
from a protected producer through private stdin; base64 is not encryption.
The command never creates, rewrites or removes credential files and reads no
ambient cache. Private CA roots are optional; system trust is used otherwise.

Optional `expected_domain_guid`, `expected_domain_sid`, `expected_dsa_guid` and
`site_name` constrain the authenticated result. DNS site names must be literal
DNS labels; a direct LDAP site constraint can retain ordinary directory text.
Duplicate/unknown input fields, multiple JSON objects and oversized input fail
without echoing it. Clearing mutable input buffers cannot guarantee erasure of
immutable runtime copies.

The structured report preserves candidate/identity/topology completeness,
actual LDAP/Kerberos codes and measured protection. It excludes credentials and
raw error causes. `result` must name a fresh file; existing files are preserved.
Qualification builds set `-X main.buildRevision=<actual-commit>` and provide the
matching `source_revision`; mismatches fail before DNS or authentication.
`run_id` labels a fresh capture. A nonzero exit means the report is incomplete.

The implementation's owned wire tests are not live AD evidence. Consult the
[design and evidence boundary](../../docs/research/portable-discovery-design.md)
and #175 before claiming a qualified client/server profile. Native current-domain
and DC Locator variants remain documented separately; this command does not
claim full #78 or PowerShell cmdlet parity.
