# Portable replication diagnostics

Build with the latest stable Go version. This example uses normal public SDK
configuration and replication functions; it has no injected backend or gateway.
This feature branch enables the portable dispatcher for the real AD matrix after
offline packet/session review. Live qualification and release readiness remain
pending; source enablement is not evidence of AD authorization or interoperability.

Supply one JSON object through private redirected stdin. Do not put passwords in
arguments, logs or a committed input file. `password_base64` is the JSON encoding
of the exact password bytes; base64 is not encryption. Prefer a caller-owned
keytab or FILE cache when possible. The program never generates, modifies or
removes credential files and never reads an ambient default cache.

```json
{
  "backend": "portable",
  "endpoint": "dc1.example.test",
  "transport": "ldaps",
  "source": "keytab",
  "username": "diagnostic-reader",
  "realm": "EXAMPLE.TEST",
  "ldap_spn": "ldap/dc1.example.test",
  "keytab_path": "/private/diagnostic-reader.keytab",
  "ca_file": "/public/lab-root.pem",
  "scope": "server",
  "kind": "all",
  "service_principals": {
    "dc1.example.test": {
      "ldap": "ldap/dc1.example.test",
      "endpoint_mapper": "RPC/11111111-2222-3333-4444-555555555555._msdcs.example.test",
      "drs": "ldap/dc1.example.test"
    }
  }
}
```

Replace the sample RPC identity with the explicitly selected principal actually
registered on that DC's computer account. Its DSA GUID and forest must match
authenticated LDAP observations. An additional selected server needs its own
mapping; the SDK never invents one or reuses the anchor identity for a peer.

`transport` accepts `ldaps`, `starttls` or `ldap-seal`. TLS verifies hostname and
trust before LDAP authentication; direct RPC independently requires Kerberos
mutual authentication, header signing and confidential AES17/18 records.
`source` accepts `password`, `keytab` or `cache`, with only the matching explicit
credential input. `kind` accepts `partners`, `failures`, `queue` or `all`.
`scope` accepts `server`, `domain`, `forest` or `site`, with the corresponding
optional `servers`, `domain_dns`, `forest_dns` or `site_name` selection.

The JSON report preserves complete/partial results, actual protocol statuses and
per-stage measured RPC protection facts. It excludes credential inputs and raw
error causes. `result` optionally names a fresh report path created with
exclusive creation and private permissions. Qualification builds set
`-ldflags '-X main.buildRevision=<actual-commit>'` and supply the matching
`source_revision`; a mismatch fails before authentication.

A Windows-only independent native reference can explicitly select
`backend: native`, `source: password`, an explicit account/domain and protected
`ldap-seal` transport. Omit portable principal mappings, keytab/cache paths and
custom CA trust. Native results do not establish portable RPC protection facts.

Failure/queue queries require replication-monitoring authorization on the
default naming context. Microsoft defines the
[Monitor Active Directory Replication right](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/05a37882-3381-4b4f-b167-d945a1234bf3)
as `f98340fb-7c5b-4cdb-a00b-2ebdfa115a96`. The
[DRS access checks](https://learn.microsoft.com/en-ca/openspecs/windows_protocols/ms-drsr/caa21197-11be-4efe-b9ae-35477ee68c8c)
also accept the manage-topology right. The example never grants either right.
An administrator's positive result does not qualify a least-privilege delegation.
