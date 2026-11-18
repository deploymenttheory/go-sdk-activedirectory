# Running the examples securely

Directory examples require an explicit server. The shared options default to
the portable backend, Kerberos from a caller-owned keytab, and verified LDAPS.
Supply an account, realm and credential path; no ambient cache, password argument
or authentication fallback is used.

```sh
go run ./examples/users -server dc1.example.test \
  -auth-user automation -auth-realm EXAMPLE.TEST \
  -auth-keytab /run/secrets/automation.keytab \
  -dn 'CN=Example User,OU=People,DC=example,DC=test'
```

Use a certificate whose name matches the server FQDN and whose issuing CA is
trusted. `-auth-ca /path/to/root.pem` supplies private roots for portable TLS
without changing system trust. There is no verification bypass.

| Shared option | Selection |
| --- | --- |
| `-auth-transport ldaps` | Verified TLS before authentication; default port 636. |
| `-auth-transport starttls` | Required, verified TLS upgrade on port 389. |
| `-auth-transport ldap-seal` | Kerberos mutual authentication and required SASL encryption on port 389. |
| `-auth-transport ldap-sign` | Kerberos mutual authentication and required SASL integrity on port 389. |
| `-auth-source keytab -auth-keytab PATH` | Explicit keytab; the default credential source. |
| `-auth-source cache -auth-cache PATH` | Explicit FILE cache with a valid TGT for the selected account and realm. |
| `-auth-user NAME -auth-realm REALM` | Required portable account and realm; the service identity is `ldap/<selected server>`. |

Signing protects integrity. Use verified TLS or sealing when the operation or
data needs confidentiality, including password changes. The SDK refuses a
connection when its requested protection cannot be established. Global catalog
connections use port 3269 for LDAPS and 3268 for the other protected profiles.
Examples with an explicit `-port` use 0 for the selected transport's default.

Some operations still require the native Windows backend. Select it explicitly
with `-auth-backend native`; it uses the current Windows identity with protected
Negotiate over verified LDAPS or StartTLS and the Windows trust store. Omit
portable credential and CA options for this route. Negotiate does not promise
Kerberos-only authentication. Backend selection never retries an unsupported
operation through another backend. See the operation guide for qualification
and the [authentication guide](../docs/authentication.md) for backend boundaries.

The dedicated [portable LDAP](portableldap/main.go),
[verified TLS](portabletls/main.go) and [AD LDS](lds/main.go) examples demonstrate
simple authentication over verified LDAPS/StartTLS. They read bounded password
bytes through redirected stdin. The [portable Kerberos](portablekerberos/main.go)
example takes a bounded stdin JSON object and demonstrates password, keytab and
cache sources with verified TLS or required SASL protection. See the
[SASL guide](../docs/portable-sasl.md). These dedicated examples use their own
documented inputs rather than the shared flags.

`passwords` reserves stdin for the requested password-change payload, so its
connection uses the shared keytab/cache options. Mutation acknowledgements,
readback and uncertain outcomes retain the operation examples' existing meaning.

Offline filter/condition/error demonstrations and local DC-cloning helpers do
not open a caller-configured LDAP session. They therefore have no LDAP
authentication flags. Cloning and local service-account operations retain their
documented host and Windows requirements.

The retained dependency examples follow the same transport requirements.
LDAP Godoc examples in `3rd_party/ldap/v3` use verified LDAPS or mandatory
verified StartTLS; simple credentials are a bounded stdin JSON object with
`bind_dn` and `password`. Password operations also read `old_password` and/or
`new_password`; the login-check example reads `user_name` and `user_password`.
Replace the example FQDN consistently and install your issuing CA in system
trust. EXTERNAL uses a private client certificate and an explicit CA bundle.
Windows SSPI derives channel binding from the verified TLS leaf.

The five `3rd_party/gokrb5/v8/examples` files are separate upstream commands;
build or run one file at a time. HTTP clients/services require HTTPS. Standalone
clients require explicit config, keytab, user and realm inputs; the service
requires private TLS and service-keytab files. The two self-contained
`example*.go` demonstrations use public upstream fixture keys and require that
isolated test KDC. Never install those published keys in a real directory.
