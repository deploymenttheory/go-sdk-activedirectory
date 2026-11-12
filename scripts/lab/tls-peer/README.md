# Owned LDAP TLS test peer

This standalone, standard-library-only program is a lab fixture for issue #11.
It is outside the SDK runtime and is not a general LDAP server. It offers a
controlled leaf certificate, handles the LDAP StartTLS exchange, counts complete
BindRequest envelopes, and optionally forwards LDAP to a validated LDAPS server.
The observer without an upstream never manufactures successful bind responses.

Build from the repository root:

```powershell
go build -o tmp/tls-peer.exe ./scripts/lab/tls-peer
go test ./scripts/lab/tls-peer
```

Run generation inside the owned guest fixture directory, whose Windows ACL
restricts access to the fixture owner. Go's Unix permission bits do not replace
that ACL. The destination must not exist:

```powershell
.\tls-peer.exe generate -dir C:\OwnedFixture\tls-cases -server dc2.ad.sdk.test
```

Generation creates separate trusted and untrusted public roots, and four leaf
certificate/private-key pairs. Import only `trusted-root.pem` into the test
client's trusted root store. `valid.pem`, `expired.pem`, `wrong-host.pem`, and
`untrusted.pem` have matching `*-key.pem` files. Root private keys remain in
memory; leaf keys remain in the owned guest directory. `manifest.json` contains
only the FQDN and certificate SHA-256 hashes, validity dates, and DNS SANs.
The roots last seven days, valid leaves two days, and the expired leaf ended a
day before generation. Partial generation leaves the new directory for explicit
owner cleanup and cannot overwrite an earlier fixture on retry.

Start one isolated case with a numeric private or loopback listener address:

```powershell
.\tls-peer.exe serve -mode starttls -listen 172.23.1.12:0 `
  -cert C:\OwnedFixture\tls-cases\expired.pem `
  -key C:\OwnedFixture\tls-cases\expired-key.pem `
  -ready C:\OwnedFixture\expired-ready.json `
  -result C:\OwnedFixture\expired-result.json `
  -connections 1 -timeout 60s -connection-timeout 15s
```

`-mode ldaps` starts TLS immediately. `starttls` accepts only the extended
request OID `1.3.6.1.4.1.1466.20037`, replies success using the received message
ID, then starts TLS. A plaintext bind is counted and rejected. Parsing follows
the definite-length BER envelope and StartTLS definitions in
[RFC 4511 sections 4.14 and 5.1](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.14).
Long-form BER lengths, including WinLDAP's non-minimal four-byte length, work
across fragmented reads. This is deliberately a narrow framing observer, not
full validation of LDAP operation contents or controls.

The new readiness JSON contains `address` (including the actual allocated port),
`mode`, and `pid`. Readiness and result files are published complete using a
same-directory hard link with create-new semantics; use the owned local NTFS
directory and new paths for every run. No request payload, username, password,
private key, or raw network error text is logged. All command arguments are
nonsecret paths and fixture settings.

For the valid control, add an explicit upstream address, public root, and expected
certificate hostname. Both front-end modes connect to **LDAPS** upstream:

```powershell
.\tls-peer.exe serve -mode ldaps -listen 172.23.1.12:0 `
  -cert C:\OwnedFixture\tls-cases\valid.pem `
  -key C:\OwnedFixture\tls-cases\valid-key.pem `
  -ready C:\OwnedFixture\valid-ready.json -result C:\OwnedFixture\valid-result.json `
  -upstream dc2.ad.sdk.test:51301 `
  -upstream-ca C:\OwnedFixture\lds-service-public-root.pem `
  -upstream-name dc2.ad.sdk.test
```

The upstream must be a private/loopback numeric address or an `ad.sdk.test` FQDN
resolving exclusively to private/loopback addresses. The connection uses a checked
numeric address and the explicit TLS hostname. Only the supplied CA pool is used;
TLS 1.2 or newer and normal hostname/date/trust validation are required. No
upstream connection occurs until front-end TLS completes, and no LDAP bytes are
forwarded until upstream TLS validates. Requests and responses are relayed without
recording their contents. Use SIMPLE for the proxy control: this fixture does not
implement SASL framing or channel-binding identity equivalence between endpoints.

Result JSON includes:

- `configured_certificate`: the loaded leaf's `sha256`, `not_before`, `not_after`,
  and `dns_names`; the certificate is not evidence of a client connection by itself.
- `connections[].selected_certificate`: the leaf selected by `GetCertificate`,
  recorded even when client validation stops the handshake. Selection alone does
  not prove delivery. Tests compare it with the leaf received by an actual client.
- `handshake_complete`, `tls_version`, `cipher_suite`, and `starttls_accepted`.
- `bind_requests`, `plaintext_bind_requests`, `ldap_bytes_received`, and
  `ldap_bytes_forwarded` (actual client-to-upstream bytes accepted by TLS Write).
- `upstream_handshake_complete`, `upstream_certificate` after validation,
  `upstream_bytes_received` (response bytes relayed), and fixed error categories.
- `timeout_seconds`, `connection_timeout_seconds`, `connection_limit`, and
  `outcome`. `connection_limit` means the configured connections were handled,
  not that a certificate or directory operation succeeded.

There are at most 16 sequential connections, a ten-minute total lifetime, a
one-minute connection lifetime, 64 KiB per LDAP envelope, and 1 MiB forwarded in
each direction per connection. At most one additional 64 KiB request is read to
detect the receive cap. Default limits are one connection, 60 seconds total, and
15 seconds per connection. Deadlines and cancellation close stalled sockets.
Failed handshakes produce a result and normal process exit; fixture setup or
artifact publication failure produces exit 1 with a fixed diagnostic.

The tests exercise real Go TLS clients, both StartTLS framing and direct TLS,
all three rejection reasons, selected/received fingerprints, zero upstream
connections on rejection, a valid proxy bind/read wire control, invalid upstream
rejection, bounded waits, malformed envelopes, and payload non-disclosure. They
do not qualify WinLDAP/Schannel certificate validation or a live AD LDS instance;
the opt-in native guest runner and its paired peer artifacts supply that evidence.

## Native guest runner

Build the root package's Windows test executable and run only
`-test.run=^TestADLDSTLSLab$` once per peer case. Set `ADSDK_LDS_TLS_LAB=1` and
`ADSDK_LDS_TLS_RESULT` to a new nonsecret JSON path. Supply this object through
private redirected stdin, then close stdin:

```json
{
  "Server": "dc2.ad.sdk.test",
  "Port": 52000,
  "Transport": "ldaps",
  "Partition": "DC=fixture,DC=ad,DC=sdk,DC=test",
  "BindDN": "CN=fixture-user,DC=fixture,DC=ad,DC=sdk,DC=test",
  "Password": "<base64 of the owned fixture password>",
  "Marker": "ad-sdk-lds:<owned fixture identifier>",
  "ExpectFailure": true
}
```

`Transport` is `ldaps` or `starttls`. Never place the password in arguments or
environment variables. Input is capped at 16 KiB; mutable input and decoded
password buffers are cleared on exit. Malformed input yields only static test
diagnostics. The runner has a one-minute context and ten-second native network
timeouts; synchronous WinLDAP cancellation retains the SDK's documented limits.

With `ExpectFailure=false`, the runner requires a successful SIMPLE bind,
`Partition` read with the NC-head bit, and close. With `ExpectFailure=true`, it
requires a nil client and an error wrapping `ErrTLSNegotiation`, without context
expiry. The output records `passed`, `server`, `port`, `transport`,
`expect_failure`, `dial_succeeded`, `tls_negotiation_error`, `context_expired`,
`partition_read`, optional `partition`/`instance_type`, and
`native_errors: [{"kind":"ldap"|"win32","code":number}]`. It never records
the bind name, password, raw error text, native diagnostics, or matched DNs.

Pair both artifacts before qualifying a negative certificate case: the SDK must
reject the connection, the peer must select the expected leaf fingerprint, and
the peer must record zero bind requests and zero forwarded LDAP bytes. Require a
successful valid-certificate bind/read through the same proxy setup first. A
failed SDK Dial alone could also mean a network failure and does not qualify a
certificate rejection case.
