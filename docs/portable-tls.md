# Portable LDAPS and StartTLS

The portable transport establishes TLS before LDAP credentials or application
requests. LDAPS starts TLS immediately after connection; StartTLS first sends one
bounded LDAP extended request and accepts only its matching successful response.
A refusal, malformed response or failed handshake closes the connection.
There is no plaintext retry or certificate-verification bypass.

The portable LDAP session uses this verified transport for explicit simple
bind. Fresh Go 1.27.4 acceptance passed on Windows/amd64 and Linux/amd64 against
Server 2016, 2019, 2022 and 2025. See the
[recorded TLS qualification](research/portable-tls-validation.md) for exact
source identity, protocol observations and independent cleanup. Portable
Kerberos remains a separate authentication gate.

## Trust and negotiated protection

The peer must present a valid server certificate for the configured endpoint.
Verification checks its hostname, trust chain, validity period and server-auth
usage. TLS 1.2 is the minimum, and TLS 1.2 is restricted to ECDHE with AEAD suites.
The negotiated cipher must provide at least 128-bit encryption. TLS 1.3 uses
Go's authenticated cipher suites. Private roots are supplied explicitly through
`TLSOptions.RootCAs` and cloned; nil selects system trust.

These facts come from the completed TLS connection, including a verified chain,
negotiated version, suite and cipher strength. The transport does not assert
authentication success, mutual authentication, delegation or channel binding.
The session must establish and observe those facts separately after bind.
Callers check both the error and `SessionProtection.Complete`.

## Public example

`examples/portabletls` uses explicit simple bind, verifies TLS, inspects measured
protection and reads RootDSE once. It performs no directory mutation and accepts
no password argument. Supply exact UTF-8 password bytes through redirected stdin
from your secret source; whitespace is not trimmed.

```sh
go run ./examples/portabletls \
  -server dc1.example.test -transport ldaps \
  -ca private-root.pem -username automation@example.test < password-input
```

Use `-transport starttls` for LDAP's TLS upgrade. The optional `-port` overrides
the transport default without changing verification or selecting plaintext.
Omit `-ca` to use system trust. An empty password or bind name is rejected before
a connection is opened. Input bytes are cleared after dial; the SDK does not
retain the caller's credential structure.

`ErrTLSNegotiation` identifies failed protection establishment. `ErrConnection`
retains network and cancellation causes without inventing an LDAP server status.
Real StartTLS refusal status and structured diagnostics remain accessible through
`LDAPError`; its ordinary error text omits server diagnostics. A configured
deadline remains observable even if the socket timer runs before the context
timer. No failure is retried automatically.

## Verification scope

Owned TCP/TLS wire fixtures exercise both transports with TLS 1.2 and 1.3, a
private CA, hostname/expiry/trust/usage failures, TLS 1.1 refusal, interrupted
handshakes, malformed/refused StartTLS, and cancellation/timeout. They verify
close-once ownership, no extra bytes after StartTLS refusal, and measured TLS
state before application traffic. A bounded parser fuzz target exercises
untrusted BER without an LDAP client dependency.

The wire fixtures complement the fresh AD DS matrix; they do not replace it.
macOS and Windows/arm64 build coverage does not qualify live execution on those
platforms. Existing native/AD LDS artifacts remain historical and do not qualify
the portable backend. The new results cover this TLS/simple-authentication and
generic LDAP slice, without promoting the 151-operation inventory.

The sequencing follows [RFC 4511 section 4.14](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.14).
Cancellation and observed state use Go's [HandshakeContext](https://pkg.go.dev/crypto/tls#Conn.HandshakeContext)
and [ConnectionState](https://pkg.go.dev/crypto/tls#ConnectionState) contracts.

## Fresh lab qualification

`portable-qualification.ps1` uses one active private-CA DC fixture for the public
TLS example path and SDK-02's actual LDAP collector. It provisions a fresh marked
OU, permits only marker-owned contacts, and independently reconciles live GUIDs
before removing the OU. Deleted-object tombstones are retained and reported.
The same binaries run on Windows/amd64 and Linux/amd64 against one server profile
per invocation. The existing private profiles share addresses; move the owned
Linux client with [portable-linux.ps1](../scripts/lab/portable-linux.ps1) before
changing the selected profile. The collector requires all three verified Windows
VMs already running and changes neither their power nor networking.

The Windows member hosts a bounded controlled TLS peer for expired, wrong-host
and untrusted leaves plus an explicit StartTLS refusal. Positive controls proxy
to the real DC through verified LDAPS. Client and peer observations must agree:
failed TLS has zero bind envelopes, plaintext binds, LDAP application bytes and
forwarded bytes. StartTLS refusal additionally requires actual client EOF with
zero subsequent bytes. These controlled negatives are labeled separately from
successful direct AD DS connections. An exact owned firewall rule permits only
the Linux address to this fresh peer executable and is removed independently.
Keys stay in the guest under an owner/SYSTEM-only ACL and are removed after use.

Compile with Go 1.27.4 from a committed source tree. Record the actual build
commit and the separately named SDK-02 baseline with
`scripts/lab/portable-source-provenance`; it verifies every production Go file
and module file byte-for-byte and records hashes of every tracked build input.
The binaries' SHA256 digests, public CA/leaf identities, client runtime versions,
server versions, protocol results and cleanup checks accompany each new capture.
No password is accepted as an argument or written to the capture. Both clients
receive bounded JSON through stdin; the Linux SSH bridge is orchestration only.
Managed runtime/string copies cannot promise complete secret memory erasure.

Run the offline fixture ownership checks before using the collector:

```powershell
./scripts/lab/test-portable-fixtures.ps1
./scripts/lab/test-portable-linux.ps1
```

Invoke `Get-Help ./scripts/lab/portable-qualification.ps1 -Full` for the binary
and immutable source arguments. Each invocation creates a fresh capture under
`H:/ad-sdk-lab/captures`; a failed or incomplete cleanup remains a failed run.
Historical captures and coverage inventory states are unchanged.

Actual AD DS domain-root subtree searches can return subordinate naming-context
references even alongside matching entries. The portable session reports those
as incomplete and does not follow another endpoint automatically. Qualification
uses the isolated profile's explicit Users, Domain Controllers and Deleted
Objects containers for paging, SPN ranges and the owned tombstone lookup. This
keeps complete-result assertions meaningful without discarding referrals.
