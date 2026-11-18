# Portable Kerberos signing and sealing

Go 1.27.4 is required. Select `BackendPortable` and
`AuthenticationKerberos`, supply one explicit password, keytab or FILE cache,
and name the realm and exact `ldap/<endpoint-FQDN>` SPN. The backend does not
select an ambient cache, rewrite the realm/SPN, try another authentication
mechanism, or retry against another endpoint.

`SASLProtectionSign` authenticates subsequent LDAP bytes.
`SASLProtectionSeal` authenticates and encrypts them. A successful bind alone
does not establish either layer: the SDK requires mutual authentication, the
authenticated server offer, final LDAP acceptance, and installation of the
exact selected protection before returning a usable client.

| Transport | Requested protection | Required behavior |
| --- | --- | --- |
| LDAP | Default | Establish sealing |
| LDAP | Sign | Establish exactly signing |
| LDAP | Seal | Establish exactly sealing |
| LDAP | None | Reject the configuration before connecting |
| LDAPS / StartTLS | Default or None | Verify TLS and authenticate Kerberos with certificate binding |
| LDAPS / StartTLS | Sign or Seal | Reject incompatible AD configuration before credentials or network access |

An unavailable requested layer fails the connection. The backend does not
silently choose another layer, including a different stronger layer. TLS and
SASL are independent layers in the generic LDAP protocol. AD DS specifically
forbids a SASL traffic-protection layer on a TLS connection. Use verified TLS
with Kerberos and certificate binding, or plain LDAP with Kerberos signing or
sealing. An explicit unsupported combination returns `ErrInvalidConfig` before
credentials or network access, without dropping the requested layer. AD can
accept such a bind and then close the first protected application request;
bind acceptance does not establish a usable compound AD profile.
[MS-ADTS sections 5.1.2.1–5.1.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/284923c1-6a5b-4510-b97a-631963c0c3bd).

## Run the public example

[The Kerberos example](../examples/portablekerberos/main.go) accepts one bounded
JSON object through redirected stdin. Its `transport` can be `ldap`, `ldaps` or
`starttls`; `protection` can be `sign` or `seal`. For example, a protected FILE
cache request contains:

```json
{
  "endpoint": "dc1.ad.example.test:389",
  "transport": "ldap",
  "protection": "seal",
  "source": "cache",
  "username": "terraform-client",
  "realm": "AD.EXAMPLE.TEST",
  "spn": "ldap/dc1.ad.example.test",
  "cache_path": "/protected/terraform-client.ccache"
}
```

Run `go run ./examples/portablekerberos < request.json`. Protect credential
files with the operating system's file access controls. Password inputs use
`password_base64` in stdin; base64 is an encoding, not encryption. Keep password
requests in memory or a protected input source, and do not include passwords in
shell arguments or retained request files. The SDK does not create or renew
credential caches.

## Interpret measured protection

`Client.Protection` reports keyless observations:

- `SASLProtection` identifies the authenticated, installed layer.
- `SASLCipherBits` describes SASL confidentiality. Signing has zero cipher bits.
- `SASLEncryptionType` identifies the selected AES profile: 17/18 use
  AES128/AES256 with SHA-1, and 19/20 use AES128/AES256 with SHA-2.
- `CipherBits`, `TLSVersion`, `TLSCipherSuite` and `TLSVerified` describe TLS.
- `MutualAuthentication` records verified AP-REP authentication.
- `ChannelBindingSent` records certificate-derived binding emitted over TLS.
  Kerberos does not acknowledge whether the peer checked that binding;
  `ChannelBound` therefore remains unconfirmed. Server enforcement requires
  separate policy and negative-test evidence.
- `Complete` becomes false after retirement, cancellation or ticket expiry.
  Previously measured fields may remain available as partial observations.

Password operations require measured encryption of at least 128 bits. Plain
LDAP signing alone does not satisfy that requirement. Verified TLS or actual
SASL sealing may satisfy the protection check; directory permissions and
password policy still determine whether the operation is accepted.

## Failure and context ownership

The connection owns a copied derived key, authenticated initial counters and
negotiated token limits after bind. The mechanism's temporary context is then
deleted. Derived keys and buffered plaintext are cleared on retirement; copied
security contexts redact value/string/numeric formatting, JSON and structured
logs. These hooks do not sanitize direct field access or arbitrary reflection.
Managed runtime copies cannot provide a guarantee of complete memory erasure.

Every subsequent LDAP byte passes through the installed SASL stream. Tokens
enforce direction, key origin, the exact protection, sequence and negotiated
size. Fragmentation preserves those counters. Corruption, reordering, replay,
truncation, sequence exhaustion or unusable framing retires the socket. Sixteen
consecutive empty authenticated tokens also fail the progress bound.

Cancellation interrupts the underlying socket before waiting for dispatch.
Replacing the transport holds the request gate through the final bind boundary;
the previous reader cannot consume and discard protected octets. Establishing
another GSS context, or starting TLS after this GSS bind, requires a new client
connection.

A damaged response after submitting a mutation leaves the result uncertain.
The SDK preserves that state and closes the connection. Reconcile the target
by GUID using a separately established connection before deciding whether
another write is needed. There is no automatic mutation retry or rollback.

## Qualification

AD DS signing policy and a client sealing requirement are distinct. The lab
configures the server's supported signing requirement, then tests clients that
require either signing or sealing. It does not invent a server policy that
requires sealing for every LDAP operation.

The [protocol contract](research/kerberos-sasl-protection-contract.md) records
the implementation rules and primary specifications. Live claims require the
fresh Windows/Linux matrix for Server 2016/2019/2022/2025, source and binary
provenance, valid controls, fault injection and independent fixture cleanup.
Earlier native evidence, TLS/simple-bind runs and synthetic crypto vectors do
not qualify this Kerberos path.
