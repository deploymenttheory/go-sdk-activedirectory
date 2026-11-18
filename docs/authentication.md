# Backend and authentication contracts

The public connection contract is available through
`activedirectory/config`, with convenience aliases at `activedirectory`.
Consumers need no SDK internal, protocol implementation or Win32 imports. The
module requires the latest stable Go release, currently Go 1.27.4. Native calls
retain `go-bindings-win32 v0.7.0`; portable protocol sources are pinned and owned
under [`3rd_party`](../3rd_party), including their licenses and patch ledgers.

## Backend selection

`Config.Backend` selects one implementation for the entire connection:

| Backend | Behavior |
| --- | --- |
| `BackendNative` (zero value) | Existing Windows amd64/arm64 WinLDAP and SSPI behavior |
| `BackendPortable` | Explicit password/keytab/FILE-cache Kerberos with verified TLS and/or authenticated SASL protection; TLS simple bind remains supported |

There is no automatic backend, credential-source or authentication fallback.
Portable Negotiate is refused: current Windows identity is a native mechanism.
`AuthenticationKerberos` means Kerberos only and must never become NTLM,
Negotiate or simple bind. The native backend currently refuses this new
Kerberos-only contract and custom `TLSOptions`, rather than silently ignoring
them. Existing native Negotiate and TLS simple bind remain available through
their existing configuration.

Validation is portable and offline. A valid configuration proves only that its
inputs are consistent; it does not prove implementation availability, readable
credentials, valid tickets, negotiated protection or server permissions.

## Explicit Kerberos inputs

Every Kerberos request supplies a username without a realm suffix, a DNS realm,
and an explicit `ldap/<endpoint-FQDN>` service identity. The service principal's
host must match the configured DNS endpoint; an IP endpoint is rejected.
Nothing is inferred from host join state, environment variables or an ambient
credential cache.

```go
options := config.Config{
    Backend:        config.BackendPortable,
    Endpoint:       config.Endpoint{Host: "dc1.example.test"},
    Transport:      config.TransportLDAPS,
    Authentication: config.AuthenticationKerberos,
    Kerberos: &config.KerberosCredentials{
        Source:   config.KerberosKeytabFile,
        Username: "automation",
        Realm:    "EXAMPLE.TEST",
        SPN:      "ldap/dc1.example.test",
        KeytabPath: "/run/secrets/automation.keytab",
    },
}
err := options.Validate() // no file access, ticket acquisition or network I/O
```

Choose exactly one source:

| Source | Required material | Other source fields |
| --- | --- | --- |
| `KerberosPassword` | Nonempty caller-owned UTF-8 `Password` bytes | `KeytabPath` and `CachePath` empty |
| `KerberosKeytabFile` | Explicit `KeytabPath` | `Password` nil and `CachePath` empty |
| `KerberosCredentialCacheFile` | Explicit `CachePath` | `Password` nil and `KeytabPath` empty |

File paths name ordinary caller-owned files. Cache schemes, implicit cache
discovery and SDK-written credential files are outside this contract. Files are
bounded to 16 MiB. The portable backend verifies their contents, exact client and
realm, ticket lifetime and service identity before use; syntax validation does
not perform those checks. A FILE cache requires a currently valid TGT and may
also contain the selected LDAP service ticket. Unrelated service entries are
not used. An expired selected credential is refused without cache renewal or a
different credential source. `Config.Credentials` and `Config.Kerberos` cannot
be combined.

The explicit LDAP DC FQDN is also the KDC endpoint on TCP port 88. The caller's
realm and service principal remain unchanged. There is no ambient `krb5.conf`,
reverse-DNS canonicalization, alternate realm/SPN, KDC UDP retry or automatic
ticket-renewal goroutine. This contract requires a DC offering Kerberos; an
LDAP proxy or AD LDS member with no KDC on that endpoint is not equivalent.
Kerberos credential network exchanges start after the requested TLS channel
has been verified. The supported crypto profiles are AES17–20; legacy RC4/DES
APIs retained in the owned dependency are never authentication fallbacks.

Value, string and numeric formatting hooks, JSON/text serialization and structured
`slog` logging redact the entire Kerberos input, including identities and file
paths. Reflection, direct field access and invalid pointer-format diagnostics
are outside those hooks; callers must not log credential fields themselves.
Callers own their input bytes/files and
must not mutate them during `Dial`. The returned client strips the credential
inputs. A backend may retain derived context keys until `Close` to protect SASL
traffic; neither Go nor third-party libraries provide an absolute erasure
guarantee for every copy. The SDK does not write credential caches or log secrets.

## Protection requests and observations

TLS and SASL are independent protection layers. `TLSOptions.RootCAs` allows a
private trust pool for portable TLS. The pool is cloned before backend retention;
nil selects system roots. TLS 1.2 or later, chain verification and endpoint-name
verification are mandatory; no skip-verification or server-name override is
provided. TLS must be established before simple-bind credentials are submitted.
Empty-password or anonymous simple bind is rejected.

`SASLProtection` selects `Default`, `None`, `Sign` or `Seal`. Explicit layers
require Kerberos. Without TLS, `None` is rejected and portable `Default` requires
sealing. With TLS, portable `Default` may rely on the verified TLS channel without
a SASL layer. Active Directory does not support compound TLS plus SASL Sign/Seal.
`Config.Validate` refuses that combination with `ErrInvalidConfig` before
credential loading or network I/O, without replacing the requested layer with
None. Choose verified TLS with None/Default, or plain LDAP with required
Sign/Seal. A successful bind by itself does not prove that subsequent protected
LDAP traffic will work.
The generic owned LDAP fixtures retain compound-layer protocol tests separately
from AD interoperability. See [MS-ADTS Using SASL](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/284923c1-6a5b-4510-b97a-631963c0c3bd).
Kerberos over TLS always includes RFC5929 `tls-server-end-point`
binding derived from the actual verified leaf certificate; there is no public
channel-binding opt-out. Unsupported certificate hash algorithms fail before
ticket acquisition instead of omitting the binding. Portable simple bind
uses verified TLS and reports `SASLProtectionNone`; it makes no Kerberos, mutual
authentication, channel-binding or delegation claim.

`client.Protection(ctx)` returns `shared.SessionProtection` through the same
bounded operation gate and lifetime as directory calls. It reports measured TLS,
SASL, authentication, mutual-authentication, channel-binding and delegation facts.
Check both the error and `Complete`; partial facts remain available on failure,
but `Complete` is false after an error or cancellation. A port number, requested
configuration or successful bind is never substituted for an observation.

`ChannelBindingSent` means the certificate-derived binding was emitted in the
actual authenticator. `ChannelBound` remains unconfirmed, represented by false:
Kerberos does not acknowledge whether the acceptor verified identical bindings,
even with mutual authentication. It must not be interpreted as a discovered
server policy or proof that no binding was used. `Complete` means the backend
collected its locally observable transport/authentication facts; it does not
turn an unobservable peer-enforcement policy into a known fact. See
[RFC4121 section 7](https://www.rfc-editor.org/rfc/rfc4121.html#section-7).

`CipherBits` measures TLS encryption. `SASLCipherBits` and `SASLEncryptionType`
describe the installed SASL context; Sign has zero encryption bits. Password
operations require measured TLS or Seal with at least 128 encryption bits.
Signing alone cannot satisfy that encryption requirement. Sequence, integrity,
framing or negotiated-size failures retire the connection; they do not trigger
a weaker layer, credential retry or LDAP mutation replay.

Backends without the optional observer return `ErrBackendUnavailable`. The
existing native password and cross-domain-move protection observations are
unchanged; the new general observer is not yet implemented by that backend.

## Errors and connection ownership

Check precise errors before the legacy umbrella:

```go
switch {
case errors.Is(err, ad.ErrUnsupportedDirectory):
    // The connected server's advertised directory type cannot provide it.
case errors.Is(err, ad.ErrBackendUnavailable):
    // The selected implementation or host mechanism is unavailable.
case errors.Is(err, ad.ErrUnsupported):
    // Legacy broad unsupported condition; inspect the detailed cause.
}
```

`BackendUnavailableError` retains the selected backend, authentication method
and refused feature without credential diagnostics. It matches
`ErrBackendUnavailable`, the legacy `ErrUnsupported`, and `ClassUnsupported`;
it does not match `ErrUnsupportedDirectory`. Configuration errors remain
`ErrInvalidConfig` / `ClassInvalidRequest`. Existing write uncertainty,
partial-result and cleanup semantics remain unchanged.

`KerberosError.Code` preserves a valid Kerberos protocol refusal separately from
`LDAPError.Code`. Ordinary error formatting excludes credential identities,
paths and server diagnostics. `ErrKerberosExpired` identifies a credential or
context outside its lifetime. The session uses the selected service lifetime
from the authenticated KDC reply or caller-owned FILE-cache metadata, retires
blocked operations at expiry and refuses later
submissions. A write already submitted before interruption keeps its recorded
accepted/rejected/uncertain outcome; expiry never authorizes a replay.
Future validity times tolerate the configured five-minute Kerberos clock skew;
expiration has no additional grace and the SDK never adjusts the system clock.

One composed client owns one endpoint-pinned session. Closing it closes every
resource module's access, cancels active operations, and releases the session
once. No backend replacement, referral reconnect, mutation replay or automatic
rollback is implied by this contract.

## Verification and live scope

Run the offline public example with `go run ./examples/authcontracts`.
Public-only consumer tests compile on Linux, macOS and Windows. Unit tests cover
source ambiguity, wrong service identities, forbidden downgrade requests,
credential redaction, trust ownership, unavailable backend selection, partial
protection facts, cancellation and close behavior.

Owned TLS/LDAP socket tests exercise actual simple-bind exchanges, binary values,
paging, critical controls, protocol refusals, partial reads, malformed responses,
lost write acknowledgements and cancellation. The opt-in `TestPortableLDAPLab`
collector exercises the actual portable client against the isolated lab; its
inputs and fixture ownership gates are documented in [portable LDAP](portable-ldap.md).
Owned KDC/GSS/TLS fixtures also exercise encrypted password preauthentication,
keytabs, TGT-only and populated FILE caches, mutual authentication, actual
certificate binding, exact Sign/Seal selection, expiry, key retirement and
post-bind directory traffic. The public stdin example is
[`examples/portablekerberos`](../examples/portablekerberos); it uses public SDK
calls and supports each explicit source. The private opt-in engine collector
injects only per-call CBT faults to prove genuine Always-policy refusals; it
does not add a public bypass. A linker source label is cross-checked with a
separately captured source/binary manifest rather than treated as proof by itself.

The public example and private collectors read one bounded JSON request from
stdin; they never require passwords in process arguments. Result paths use
exclusive creation and refuse to overwrite an earlier capture before any
authentication. `scripts/lab/kerberos-auth-cases.ps1` enumerates the nonsecret
per-profile matrix. The service-expiry probe requests a fresh, short KDC-issued
service ticket from a TGT-only cache, verifies its authenticated deadline, reads
before that deadline and waits for operation admission to refuse the expired
context. It never changes the clock or edits a ticket/cache lifetime.

Linux/Windows live evidence against Server 2016/2019/2022/2025 remains required
for applicable Kerberos and policy claims. The implementation and unit fixtures
alone do not satisfy that acceptance gate.
Existing native evidence does not qualify this backend, and no coverage inventory
state is promoted by these implementation changes.
The [retained SDK-02 validation](research/portable-ldap-validation.md) records
the completed TLS simple-bind matrix and its precise scope.
