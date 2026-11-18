# Backend and authentication contracts

The public connection contract is available through
`activedirectory/config`, with convenience aliases at `activedirectory`.
Consumers need no SDK internal or Win32 imports. The module uses the latest stable
Go release, currently Go 1.27.4, and retains `go-bindings-win32 v0.7.0`. This change
adds no portable protocol dependency.

## Backend selection

`Config.Backend` selects one implementation for the entire connection:

| Backend | Behavior |
| --- | --- |
| `BackendNative` (zero value) | Existing Windows amd64/arm64 WinLDAP and SSPI behavior |
| `BackendPortable` | Explicit portable LDAP selection; currently returns `ErrBackendUnavailable` before network or credential submission |

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
discovery and SDK-written credential files are outside this contract. A backend
must verify file contents, expected client identity, ticket expiry and service
identity before using a credential; syntax validation does not perform those
checks. `Config.Credentials` and `Config.Kerberos` cannot be combined.

Formatting, JSON/text serialization and structured `slog` logging redact the
entire Kerberos input, including identities and file paths. Exported fields can
still be deliberately read by a caller. Callers own their input bytes/files and
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
a SASL layer. Kerberos over TLS must bind its context to the server certificate;
there is no channel-binding opt-out in this contract. These requirements describe
what subsequent protocol implementations must enforce, not completed support.

`client.Protection(ctx)` returns `shared.SessionProtection` through the same
bounded operation gate and lifetime as directory calls. It reports measured TLS,
SASL, authentication, mutual-authentication, channel-binding and delegation facts.
Check both the error and `Complete`; partial facts remain available on failure,
but `Complete` is false after an error or cancellation. A port number, requested
configuration or successful bind is never substituted for an observation.

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

Live lab tests are not applicable to this contract-only change: it adds no
working portable session, credential exchange, TLS handshake, ticket acquisition
or SASL layer. Unsupported execution fails before contacting a directory.
Portable implementation and its actual-session fault tests belong to SDK-02;
TLS, Kerberos/channel binding and SASL qualification remain SDK-03 through SDK-05.
Linux/Windows live evidence against Server 2016/2019/2022/2025 is still required
for those protocol claims. Existing native evidence does not qualify a new
backend, and no coverage inventory state is promoted here.
