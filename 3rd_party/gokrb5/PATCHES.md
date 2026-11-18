# Local GoKrb changes

Basis: canonical `jcmturner/gokrb5` revision
`855dbc707a37a21467aef6c0245fcf3328dc39ed`, `v8/` subtree. Original file digests
are retained in `UPSTREAM.json`. Canonical license/notice bytes are unchanged.

1. **Root-module ownership.** Rewrite self-imports to the SDK-owned
   `3rd_party/gokrb5/v8` path. Retain original module files as provenance, without
   a nested module or replace directive.
2. **RFC8009 key sizes.** AES256/SHA384 has a 32-byte AES base/encryption key and
   24-byte MAC keys/tags. Fix the base/seed size without growing `Kc` or `Ki`;
   choose the 192-bit MAC derivation only for the corresponding five-byte usage
   labels. The string-to-key base stays 256 bits, and an empty arbitrary label
   cannot panic.
3. **RFC8009 PRF.** Convert the hash output size from bytes to bits before the
   KDF. Preserve the complete 32/48-byte PRF output rather than truncating it to
   4/6 bytes. Appendix A vectors pin both profiles.
4. **Authenticated decryption bounds.** Reject a wrong key size or ciphertext
   shorter than its confounder/tag before slicing or decrypting. SHA2 profiles
   authenticate ciphertext before decryption, as required by RFC8009. SHA1
   integrity verification also rejects short input safely. No unauthenticated
   plaintext is returned after a failure.
5. **Default verification.** Retain upstream RFC3962/RFC8009 and other offline
   unit vectors. Add all four AES profile checks (17/18/19/20), exact
   base/seed/MAC sizes, round trips, tampered tags, truncated input and wrong key
   sizes. Existing external-network test gates receive SDK-specific environment
   names; ordinary cryptographic/parser tests remain enabled.
6. **Literal error aggregation.** Use `errors.New` for an already-constructed
   aggregate message. This preserves literal percent characters and passes the
   latest Go vet checks without interpreting server-derived text as a format.


7. **Preserved error identity and checked KDC transport.** Wrap underlying errors
   with `%w` and expose `Unwrap` through the Kerberos error chain. Typed KDC,
   ASN.1 and configuration dispatch uses `errors.As` with the original predicates
   preserved. TCP reads use complete framing reads, reject responses over 16 MiB
   before allocation, and detect short writes. Regression tests cover fragmented
   headers, truncated replies, short I/O and wrapped cause identity. Empty
   principal and preauthentication configuration values are rejected before use.
8. **Untrusted password hints and bounded derivation.** Reject empty or malformed
   ETYPE-INFO/INFO2 and invalid parameter widths. Select only the requested
   encryption type's salt and parameters; an unrelated first entry cannot switch
   the algorithm or label a key incorrectly. AES `StringToKey` and
   `StringToKeyIter` reject iteration counts outside 1–1,048,576, including the
   all-zero encoding of 2^32, rather than reducing them. RFC3962 explicitly permits
   a work limit of at least 50,000. Retained vectors and all four AES profiles
   still run normally. Low-level PBKDF2 helpers remain explicit-caller functions.
9. **Credential and message decoder bounds.** Replace the ccache unchecked slices
   and count-derived allocations with an input-bounded reader and install state
   only after complete decoding. Keytab principal parsing checks errors, negative
   record skips are bounded, and timestamp/length conversions are checked. PAC
   buffer counts and offsets are bounded before allocation or slicing. Password
   reply envelopes validate fixed headers and nested lengths. Default regression
   tests and opt-in fuzz targets cover these hostile inputs.
10. **Retained API behavior.** JSON tags spell the existing exported field names;
    they do not rename the canonical payload. SPNEGO context values use a private
    key type and HTTP DNS resolution inherits the request context. Unnecessary
    RC4 `Reset` is removed without claiming it erased cipher memory. Checksum
    entry points reject invalid key sizes and failed checksums cannot validate
    empty inputs. Retained DES3/RC4 decoders reject truncated ciphertext before
    slicing, DES3 rejects empty padded input, and n-fold/legacy seed dimensions
    reject invalid input. These guards do not enable legacy SDK negotiation.
    Buffer assembly makes slice ownership explicit.
11. **Replay-test fixture isolation.** Parallel and repeated AP exchange tests
    share a client/service identity and the production replay-cache singleton.
    On coarse clocks, independent synthetic authenticators could have identical
    timestamp keys, so a test's first verification correctly returned a replay
    error. Allocate unique increasing microsecond timestamps in the test helper.
    Keep the original assertion that resubmitting the same AP request is rejected.
    Production authenticator generation and replay detection are unchanged.

References: [RFC8009 sections 3–6 and Appendix A](https://www.rfc-editor.org/rfc/rfc8009.html),
[RFC3962](https://www.rfc-editor.org/rfc/rfc3962.html).

Formatting uses Go 1.27.4 and the SDK formatter configuration. Long string
literals are split into concatenations without changing decoded values; a Go AST
check verified all 193 named string constants before and after this change.
Comments are wrapped separately, and every Go source line is at most 180
characters. `UPSTREAM.json` records the verification summary. These formatting
changes do not change protocol behavior or reassign historical qualification.

## Explicit SDK authentication policy (SDK-04)

The SDK selects `StrictRealm` and a caller context on an owned client. This mode
checks the reply's client identity and both service identities against the
explicit realm/SPN before caching a ticket. It requires a valid AES17–20 key,
ticket version, flags and actual lifetime; it refuses realm referrals and expired
cached tickets rather than silently renewing or selecting another identity.
`GetServiceTicketWithValidity` returns the actual cached lifetime and a copied
session key. Strict clients do not start automatic renewal goroutines. Copied
service-ticket values redact value/string/numeric formatting hooks and JSON.
Direct field access and arbitrary reflection remain outside those hooks.
Strict destruction clears owned session/cache key bytes after authentication
work stops; source keys and returned key copies retain independent ownership.
Password-derived temporary keys and serialized initiating authenticators are
cleared after use, without promising erasure of Go runtime or compiler copies.

KDC discovery, dialing and exchanges inherit cancellation. Cancellation closes
the owned socket and waits for its callback. The SDK uses its explicit DC FQDN
as KDC over TCP; it does not load ambient configuration or discover another
realm. The retained library API still supports context-aware SRV discovery.
Preauthentication checks empty ETYPE-INFO/INFO2 offers and selects an intersection
of the requested AES profiles, without deriving a legacy-profile password key.

The real authenticator factory allocates unique, process-wide microsecond
timestamps, including on coarse Windows clocks. Sequence randomness remains
unchanged. Allocation fails if it would exceed a one-second future bound; replay
cache detection is unchanged. AS/TGS/AP reply and error envelopes reject trailing
bytes or wrong protocol versions; AP reply/error microseconds are bounded.
Strict replies cannot select a key profile outside the actual request or exceed
its requested ticket lifetime.

TGS validation treats the TGT's original authentication time as historical, not
as the current KDC clock. An older currently valid ticket, including an omitted
start time, is not a clock-skew failure. Future start/authentication times remain
bounded by configured skew; expiration has no additional grace. The SDK uses
five minutes for future clock tolerance, without modifying the system clock.
Encrypted wire regressions retain valid older/future-within-skew controls plus
expired, invalid, far-future, foreign-principal, bad-nonce and profile refusals.
This correction was independently reproduced in unit fixtures; a prior transient
TGT-only lab failure was not causally attributed to it.

Owned real-socket AS/TGS tests retain cancellation, malformed-preauthentication,
principal, lifetime, key and nonce regressions alongside valid controls. These
tests do not substitute for the separate live Windows/Linux AD policy matrix.

References: [RFC4120 sections 3.1.5, 3.2.3 and 3.3.4](https://www.rfc-editor.org/rfc/rfc4120.html),
[RFC4121 section 7](https://www.rfc-editor.org/rfc/rfc4121.html#section-7).
