# Local LDAP changes

Base: official `go-ldap/ldap` revision
`a41b2a26f37f9bda6d29f97904389dd733dfea84` (`v3` module, upstream Go 1.26.0).
The SDK module requires Go 1.27.4. Original source hashes and the selected
extension source are recorded in [UPSTREAM.json](UPSTREAM.json).

## Packaging and existing LDAP behavior

- Rewrite LDAP self-imports to the SDK-owned `3rd_party/ldap/v3` path. Preserve
  the upstream MIT license, README, metadata, original module manifests, unit
  tests and LDIF fixtures. Dependency versions belong to the SDK root manifests;
  no nested module or `replace` is needed by consumers.
- Preserve upstream guarded packet-child, control and LDAPResult decoders.
  Upstream guards already reject malformed partial searches and wrong response
  operation tags; an older fork's decoder implementation is not substituted.
- Validate resultCode, matchedDN and diagnostic schema even on success. Check
  actual BER tag/class/type without truncating a tag before comparison. Check
  paging/search lengths and integer bounds before narrowing conversions. Retain
  optional absent-control semantics and valid controls in regression fixtures.
- Preserve error identity with `%w` instead of interpolated strings. Keep
  security/static/error analyzers enabled; protocol constant-name false positives
  and required legacy algorithms have local explanations. Apply repository Go
  formatting, LF and the 180-column limit.
- Bound definite-length LDAP BER to 16 MiB, nesting depth 32 and 262144 nodes
  before recursive decoding. Apply the same budget to recognized encoded control
  values. Reject malformed envelopes and unmatched response message identifiers
  immediately, with a sticky terminal error delivered to pending operations.
  Close on short request writes. A later expected-ID success cannot erase an
  earlier stream failure or turn an unknown write into an accepted write.
  Check primitive integer/enumeration lengths and boolean length before the
  upstream BER decoder can discard a parse error and substitute a zero value.
  Retain AD DirSync's fixed-width flag integer interoperability.
- Mark an error as an actual server result only after decoding a complete valid
  LDAPResult. A retained response packet can accompany a local parser error;
  its presence cannot turn the library's local status 200 into a server refusal.
  The SDK reports malformed submitted writes as uncertain with invalid-result
  classification and retires the connection.
- Validate complete operation-specific result tails, search-entry/value-set
  schemas, referrals and intermediate responses. Preserve valid optional Bind
  SASL credentials and Extended response names/binary values. Validate response
  control OIDs, optional flags/value shapes and known encoded values on a bounded
  wire clone before any success can be accepted; avoid mutating packets that the
  request-specific upstream decoder still owns. Reject invalid UTF-8 LDAPResult
  text while preserving arbitrary attribute and control value bytes.
- Gate only directory-dependent upstream tests behind explicit owned fixture
  endpoints and `ADSDK_VENDOR_LDAP_INTEGRATION=1`. Offline unit tests stay in the
  regular SDK suite; default runs never contact an example host or host RDP port.

## GSS context and protected framing prerequisites

SDK-04/05 add a keyless bind-result API without changing the legacy bind
signatures. It captures mechanism facts before context deletion, rejects early
LDAP success or an unaccepted layer selection, and requires the exported layer
to match the authenticated selection before installing its copied context.
SASL protection may operate above TLS as specified by RFC 4513 section 5.2.1.6.
Cipher strength describes only installed confidentiality; signing is not
reported as encryption. AP-REP acceptor subkeys require an exact supported AES
key size and the initiating profile; this client does not advertise RFC 4537
enctype renegotiation. Dedicated bind-result and subkey tests retain these
checks. These offline checks do not establish live policy qualification.

The SASL handoff now reserves an idle connection for the whole bind and keeps
the final-response request gate closed until replacement is installed. Exact
BER reads cannot discard prefetched protected octets. Transport snapshots and
replacement are synchronized with close; closing interrupts a blocked network
write before waiting for dispatch. Unbind waits for its actual PDU write before
retirement. A second GSS bind or post-GSS StartTLS is refused rather than
nesting layers or exposing an intermediate stream. TLS state remains observable
through an installed SASL layer.

Protected streams fail closed on AES-profile tampering, replay, ordering,
truncation, negotiated bounds or sequence exhaustion. Empty authenticated
tokens advance sequences but sixteen consecutive empty tokens fail progress
bounds. Failure clears owned keys after both I/O directions retire. Consumed
and retired plaintext buffers are cleared. Exported copied contexts redact
formatted, nested JSON and structured logs; keyless observations remain
separate. These rules have all-four-profile and concurrent byte-boundary tests.

The selected pure-Go framing/CBT extension concepts originate from
`jfjallid/ldap` revision `da9b2597489550e34b9be32649e09563e1607454`, with the
following owned changes. These are prerequisites for SDK-04/05. The SDK-02 engine
does not enable public Kerberos execution.

- Build and retain the initiating authenticator, including bounded sequence,
  timestamp, microseconds and initiator subkey. Verify AP-REP encryption and its
  binding to that timestamp/microsecond pair before accepting reply sequence or
  acceptor subkey. Initial counters never come from untrusted data tokens.
- Negotiate the RFC 4752 layer from the authenticated offer. Reject unoffered
  layers and unusable sizes; encode the no-security-layer selection as bit 1.
  Record the peer/local token limits and advance the counters consumed by the
  negotiation. Explicit protection is never silently disabled because TLS exists.
- Export copied established key/counter/size state only after authenticated
  negotiation. Record acceptor-subkey origin separately from initiator/session
  key fallback. Clear owned derived-key copies on context or connection retirement.
- Enforce RFC 4121 token direction, selected protection, key-origin flags,
  expected sequence and framing limits. Ignore unknown flag bits as required by
  the RFC. For sealed data, compare the authenticated decrypted header to the
  normalized outer header, including sequence, flags, EC and normalized RRC.
- Fragment outbound LDAP bytes into independently protected tokens that fit the
  negotiated peer token size. Enforce the local inbound size. Integrity, order,
  malformed framing or short-write failure poisons and closes the connection;
  later reads/writes cannot continue using the context.
- Derive RFC 5929 certificate hashes and RFC 1964 binding structures from the
  actual verified TLS state. The required MD5 structure digest has a precise
  protocol rationale and does not replace the certificate's SHA-2 hash. Checked
  length fields avoid truncation; unsupported certificate hashes fail.
- Permit TLS state observation through the SDK's owned connection wrapper. The
  library reader never takes ownership of an unverified simple-bind channel.
- Use the SDK-owned upstream Kerberos source and its RFC 8009 corrections. Four
  AES profiles require actual known-vector and protected-frame checks; reducing
  supported profiles to hide a key-size or derivation failure is unacceptable.

`security_context_test.go`, `channelbinding_test.go`, `kerberos_wire_test.go` and
`sasl_conformance_test.go` retain valid controls and protocol regressions.
`vendor_bounds_test.go` retains malformed-schema and integer-bound regressions.
Passing these tests does not establish a complete independent protocol review or
the required live AD matrix. Public Kerberos authentication, credential-source
handling, channel-binding interoperability and policy qualification remain
separate implementation and acceptance work.
