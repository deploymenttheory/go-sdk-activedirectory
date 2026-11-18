# Maintained RPC source and security changes

Reference: `oiweiwei/go-msrpc` at
`62c49e1e5992238091f95c7df7ea40775d9bd022` (MIT). Original license/module bytes
and exact retained/omitted identities are recorded in `UPSTREAM.json`.

The original parser/record red cases and intermediate isolated source remain in
`docs/research/portable-replication-evidence/`. Historical proof is not rewritten
or treated as live AD qualification.

- Retain only the AES record algorithm, with maintained GoKrb v8 imports. Reject
  profiles19/20 explicitly; no RC4/DES/NTLM, provider selection or fallback.
- Own copied keys and canonical AES17/18 implementations. Validate exact key
  sizes, role/subkey flags, sequence, outer and encrypted headers, rotation,
  lengths and MAC before publishing plaintext. Clear copied keys on retirement;
  redact formatting, JSON and structured logs. Key derivation stays private to
  locked record operations. Public algorithm flags are immutable constants.
- Replace the used transport and NDR boundary with small bounded SDK adapters;
  do not retain the vulnerable generic parser behind an outer fixture filter.
  Refuse short/oversized fragments, invalid authentication ranges, malformed
  unions/counts/UTF16, no-progress reads and short writes before unsafe access.
- Use raw three-leg DCE Kerberos authentication, validated AP-REP identity/time,
  explicit AES context keys and independent directional sequence ownership.
  A completed AP exchange alone does not establish RPC/application acceptance.
- Require header signing, Kerberos privacy and NDR32 on the selected interface.
  Protect every fragment and append mandatory verification-trailer commands
  binding the interface/transfer syntax and header-signing declaration. Keep the
  complete trailer in the final request fragment. An actual bind-interface
  substitution regression refuses dispatch despite a valid AP exchange.
- Serialize calls without multiplexing, retries or connection reuse after a
  fault. Validate call/presentation/security contexts and ordering, bound total
  stubs/fragments, ignore allocation hints and join real I/O and context causes.
  Cancellation closes the socket and joins callback completion before return.
- Preserve both measured I/O failures and context/close causes during retirement.
  Share one close-ownership token across bind and application phases. Treat RPC
  presentation rejection fields as unprotected negotiation metadata, distinct
  from cryptographically verified fault statuses.
- Decode only EPM map/free and DRS bind/unbind/GetReplInfo diagnostics. Preserve
  actual server status independently of transport/decoding errors and preserve
  nullable text, signed USNs, GUID bytes, queue order and valid partial prefixes.
  Endpoint-map tower addresses cannot redirect the selected host.
- Emit a zero allocation hint, as permitted by MS-RPCE, and validate response
  authentication-trailer alignment relative to the PDU body. Keep keyless
  observations separate: verified AP authentication does not imply a protected
  application reply, and a retired context cannot report complete protection.

The SDK dispatcher remains disabled pending live qualification. Default owned
socket tests and opt-in independent MIT packet interoperability establish only
the explicitly exercised offline boundaries. No omitted provider/protocol is a
supported capability.
