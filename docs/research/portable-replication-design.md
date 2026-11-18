# Portable replication diagnostics

SDK-07 implements direct DRS/RPC diagnostics for inbound partners, connection
failures, link failures and pending operations. Outbound partners retain the
existing ranged LDAP path. This note records the implementation boundary and
candidate qualification; it does not establish portable AD interoperability.

## Existing observation contract

The existing [diagnostic contract](replication-diagnostics-contract.md) separates
successful counted empty results from denied, missing, malformed or interrupted
observations. The engine already retains each target and category independently,
including available records from an incomplete result. Native result fields,
nullable strings, FILETIME precision, unknown numeric values and queue order
must survive portable decoding. An omitted LDAP attribute cannot establish a
confirmed empty failure or queue result.

The current aggregation accepts only Negotiate before calling the native reader.
The final implementation will select an explicit backend at that same seam:
native behavior remains available; portable RPC requires explicit Kerberos and
authenticated packet privacy. There is no native/helper, mechanism, endpoint or
weaker-protection fallback. Scope expansion remains separate from per-target
diagnostics. The existing per-target error aggregation must not discard another
category's successful observations.

## Pinned candidate and executable gate

The reviewed reference is
[`oiweiwei/go-msrpc` at `62c49e1`](https://github.com/oiweiwei/go-msrpc/tree/62c49e1e5992238091f95c7df7ea40775d9bd022),
with MIT licensing. Its complete 7,889-file upstream checkout is retained as
the reference, with no tracked source changes. It supplies direct TCP RPC,
NDR and generated DRS protocol definitions. Its own Kerberos stack depends on
a separate v9 fork; that fork will not replace the SDK's qualified owned v8.
[Pinned module](https://github.com/oiweiwei/go-msrpc/blob/62c49e1e5992238091f95c7df7ea40775d9bd022/go.mod),
[DRS interface](https://github.com/oiweiwei/go-msrpc/blob/62c49e1e5992238091f95c7df7ea40775d9bd022/msrpc/drsr/drsuapi/v4/v4.go).

The [baseline qualification](portable-replication-evidence/candidate-msrpc/qualification.json)
retains the exact negative tests, actual failing log and SHA-256 values. Go
1.27.4 on Windows/amd64 executed the real AES record implementation and the
actual `net.Conn` RPC packet boundary. A valid encrypted record and a complete
wire-fragment control passed. The following gates failed:

- Signature lengths 0–15 panic before validation.
- A valid encrypted record is accepted with the wrong expected sequence.
- Altered token ID, sender role, sealed flag and key-origin flag are accepted.
- Wire fragments shorter than their common header are accepted.
- Authentication lengths outside the actual fragment cause parser panics.

These are observed baseline failures, not claims about an adopted SDK backend.
The candidate is not an SDK dependency, and portable RPC remains unavailable.
The used packet/session parser must pass the retained regressions after patching;
rejecting a particular fixture in an outer wrapper is insufficient.

## Owned implementation boundary

The tracked dependency closure will live under root `3rd_party/msrpc`, retaining
canonical license/module provenance, an exact retained/omitted file ledger, and
a patch ledger. The full upstream reference remains separate. Unused protocols,
SMB/HTTP transports and other authentication providers will not become qualified
by inclusion of the TCP diagnostic path.

Credentials and mechanisms belong to one call, using the SDK-owned v8 credential
loader and validated ticket lifetime. No process-global credential registry or
default-provider fallback is permitted. RPC discovery is untrusted routing
metadata; an endpoint-mapper result must never redirect authentication to another
host, protocol or interface. Actual context establishment and authenticated
traffic determine reported protection, rather than requested flags.

The retained RPC implementation needs bounded fragment and total-response sizes,
bounded NDR counts/pointers/strings, strict authentication trailer validation,
full reads, checked writes and ordered authenticated fragments. Cancellation,
malformed input, integrity failure or connection loss must retire the connection.
RPC faults and DRS return statuses remain distinct from Go transport errors.
Only authenticated status data can establish confirmed server refusal.

The DRS adapter must preserve pointer presence independently of an empty string;
generated string fields alone cannot represent that distinction. Each requested
category retains its own status and completeness. Wrong unions, inconsistent
counts, unfinished deferred pointers and trailing malformed content cannot turn
into healthy empty diagnostics.

## Qualification still required

Owned protocol, cryptographic and cancellation fixtures must establish the real
packet/session behavior first. SDK-04's full qualification remains a predecessor
gate for enabling/completing this feature. Fresh direct Windows/Linux client
captures against Server 2016/2019/2022/2025 must independently compare applicable
observations and exercise authentication refusal, authorization refusal, partial
categories and connection loss. Existing native or LDAP/Kerberos captures do not
qualify this new RPC backend. macOS and ARM64 remain build/unit coverage unless
separate live evidence is collected.
