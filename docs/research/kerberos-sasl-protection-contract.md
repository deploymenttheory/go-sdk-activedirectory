# Kerberos SASL traffic protection contract

SDK-05 retains the authenticated per-message context after bind. This note is a
protocol implementation contract, not live Kerberos qualification evidence.

## Authentication and transport boundary

The mechanism owner verifies AP-REP mutual authentication, actual ticket expiry
and channel-binding use. It exposes a keyless authentication snapshot before
context deletion. The LDAP bind owner combines that snapshot with a complete
successful final LDAP BindResponse and the actually installed security layer.
Generating a signed layer selection is an intermediate state, not final bind
acceptance. Pending request processing stays suspended across the handoff.

SASL starts at the first byte after the successful final BindResponse. Preserved
reader bytes at that exact boundary must enter the new protected decoder. Any
SASL layer sits above an existing TLS layer, and the two protections act
independently. The implementation must neither erase an explicit signing/sealing
request because TLS exists nor send another LDAP operation before the requested
layer is installed. [RFC4513 sections 5.2.1.4–5.2.1.6](https://www.rfc-editor.org/rfc/rfc4513.html#section-5.2.1.4).

## Negotiation and observations

The authenticated four-octet server offer constrains the exact chosen layer and
peer token limit. The protected response contains one selection: no layer bit 1,
integrity bit 2, or confidentiality bit 4. Limits apply to protected output tokens;
plaintext may need fragmentation. Invalid offers, unsupported requested layers
and unusable limits fail the exchange. [RFC4752 sections 3.1–3.3](https://www.rfc-editor.org/rfc/rfc4752.html#section-3.1).

Public SDK enums and the owned LDAP library's enums have different values. Their
mapping is explicit. The existing public default means sealing over LDAP without
TLS, or no additional SASL layer on independently verified TLS. Requested policy
selects what is required; only authenticated selection, final acceptance and
installed framing establish the reported observation.

The key context export owns a copied established AES key, key-origin flag,
initial send/receive counters and token limits. The authentication snapshot holds
no key. Connection retirement clears owned derived-key copies. A closed, failed
or expired context never reports complete current protection.

## Protected stream

Each token authenticates direction, expected sequence, protection and key origin.
Unknown flag bits follow the RFC's receiver rules. Integrity mode authenticates
the payload and normalized header; confidentiality mode checks the protected
header copy after authenticated decryption. Rotation is interpreted modulo the
body length, including rotations larger than that length. Send counters advance
per protected token, rather than per LDAP message. [RFC4121 sections 4.2.1–4.2.6](https://www.rfc-editor.org/rfc/rfc4121.html#section-4.2.1).

A four-octet SASL length prefix frames each protected token. Reads must respect
fragmentation and coalescing without exceeding the negotiated receive limit.
Outgoing fragments must fit the peer limit. Integrity, ordering, malformed size,
truncation and short-write failures retire the connection; no later operation
may resume that stream. [RFC4422 section 3.7](https://www.rfc-editor.org/rfc/rfc4422.html#section-3.7).

Unit and wire tests must cover these boundaries with valid controls and adverse
cases. Live signing/sealing claims still require fresh Windows/Linux acceptance
against Server 2016, 2019, 2022 and 2025 with owned policy/account fixtures and
independent cleanup. The earlier TLS/simple-bind matrix and synthetic AES/GSS
vectors do not establish that result.
