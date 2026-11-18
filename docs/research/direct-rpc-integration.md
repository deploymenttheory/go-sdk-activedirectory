# Direct replication RPC integration basis

This SDK07 checkpoint retains a bounded RPC/record implementation under
`3rd_party/msrpc`. The public replication dispatcher remains unavailable for the
portable backend. Authenticated LDAP target discovery, explicit per-target/stage
principal integration and the Windows/Linux AD lab matrix remain required.
It does not complete issue172 or qualify an omitted upstream provider.

The maintained closure uses the existing owned GoKrb v8 implementation with no
new module dependencies. The complete reviewed upstream checkout remains the
reference; the licence, original module metadata and exact retained/omitted Git
identities are kept with the maintained code. Historical red cases and the
earlier isolated snapshot remain immutable in the replication evidence directory.

## Protocol boundaries

An explicit target has separate authenticated endpoint-map and DRS associations,
each with fresh actor, key and sequence ownership. A tower supplies only a bounded
TCP port, never a replacement host. The non-DC DRS principal is an explicitly
selected `ldap/<DNS host>` identity; authenticated endpoint mapping has a distinct
registered RPC identity. The eventual engine adapter must verify identities
against authenticated LDAP DSA/forest data and registered SPNs and fail partially
for a discovered peer without an explicit mapping. It must not guess identities.
See [MS-DRSR non-DC principals](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/894d0999-7d79-4e81-a407-7bcf6522b0a7)
and [endpoint mapping principals](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/599d1fe8-0549-4653-bdce-cb51965c19ae).

RPC authentication uses raw three-leg DCE Kerberos, verified AP-REP time/key
possession and explicit AES17/18 context profiles. RFC8009 profiles19/20 are
refused; their enum values do not establish the different record algorithm.
The established actor protects every subsequent header and fragment and checks
call/context/security identifiers and directional sequences. AP-REP alone does
not authenticate the RPC presentation result, so a bind rejection remains
unprotected negotiation metadata. Actual fault statuses are exposed only from
verified protected fault packets. See [MS-KILE DCE authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/190ab8de-dc42-49cf-bf1b-ea5705b7a087)
and [RFC8009](https://www.rfc-editor.org/rfc/rfc8009.html).

Mandatory verification-trailer commands bind the abstract/transfer syntax and
header-signing declaration. The complete trailer remains in the final fragment.
An actual modified-bind fixture proves the protected request is rejected before
dispatch when the advertised interface was substituted. See the
[MS-RPCE verification trailer](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/0e9fea61-1bff-4478-9bfe-a3b6d8b64ac3).

The NDR32 subset handles EPM map/free and DRS bind/unbind/version-one diagnostic
requests plus inbound neighbors, connection failures, link failures and pending
operations. It checks conformance, pointer presence, counts, union selection,
strict UTF16 and complete consumption before accepting a server status. Valid
record prefixes survive malformed later data; the association is retired.
Non-DC bind extensions keep epoch and configuration GUID zero and advertise only
the ignored BASE and mandatory POST_BETA3 bits. Server GET_REPL_INFO support must
be observed. See [DRS extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/3ee529b1-23db-4996-948a-042f04998e91).

## Evidence limits

Default tests use actual owned sockets, canonical upstream NDR encoder fixtures,
malformed packets, protected refusals, tampering, fragmentation, cancellation and
retirement. Separate Python AES fixtures exercise both sender roles. Opt-in
Linux tests use the installed MIT GSS acceptor with fresh synthetic tickets and
keytabs, including RPC BIND/AUTH3 and confidential DRS bind/query/unbind packets
for AES17 and AES18. The MIT peer is solely an offline test process; runtime code
does not launch helpers. These tests do not contact a KDC or AD and do not qualify
AD authorization, endpoint registration, topology discovery or any server matrix.
