# Direct replication RPC integration basis

This SDK07 checkpoint retains a bounded RPC/record implementation under
`3rd_party/msrpc`. The qualification branch enables the normal public replication dispatcher
for the portable backend after offline packet/session review. Authenticated LDAP DSA/computer identity binding, explicit
per-target/stage principal integration and complete owned-wire public workflows
are implemented. The Windows/Linux AD lab matrix remains required.
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
registered RPC identity. The engine adapter verifies identities against
authenticated LDAP DSA/forest data and registered SPNs and fails partially
for a discovered peer without an explicit mapping. It does not guess identities.
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

The engine uses the authenticated nTDSDSA GUID, its parent server's computer
reference and the computer's complete ranged SPN values. It validates the
explicit mapping before credential loading, then uses a new owned credential
client and key/sequence context for each RPC stage. A tower cannot replace the
selected host. RPC record profiles19/20 are refused; a single TGS request offers
only implemented record profiles18/17, without retrying a failed or cached
unsupported profile. The strict explicit-realm policy and refusal of referrals
remain in force for discovered peers.

The public reader workflows are exercised with real TLS LDAP, encrypted AS/TGS,
endpoint-map and DRS sockets for password, keytab and TGT-cache sources. Tests
verify successful/partial/refused categories, protected faults, malformed copied
prefixes, tamper, connection loss and cancellation. Independent outbound LDAP
data survives RPC failure. Unattempted categories do not borrow another query's
status. Per-stage keyless observations distinguish actual protected replies from
successful AP authentication alone. This source enablement does not establish live AD qualification.
Authenticated zero-count containers establish empty results. Endpoint-map
refusals preserve their actual status while unsubmitted DRS categories remain
incomplete. An empty mapping, malformed tower and damaged protected reply are
separate failures; none causes another endpoint attempt. Caller keytab/cache
bytes remain unchanged across the complete workflow.

## Evidence limits

Default tests use actual owned sockets, canonical upstream NDR encoder fixtures,
malformed packets, protected refusals, tampering, fragmentation, cancellation and
retirement. Separate Python AES fixtures exercise both sender roles. Opt-in
Linux tests use the installed MIT GSS acceptor with fresh synthetic tickets and
keytabs, including RPC BIND/AUTH3 and confidential DRS bind/query/unbind packets
for AES17 and AES18. The MIT peer is solely an offline test process; runtime code
does not launch helpers. These tests do not contact a KDC or AD and do not qualify
AD authorization, endpoint registration, topology discovery or any server matrix.

## Qualification-source enablement

Commit `fbca66dfaa262ff6b519f8be6fc9ff34625d3346` passed the complete Go1.27.4
Linux race suite from all 4,419 raw committed Git inputs, with both independent
MIT AES17/18 DCE and protected RPC lifecycle tests running. Windows full tests,
vet, lint and inventory checks also passed, as did Linux, macOS and Windows ARM64
cross-builds. These are offline checks. A subsequent local source switch enables
the public dispatcher specifically for the real AD matrix, with no public bypass
or injected runtime factory. An added exact-base-object DN guard strengthens the
portable nTDSDSA identity read while preserving the native helper's behavior.
The enabled source needs its own exact build/source proof and live results;
the earlier commit's tests are not relabelled as those results.
