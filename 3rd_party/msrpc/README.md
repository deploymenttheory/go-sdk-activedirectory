# Maintained direct RPC diagnostic closure

This component derives its AES record source from the reviewed
[`oiweiwei/go-msrpc`](https://github.com/oiweiwei/go-msrpc) revision
`62c49e1e5992238091f95c7df7ea40775d9bd022`. The canonical MIT licence and
original module manifests are retained unchanged. `UPSTREAM.json` identifies
the two derived upstream files and every omitted canonical Git blob. The full
reviewed clone remains the local reference under `tmp/candidates/go-msrpc`.

The SDK owns the small `rpcdce`, `rpcwire`, `epmwire` and `drsrwire` adapters.
They implement one explicit Kerberos actor per TCP association, bounded NDR32
endpoint mapping and DRS diagnostic contexts, and confidential AES17/18 records.
They import the SDK's maintained GoKrb v8 source. There are no extra module
dependencies, process helpers, global mechanism registries or transport retries.
The upstream mapper, generic NDR decoder, multiplexed transport, credential
registry, SMB/HTTP transports and authentication providers are omitted.

Default tests exercise real sockets, malformed packets, authenticated refusals,
record tampering, fragmentation, cancellation and retirement. Canonical upstream
encoders produced the retained NDR fixtures. A separate Python implementation
produced AES record fixtures. Opt-in Linux tests use the installed MIT GSS library
solely as an independent offline acceptor, including actual RPC BIND/AUTH3 and
protected DRS bind/query/unbind packets. No SDK runtime launches that test peer.

These checks do not establish live AD support. The qualification branch enables
the SDK's normal public dispatcher for its real AD matrix after offline
packet/session review; release readiness still requires that complete evidence. Profiles19/20 are explicitly refused because their RFC8009 record
semantics have not been implemented and independently qualified here.
