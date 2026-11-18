# Portable LDAP sessions

Select `BackendPortable`, `AuthenticationSimple`, and either `TransportLDAPS` or
`TransportStartTLS`. Supply explicit nonempty credentials. The engine verifies
the chain and configured endpoint name with TLS 1.2 or later and an AEAD cipher
before submitting a bind. `TLSOptions.RootCAs` supplies a cloned private trust
pool; nil uses system trust. There is no certificate verification bypass.

The runnable [example](../examples/portableldap/main.go) accepts an endpoint and
CA path, and reads exact password bytes from redirected standard input. Callers
own their password bytes and can clear them after `Dial`. The returned client
does not retain the configuration's credential fields. Go and protocol-library
copies cannot provide a guarantee that every secret copy has been erased.

Portable Negotiate and portable Kerberos execution fail with
`ErrBackendUnavailable` before connecting. Kerberos configuration validation and
the owned protocol prerequisites do not establish working Kerberos sessions.
There is no authentication, backend, endpoint, referral or credential fallback.

## Session behavior

Every resource module shares one serialized, authenticated session. Search
preserves arbitrary attribute octets, including NUL, non-UTF-8 bytes, GUIDs and
SID values. Base reads require exactly one returned entry. Ranged reads retain
the returned attribute descriptions for the existing range collector; ordinary
search reports a returned range as incomplete. Portable typed filters use RFC
4515 octets and do not inherit WinLDAP's W-string extensible-value restrictions.

Paged searches use critical RFC 2696 controls. Cookies are opaque bytes and may
repeat while the server advances its cursor. Caller limits release the last
cookie with page size zero and the same query and controls. A failed bounded
release retires the session. Referrals are returned as incomplete observations;
the SDK does not connect to the referred server.
A valid terminal LDAP refusal can omit the paging response and ends that cursor
without replaying a request or retiring an otherwise valid connection.

Add, Modify, Delete and ModifyDN preserve critical controls and binary values.
An omitted control value remains different from an explicit empty value. The
assertion, permissive-modify and deleted-object workflows use the same boundary.
Missing controls are never retried with reduced requirements.

An acknowledged write is accepted; a valid LDAP refusal is rejected. A request
whose response is lost, malformed or interrupted is uncertain after submission,
even when a later read might discover its effect. Validation or cancellation
before submission remains not attempted. See [mutation outcomes](directory-objects.md)
and [errors](errors.md). Reconcile an uncertain result before submitting another
write; this backend never replays a write or performs automatic rollback.

The socket is bounded by the operation context and configured timeout.
Cancellation closes the owned transport before waiting for the library reader.
Malformed or failed transport exchanges retire the session, preventing further
use of an untrusted stream. Already returned objects remain available alongside
a nonnil error. Server diagnostics are accessible through `LDAPError` but are
omitted from its default error string.
Inbound LDAP frames and recognized encoded control values are bounded to 16 MiB,
32 nesting levels and 262144 BER nodes before recursive decoding. Malformed or
unmatched response identifiers terminate the stream immediately.

`client.Directory.Protection(ctx)` reports measured TLS version, cipher and key
size after the selected simple bind has succeeded. It reports no mutual
authentication, channel binding or delegation for simple bind. Always inspect
the error and `Complete` before relying on an observation.

## Source ownership and checks

The SDK owns the pinned [LDAP source](../3rd_party/ldap/README.md) and
[Kerberos source](../3rd_party/gokrb5/README.md). Upstream guarded decoders and
tests are retained; local changes and security prerequisites are listed in each
`PATCHES.md`. Source is included under the SDK module's import path, without a
nested module or local replacement that downstream module consumers would lose.
Use Go 1.27.4 or the current later stable release.

Ordinary `go test ./...` does not contact a directory. Upstream LDAP integration
tests require `ADSDK_VENDOR_LDAP_INTEGRATION=1`, `LDAP_TEST_URL` and
`LDAPS_TEST_URL`, pointing to an explicitly owned disposable fixture.

`go test -count=1 -run '^TestPortableLDAPLab$' ./activedirectory/acceptance` is
separately gated by the following collector inputs:

Automated remote collectors select `ADSDK_PORTABLE_LAB_INPUT=stdin` and supply
one strict JSON object through the test binary's standard input, bounded to
128 KiB. The fields are `endpoint`, `transport`, `ca_file`, `username`,
`password_base64` (base64 of exact UTF-8 password bytes), `run_id`,
`source_revision`, `result`, `allow_write` and `fixture_ou`. This mode uses no
environment fallback, does not echo the request, and clears its password byte
buffer after `Dial`. Keep credentials out of shell assignments and argument lists.

For manually managed local runs, the environment inputs are:

| Variable prefix `ADSDK_PORTABLE_LAB_` | Value |
| --- | --- |
| `ENDPOINT`, `TRANSPORT` | Explicit host:port and `ldaps` or `starttls` |
| `CA_FILE`, `USERNAME`, `PASSWORD` | Explicit lab trust and credentials; never included in the artifact |
| `RUN_ID`, `SOURCE_REVISION`, `RESULT` | Unique ASCII run identifier, tested revision and fresh JSON output path |
| `ALLOW_WRITE`, `FIXTURE_OU` | Optional `1` and an independently provisioned `OU=sdk-portable-*` in `DC=ad,DC=sdk,DC=test` |

The parent OU must carry description `sdk-portable-parent:<RUN_ID>`. The collector
checks the actual lab RootDSE before writing, and the contact uses description
`sdk-portable-owned:<RUN_ID>`. It records the owned DN and binary GUID for
independent reconciliation. The outer collector must verify and clean the owned
fixture independently, including both possible DNs after an interrupted rename.
The test does not infer acceptance or roll back an uncertain write.

Assertion control acceptance is tested only when advertised. Otherwise the lab
test requires an actual rejected LDAP status 12 for one critical assertion probe
and verifies that its requested description change had no effect. That change is
never retried without its assertion. A separate duplicate-add operation tests
the advertised critical permissive-modify control. The artifact records
`assertion_advertised` and a distinct unsupported/refused step; such evidence
does not qualify assertion acceptance. Permissive-modify and show-deleted controls
must be advertised before fixture creation.

Owned wire fixtures prove the tested protocol behavior; they do not qualify all
AD versions or real Kerberos interoperability. The retained
[implementation validation](research/portable-ldap-validation.md) records the
actual Windows/Linux, LDAPS/StartTLS, Server 2016/2019/2022/2025 simple-bind matrix,
including ranged reads and independent cleanup. This does not qualify public
Kerberos or all operations in the readiness gate. Preserve fresh source, binary,
server and cleanup provenance for each actual lab run; native evidence and
planned identifiers do not qualify a portable session.
