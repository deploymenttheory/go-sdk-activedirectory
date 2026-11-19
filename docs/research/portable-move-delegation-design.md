# Portable move delegation: protocol and implementation boundary

SDK-12 [#177](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/177)
extends the shared [move contract](../object-moves.md), not a copy/delete workflow.
This document records the reviewed implementation and protocol boundary. Owned
socket tests pass; live AD delegation and cross-domain moves remain unqualified.

## Forwarding policy

Delegation remains off by default. Explicit `AllowDelegation` requires real
credential forwarding or fails; it never falls back to an ordinary bind.
Password/keytab authentication requests forwardable credentials only for that
opt-in. FILE caches remain read-only, and an explicit valid TGT is required.

RFC4120 §2.6 says addressless forwarding **SHOULD** obtain a fresh forwarded TGT
to separate session keys. It does not universally require another TGS exchange
for every addressless ticket transfer. This SDK deliberately adopts the stricter
policy: obtain a fresh KDC-issued `FORWARDED` TGT; never serialize the original
TGT as a shortcut, edit ticket flags or use ambient credentials.
[RFC4120 §2.6](https://www.rfc-editor.org/rfc/rfc4120.html#section-2.6).

The authenticated service reply must identify the exact requested LDAP SPN,
actor and explicit realm with a permitted AES profile, correct nonce and valid
lifetime, and carry `OK-AS-DELEGATE`. A separate TGS request for the explicit
realm's TGT requests `FORWARDED`/`FORWARDABLE`; its authenticated reply must satisfy
the same identity/profile/time checks and actual forwarding flags. Local intent
or mutable cache metadata cannot manufacture those KDC policy observations.
Requests remain on the configured KDC/realm; no SPN, realm or backend fallback.
[RFC4120 §2.8](https://www.rfc-editor.org/rfc/rfc4120.html#section-2.8),
[MS-KILE ticket flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/de260077-1955-447c-a120-af834afe45c2).

RFC4121 §4.1.1 places the delegation flag and a bounded KRB-CRED in the AP-REQ
authenticator checksum. KRB-CRED carries the forwarded ticket and its key/info;
its encrypted part uses the **service-ticket session key**, not the initiator
subkey. All four supported AES profiles retain independent known-vector tests.
Owned plaintext/key copies are cleared at their lifetime boundary, and public
observations contain no credential, ticket or security handle.
[RFC4121 §4.1.1](https://www.rfc-editor.org/rfc/rfc4121.html#section-4.1.1),
[KRB-CRED format](https://www.rfc-editor.org/rfc/rfc4120.html#section-5.8).

MIT's GSS initiator calls `krb5_fwd_tgt_creds` and temporarily removes its send
subkey while encoding the credential. Its forwarding helper requests a forwarded
TGT. MIT can clear its delegation request on failure; the explicit SDK request
will instead fail closed. This is an interoperability reference, not a new SDK
dependency or permission to run a client-side runtime helper.
[MIT GSS initiator](https://github.com/krb5/krb5/blob/master/src/lib/gssapi/krb5/init_sec_context.c),
[MIT forwarding helper](https://github.com/krb5/krb5/blob/master/src/lib/krb5/krb/fwd_tgt.c).

## Observations and move admission

`DelegationSent` records actual emission of validated encrypted KRB-CRED and
the corresponding GSS flag. A delegated local mechanism context becomes
established only after mutual authentication, exact SASL layer negotiation and
the final successful LDAP result. Neither fact proves remote impersonation
authorization, policy assignment or successful destination writes. Actual
cross-domain results and independent source/destination observations remain
authoritative. Lifetime checks include the delegated credential's real expiry.

The existing workflow retains exact source/destination endpoints, distinct
clients, default-domain NCs, forest identity and each observed RID master.
Critical control `1.2.840.113556.1.4.521` contains the destination DC's raw UTF-8
DNS name. It submits one ModifyDN, preserves source GUID/partition and destination
readback separately, and never retries or claims rollback after uncertainty.
The portable session supplies actual protection/delegation observations through
the existing move-security seam. Same-domain moves remain independently usable.
[MS-ADTS security](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6db12dc8-79d8-4d98-900c-04df669b68ee),
[move control](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-crossdom-move-target-oid).

## Qualification prerequisites

Existing retained manifests describe the `AD.SDK.TEST` domain for each server
profile; they do not demonstrate a second domain in the same forest with both
RID masters available. [LAB-03](https://github.com/deploymenttheory/terraform-provider-activedirectory/issues/20)
owns those advanced fixtures. No lab/SSH/guest call is part of this design work.

Owned socket tests exercise actual AS/TGS/AP and LDAP exchange boundaries:
default nonforwarding, all explicit credential sources, fresh forwarding policy,
malformed/refused/expired/wrong-identity replies, final acknowledgement, key
retirement, cancellation, lost mutation response and partial destination readback.
Independent MIT acceptor/delegated-credential validation is a separate protocol
gate where available. Positive user/computer moves and password preservation
must later run from Linux/Windows against applicable server profiles, with exact
source/binary/protection and marker/GUID cleanup records. Missing infrastructure
stays blocked; an always-unsupported implementation is not full SDK-12 delivery.

The opt-in offline test is:

```sh
ADSDK_DELEGATION_MIT_INTEROP=1 go test -mod=readonly ./activedirectory/acceptance \
  -run '^TestPortableDelegationIndependentMITAcceptor$' -count=1 -v
```

It requires Linux Python3 and the installed MIT `libgssapi_krb5`/`libkrb5`, with
no development packages. The test-only ctypes peer acquires one explicit
service keytab, accepts the actual emitted AP-REQ, and checks actual GSS flags,
actor/service identity and delegated-credential handle. It imports any delegated
credential into a new MEMORY ccache and verifies the fresh realm TGT's flags,
AES profile and expiry. Input is bounded private stdin; output contains no
tokens, keys or credential payloads. Temporary service keys/replay state belong
to an owned test directory. The peer retires its credential/context/cache, and
the Go fixture removes its private keytab. It exercises no AD server or move.
The local SDK separately completes the owned LDAP acceptor's mutual/SASL/final
bind exchange; this is not a claim of MIT LDAP-server interoperability.
[MIT API declarations](https://github.com/krb5/krb5/blob/master/src/include/krb5/krb5.hin),
[credential-cache extension](https://github.com/krb5/krb5/blob/master/src/lib/gssapi/krb5/gssapi_krb5.h).

## Actual independent offline qualification

Corrected source `075026493693067e0b0c8daf3b686a699c4cb3ca` now passes the
actual opt-in MIT GSS default/forwarding cases and root's full Go 1.27.4 Linux
race/vet checks, with all 4,325 raw-Git inputs verified before and unchanged
afterward. The [retained evidence](portable-delegation-evidence/corrected-0750264-offline/README.md)
keeps the original independent failures, concrete DER finding, interrupted
worker run and fresh successful root run distinct. No AD server or move was
tested by this offline gate; all advanced live prerequisites remain required.

## Integration with merged portable workflows

The branch incorporates main `09f3214`, including the merged mutation contracts
and direct replication diagnostics. The shared owned KDC fixture retains both
the explicit RPC service allowlist and the opt-in forwarded-TGT admission checks;
neither replaces the other. Both evidence-directory byte-preservation rules are
retained. Full Go 1.27.4 Windows tests and vet pass on the integrated source.

The immutable `0750264` evidence above describes that earlier tested source.
It does not establish source equivalence or live qualification for the integrated
branch. All outstanding cross-domain lab and acceptance requirements remain.
