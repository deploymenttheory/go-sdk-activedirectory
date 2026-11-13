# Moving directory objects

`Client.MoveObject` submits one native LDAP ModifyDN, retaining the RDN and
object GUID. It supports moves within one naming context on AD DS or AD LDS,
and moves between domain naming contexts in the same AD DS forest. It does not
copy attributes into a replacement object or submit Add/Delete/password writes.

```go
object, err := ad.IdentityByGUID("00112233-4455-6677-8899-aabbccddeeff")
// Check err.
parent, err := ad.IdentityByDN("OU=Destination,DC=example,DC=test")
// Check err.
result, err := client.MoveObject(ctx, ad.MoveObjectRequest{
    Identity: object, TargetParent: parent,
    Options: ad.ObjectMutationOptions{Properties: []string{"description"}},
})
// Inspect err and result.Mutation, including State, Verified and raw readback.
```

Identity and TargetParent accept explicit DN or GUID identities. The source's
Options.Partition follows the existing identity scoping rules. With a nil
Destination, the parent must be in that same naming context. Containers and
their descendants use server-supported intrapartition move behavior. The SDK
does not enumerate or move descendants one at a time. RDN bytes are retained
from the resolved DN, including Unicode and escaped literals. Renaming remains
the separate `RenameObject` operation.

Cross-domain moves require a separately authenticated destination client:

```go
source, err := ad.Dial(ctx, ad.Config{
    Endpoint: ad.Endpoint{Host: "rid1.source.example.test"},
    AllowDelegation: true,
})
// Check err and defer source.Close().
destination, err := ad.Dial(ctx, ad.Config{
    Endpoint: ad.Endpoint{Host: "rid1.target.example.test"},
})
// Check err and defer destination.Close().
result, err := source.MoveObject(ctx, ad.MoveObjectRequest{
    Identity: object, TargetParent: targetParent,
    Destination: destination,
    DestinationPartition: "DC=target,DC=example,DC=test",
})
```

An explicit Destination selects cross-domain semantics; it must be a distinct
client for a different domain. DestinationPartition is useful for GUID parent
resolution; otherwise that client's configured/default naming context applies.
Both endpoints must be full LDAP replicas at their exact advertised DNS names,
and each must be its domain's observed RID master. The SDK follows each domain's
actual rIDManagerReference and checks fSMORoleOwner against the connected DSA.
It requires writable domain-NC instanceType, matching configuration-NC GUIDs
and root-domain DNs, and source support for the cross-domain control. AD LDS
cross-partition moves, global catalog endpoints and advertised RODCs are rejected.
No endpoint discovery or automatic reconnection occurs.

The source ModifyDN includes critical control `1.2.840.113556.1.4.521`. Its value
is the destination DC's raw UTF-8 DNS hostname, without a terminating NUL or an
inner BER wrapper. NewParent is the resolved destination parent DN, and
DeleteOldRDN is true. The native server operation carries account state and
passwords for eligible user/computer moves; the SDK neither reads nor rewrites
passwords. SID-related changes are server-managed; retaining GUID does not mean
that the account SID is unchanged.

`AllowDelegation` is an explicit security decision at Dial. It requires
Negotiate and a DNS endpoint and adds SSPI DELEGATE and MUTUAL_AUTH requests
without clearing existing flags. It permits the source server to authenticate
to other servers as the bound identity. It is false by default. Cross-domain
MoveObject also checks the existing LDAP-owned security context: negotiation
must be complete, the package must be Kerberos, and negotiated delegation and
mutual-authentication flags must be present. An unavailable or insufficient
context returns an error before any move. Requesting delegation alone proves
nothing about Windows/domain policy. The destination client's identity is used
only for its reads and never substitutes for delegated source authorization.
No password, ticket, secret key or SSPI handle is returned in MoveSecurity.

Preflight rejects visible deleted/recycled entries, naming-context roots,
schema moves, AD DS LSA-specific classes, self/descendant destinations and
applicable systemFlags restrictions. Cross-domain checks additionally reject
the protocol's forbidden classes, visible critical/protected objects, trust
accounts, built-in groups and restricted RIDs. Missing required identity,
instanceType, role or forest metadata prevents dispatch. Omitted optional
restriction attributes are not proof of authorization: server checks remain
authoritative for ACL protection, schema systemOnly/containment, well-known
objects, leaf status, group memberships, uniqueness and effective RID ownership.
The SDK never clears protection, changes membership or adjusts names to force a
move. Native diagnostics retain the resulting failure details.

Source and destination preflights are sequential observations, not locks or a
distributed transaction. The SDK never holds both client gates at once, so
reciprocal moves do not deadlock. A source workflow timeout bounds the whole
operation, including gate waits; destination reads also use their client's
timeout. Optional ExpectedVersion is a critical GUID/uSNChanged assertion on
the source endpoint. It does not guard the destination parent or RID ownership.

Always inspect Mutation.State on error. Accepted means the source acknowledged
the move; Verified additionally requires an ordinary destination read returning
the same GUID at the requested DN. Hidden/ranged values or readback failure
retain raw candidates and errors. Verification does not prove password behavior,
every retained attribute, or visibility on other replicas. For cross-domain
operations, PartialEffectsPossible remains true after any submitted attempt,
including server rejection: the native protocol can report that cleanup is
required. No uncertain/rejected write is retried, no rollback is claimed, and
the SDK performs no automatic cleanup. Reconcile both endpoints before another
write after interruption or incomplete outcomes.

Mutation.Source and Mutation.Partition describe the write endpoint. After and
ReadbackCandidates come from Destination in DestinationPartition. A returned
destination uSNChanged is not a source-side ExpectedVersion.

The runnable `examples/moves` requires explicit `-apply`, source server,
identity and parent. Cross-domain use additionally requires `-destination-server`
and `-delegate`; each client uses the caller's current Windows identity. The Go
API can supply independent Config.Credentials to either client.

Portable tests cover DS/LDS scope, GUID parents, RID/forest identity, forbidden
objects, incomplete observations, versions, timeouts and all outcome states.
Actual WinLDAP loopback tests inspect ModifyDN BER, Unicode/escaped names,
critical assertions and raw destination control bytes for user/computer moves,
native errors and cancellation, with all seven native ownership counters zero.
Native SSPI tests check borrowed-context layout and allocated-buffer ownership.
No live directory bind or move was performed for this draft. Live delegation,
user/computer password preservation and PowerShell differential comparisons on
Server 2016/2019/2022/2025 and applicable LDS remain qualification requirements.
Those runs must record OS/module versions, endpoint/role identities, fixture
GUIDs and before/after attributes, and validate passwords without logging them.

References: [Move-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/move-adobject?view=windowsserver2025-ps),
[cross-domain control](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-crossdom-move-target-oid),
[intrapartition constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/61a299bd-7580-49bd-b64c-fae53b26aab4),
[cross-domain constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ddfd32cf-615c-4e98-9d8f-e490e13c3c71),
[delegation requirement](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6db12dc8-79d8-4d98-900c-04df669b68ee),
[SSPI context flags](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_flags),
[Kerberos context requests](https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--kerberos),
[negotiated package](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_negotiationinfow).
