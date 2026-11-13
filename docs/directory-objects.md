# Generic directory object mutations

`CreateObject`, `UpdateObject`, `RenameObject`, and `DeleteObject` use native WinLDAP on the existing authenticated connection. DN and GUID identities use the same explicit constructors and partition rules as `ResolveIdentity`; SID and account-name forms are not accepted for generic writes. Unknown directory types fail before writes. AD DS conventional GC ports are rejected; AD LDS arbitrary ports remain supported. The server determines writability, authorization, schema constraints, and protected-object rules. The SDK does not transfer credentials, chase referrals, invoke PowerShell, or retry writes.

The runnable example defaults to a read:

```powershell
go run ./examples/objects -server dc.example.test -dn 'OU=Fixtures,DC=example,DC=test'
# Explicitly authorized writes to a disposable fixture:
go run ./examples/objects -server dc.example.test -dn 'OU=Fixtures,DC=example,DC=test' -operation create -class container -name 'SDK, sample' -apply
go run ./examples/objects -server dc.example.test -dn 'CN=SDK\, sample,OU=Fixtures,DC=example,DC=test' -operation set-description -description 'reviewed value' -apply
go run ./examples/objects -server dc.example.test -dn 'CN=SDK\, sample,OU=Fixtures,DC=example,DC=test' -operation rename -name 'SDK renamed' -apply
go run ./examples/objects -server dc.example.test -dn 'CN=SDK renamed,OU=Fixtures,DC=example,DC=test' -operation delete -apply
```

Creation accepts a structural class LDAP display name, an explicit parent identity, a literal name, and `map[string][]RawValue`. The SDK queries the selected server's schema, follows inherited `rDNAttID`, and escapes the name as one RFC4514 value. It supplies `objectClass` and the naming attribute; callers cannot override those fields. The server validates mandatory/allowed attributes and superclass/security constraints. Parent resolution is a preflight observation: it is not an atomic parent-version or parent-identity guard. The LDAP add reply has no new objectGUID, so creation readback observes the new DN and cannot exclude a concurrent delete/recreate at that DN.

Existing objects are resolved uniquely in the selected naming context before writing. Modify, rename, and delete address the resolved binary objectGUID using AD's alternate DN form, preventing a reused old DN from selecting another object. Partition validation is a preflight check, not an atomic guard against concurrent movement. Rename keeps the current parent and naming attribute and always removes the old RDN, as required by AD. This API does not perform cross-parent moves.

Attribute updates are one atomic LDAP Modify request:

| Request | Meaning |
| --- | --- |
| Attribute omitted from `Changes` | No change |
| `AttributeSet`, nonempty `Values` | Replace all values |
| `AttributeClear`, no values | Delete the entire attribute |
| `AttributeAddValues`, nonempty values | Add those values |
| `AttributeRemoveValues`, nonempty values | Remove those values |

`NewRawValue([]byte{})` is a single zero-length value, not clear or omission. Binary octets and multivalue sets are preserved. Attribute names must be LDAP display names without options/numeric aliases. Exact duplicate values and contradictory operations are rejected before any network read. One disjoint remove/add pair for an attribute is allowed and normalized to remove-first; repeated additions/removals, overlap, and Set/Clear mixtures are rejected. Server matching rules remain authoritative: byte-distinct text can still compare equal under schema rules.

```go
// Strict conditional replacement of one value: if the old value is absent,
// the server rejects the entire Modify. There is no permissive-modify control.
result, err := client.UpdateObject(ctx, ad.UpdateObjectRequest{
    Identity: identity,
    Changes: []ad.AttributeChange{
        {Attribute: "description", Kind: ad.AttributeRemoveValues,
            Values: []ad.RawValue{ad.NewRawValue([]byte("old"))}},
        {Attribute: "description", Kind: ad.AttributeAddValues,
            Values: []ad.RawValue{ad.NewRawValue([]byte("new"))}},
    },
})
```

Clear or Remove against a missing attribute, and Add of an existing value, retain strict native LDAP errors. There is no implicit read/merge/write. `ObjectMutationOptions.ExpectedVersion` can additionally require an exact objectGUID and decimal uSNChanged observed on the same endpoint. The SDK checks the endpoint and GUID and sends a critical RFC4528 assertion over both attributes only when RootDSE advertises `1.3.6.1.1.12`. This is not assumed to be available on AD servers. Unsupported servers return `ErrObjectControlUnsupported` before writing; there is no non-atomic fallback. A false assertion returns `ErrObjectConcurrency`. ExpectedVersion is unsupported for creation and recursive deletion, because it cannot guard the parent or the whole subtree.

`ObjectMutationResult.State` distinguishes not attempted, accepted, rejected, and uncertain. Native `LDAPError` remains available through `errors.As`, including numeric status, matched DN, and diagnostic text. Ordinary error strings deliberately omit directory diagnostics. Accepted state is retained when later cleanup, cancellation, readback, or verification fails. `PreflightCandidates` and `ReadbackCandidates` retain raw resolution rows even on ambiguity, partial retrieval, cancellation, or cleanup errors; incomplete candidates are never promoted to `Before`/`After` or treated as verified identities. For creation, preflight candidates describe the parent. Uncertain state requires caller reconciliation, never an automatic retry or rollback.

Readback runs on the same connection after an accepted request. `ReadbackComplete` requires a complete, unique, in-scope search and matching GUID. `Verified` also compares the requested changes: Set requires the exact returned byte set, Add requires all added values, Remove requires the removed values to be absent from a complete returned set, and rename requires the requested literal RDN value. Schema normalization or concurrent writes can prevent these conservative checks from succeeding. Omitted/hidden or ranged attributes cannot verify a change; Clear always remains unverified because omission cannot prove emptiness. `ErrObjectVerification` preserves accepted state and the returned observation for reconciliation. These are subsequent observations, not atomic post-read controls or isolation from other writers. No automatic rollback occurs.

Deletion defaults to leaf-only. `Recursive: true` requires the advertised critical tree-delete control and sends **one** request. AD may delete between 1 and 16,384 objects and then return `adminLimitExceeded / ERROR_DS_TREE_DELETE_NOT_FINISHED`, leaving the root. `PartialEffectsPossible` is therefore true for every submitted recursive request, including rejected and uncertain outcomes. Reconcile the surviving tree before deciding on any further delete. An accepted delete is verified only as the absence of a visible live object with that GUID; tombstones are not inspected.

WinLDAP's documented native tree-delete control input is a zero-length value with a null value pointer. Local native wire tests observe Windows encoding this as an explicit empty OCTET STRING, whereas MS-ADTS describes an omitted control value. No custom wire workaround is used; acceptance of this native encoding remains part of live AD qualification.

The draft has portable validation/workflow tests, native injected ownership/cancellation tests, and actual WinLDAP loopback wire tests. It has not executed fixture CRUD or PowerShell differential mutations against AD DS/AD LDS. Duplicate names, schema/permission failures, protected/nonempty objects, large-tree partial completion, interrupted writes, supported assertions, and server/module-version coverage still require isolated live qualification before issue #16 acceptance.

Protocol references: [classSchema and inherited rDNAttID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ccd55373-2fa6-4237-9f66-0d90fbd866f5), [GUID alternative DNs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/92a54869-38d7-4e71-a3be-5f67a0dcdd7e), [AD ModifyDN requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/64edaffe-8216-47bd-aaf0-9556de328c66), [RFC4528 assertions](https://www.rfc-editor.org/rfc/rfc4528), [AD partial tree deletion](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b8ee2305-b0eb-41be-894f-b94b5d29ca9e), [documented native tree-delete control](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-tree-delete-oid).
