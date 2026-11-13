# Deleted-object discovery and restoration

`DeletedObjects` reads deleted entries through critical show-deleted or
show-recycled controls. `RestoreObject` restores one eligible deleted object
through the shared native LDAP writer. Both support AD DS and applicable AD LDS
on the selected connection; neither discovers another server, enables a feature,
creates a missing parent, restores descendants, nor runs PowerShell.

```go
found, err := client.DeletedObjects(ctx, ad.DeletedObjectQuery{
    Search: ad.SearchOptions{
        Base: "DC=example,DC=test", Scope: ad.ScopeSubtree,
        Filter: "(sAMAccountName=fixture-user)",
        Properties: []string{"description"}, ResultLimit: 100,
    },
    IncludeRecycled: true,
})
// Inspect err, found.Complete, found.Observation.LimitReached and each row's
// State/Error. Objects and raw observations survive partial/native errors.

identity, err := ad.IdentityByGUID("00112233-4455-6677-8899-aabbccddeeff")
// Check err before using identity.
restored, err := client.RestoreObject(ctx, ad.RestoreObjectRequest{
    Identity: identity,
    Options: ad.ObjectMutationOptions{Properties: []string{"description"}},
})
// Inspect err and restored.Mutation even on failure.
```

Empty discovery Base selects Config.Partition or defaultNamingContext. A supplied
Base must be within the selected advertised naming context. Scope has ordinary
Search semantics: zero means Base, not Subtree. Filters use LDAP syntax. The SDK
adds `(isDeleted=TRUE)` without substituting values into the caller's filter.
Page size, result limits, incomplete ranges and cursor cleanup retain the shared
Search behavior. `IncludeDeactivatedLinks` requests the critical control that
exposes retained link values; ranged values remain explicitly incomplete.

Capabilities are checked on the connected DSA by reading its complete
`msDS-EnabledFeature` forward links and resolving `msDS-OptionalFeatureGUID`.
The Recycle Bin GUID is shared with the optional-feature API. Raw DSA and feature
observations are retained. Missing, hidden, malformed or ranged links do not
prove a feature is disabled. Reads stop after at most 256 feature links; a larger
list remains raw evidence with an incomplete error. Discovery still returns its
object observations if feature qualification fails, with unknown classifications.
Global catalog ports are rejected; use a full LDAP replica.

`DeletedStateDeleted` means the returned deletion metadata and visibility
control identify a deleted object while Recycle Bin is positively observed.
`DeletedStateRecycled` is irreversible through this operation.
`DeletedStateTombstone` follows an observed complete feature list without
Recycle Bin, or a TRUE isRecycled value returned by show-deleted while feature
state is unknown: the control excludes actual recycled objects.
`DeletedStateProtected` identifies a returned disallow-delete
system flag, including the protected Deleted Objects container. Unknown feature
or deletion metadata remains `DeletedStateUnknown`. With IncludeRecycled, an
omitted isRecycled value cannot distinguish deleted from recycled; show-deleted
provides that distinction because the server excludes recycled objects.
Collection completeness does not promise that every state is known or restorable.

An expired/garbage-collected object has no surviving LDAP row. The SDK returns
`ErrDeletedObjectUnavailable` when restoration cannot observe it; it does not
invent an expiration timestamp or confuse ACL/replication absence with permanent
deletion. Observed recycled state is authoritative for ineligibility. Retention
age alone is not, since garbage collection and replication are asynchronous.

Restoration accepts a current deleted DN or GUID. A nil NewName uses
`msDS-LastKnownRDN`; otherwise it is a literal RDN value, escaped once. A zero
TargetParent uses lastKnownParent; an explicit DN/GUID selects an existing live
parent in the same naming context. Missing parents must be restored separately.
The server enforces permissions, class containment and name/SAM/UPN/SPN conflicts.
Names and target paths are never silently changed to avoid conflicts.

Default `RestoreWithRecycleBin` mode requires positively observed Recycle Bin
enablement and does not accept replacement Attributes. Recycle Bin requires the
applicable forest/configuration-set feature prerequisites; the SDK does not
enable it or infer enablement from server version alone. The caller
also needs the Reanimate-Tombstones right and applicable rename/create-child
permissions. Native LDAP diagnostics are retained when these fail.

`RestoreLegacyTombstone` explicitly opts into potentially lossy reanimation. It
can proceed when feature metadata is unavailable: the retained capability Error
and nil RecycleBinEnabled remain visible, while the critical show-deleted control
proves that the selected row is not an actual recycled object. Positive feature
enablement together with a returned TRUE isRecycled is inconsistent and rejected.
Show-recycled fallback is diagnostic only and never submits a write. Protected
objects, naming-context roots and schema objects are rejected in both modes.

Legacy Attributes supplies complete replacement values for stripped mandatory
attributes (and optional values the caller knows), in the same atomic Modify:

```go
restored, err := client.RestoreObject(ctx, ad.RestoreObjectRequest{
    Identity: identity, Mode: ad.RestoreLegacyTombstone,
    NewName: &name, TargetParent: parentIdentity,
    Attributes: map[string][]ad.RawValue{
        "sn": {ad.NewRawValue([]byte("Known surname"))},
    },
})
```

Use attributes required by the object's actual schema; the SDK does not invent
values or silently add a second repair operation. Empty lists, duplicate values,
identity/deletion metadata and conflicting naming attributes are rejected.
Binary and multivalue values are preserved. Missing mandatory values retain the
server's rejection. A tombstone may lack its former name or parent; supply them
explicitly instead of guessing from a possibly truncated delete-mangled name.
Stripped attributes and links cannot be recovered from absent data. User account
enablement and passwords are separate explicit operations, never automatic here.

The operation submits exactly one Modify against the object's GUID: remove
isDeleted and replace distinguishedName, plus any legacy replacement attributes,
under the critical show-deleted control.
Optional `ExpectedVersion` uses the shared critical assertion on GUID/uSNChanged
for the same endpoint. No failed, rejected or uncertain write is replayed.
`ObjectWriteAccepted` is distinct from successful readback. An ordinary live
search must return the same GUID at the requested destination before Verified is
true. Supplied legacy values must also match complete returned values. Before/after
raw properties are retained; Verified does not claim that
every pre-deletion attribute or link was visible or restored. Reads across the
workflow are not a transaction, and parent/name preflight can race other changes.

Portable tests cover feature visibility, scope, parent/name selection, protected
and recycled objects, deadlines, conflicts, identity retention, partial results
and uncertain outcomes. Actual WinLDAP loopback tests check the mandatory Modify elements,
legacy binary/multivalue replacements, unknown-feature tombstone provenance,
critical controls, Unicode DNs, paged visibility controls on every request and
cookie release, partial permissions/ranges, and all seven ownership counters.
No live directory was changed to validate this draft. Disposable-fixture
PowerShell differential qualification on Server 2016/2019/2022/2025 and applicable
AD LDS remains open. The runnable `examples/restoration` defaults to discovery;
restoration requires explicit `-operation restore -guid ... -apply`. Add
`-legacy -attribute sn=KnownSurname` for explicit legacy mode; repeat `-attribute`
for multiple text attributes/values. Use the Go API for binary values.

References: [Restore-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/restore-adobject?view=windowsserver2025-ps),
[native restoration](https://learn.microsoft.com/en-us/windows/win32/ad/restoring-deleted-objects),
[undelete operation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4302a2eb-55c8-426c-b310-6791c6ae8307),
[undelete permissions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004),
[deletion states](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6c21dd2f-40cd-4963-90a2-a7f657f319a4),
[show-deleted control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4b8f2a0e-9ea6-4be3-b639-4b019948c568),
[optional features](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9ae2a9ad-970c-4938-a6bf-9c1fdc0b8b3e),
[Recycle Bin feature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9482178-ee53-4b6c-841d-5259d6261985).
