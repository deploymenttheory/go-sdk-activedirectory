# Single-object synchronization

`Client.SyncObject` requests one object from an explicit source DC onto the
destination client's pinned LDAP endpoint. It uses the documented synchronous
rootDSE `replicateSingleObject` Modify through the shared native WinLDAP writer.
No runtime PowerShell, RSAT, ADWS, referral, reconnect, or automatic retry is used.
The DCs need a common full naming-context replica; a direct replication
partnership is unnecessary. AD DS and AD LDS are accepted for ordinary object
replication. Password-only replication requires AD DS and an RODC destination.

```go
destination, err := activedirectory.Dial(ctx, activedirectory.Config{
    Endpoint: activedirectory.Endpoint{Host: "dc2.example.test"},
    Timeout: 2 * time.Minute,
})
// Check err, and always close destination.
result, err := destination.SyncObject(ctx, activedirectory.SyncObjectRequest{
    Source: activedirectory.Config{
        Endpoint: activedirectory.Endpoint{Host: "dc1.example.test"},
        Timeout: 2 * time.Minute,
    },
    Partition: "DC=example,DC=test",
    Object: activedirectory.SyncObjectIdentity{
        DistinguishedName: "CN=Fixture,OU=Lab,DC=example,DC=test",
    },
    Properties: []string{"description"},
})
// Inspect both err and result.State; never replay an uncertain request.
```

The runnable `examples/object-sync` accepts source/destination/partition/object
flags and an explicit `-apply`. Both connections default to the current Windows
identity; distinct `Config.Credentials` may be provided for source inspection and
destination execution. Credentials are not forwarded to the source DC by this
operation. DC-to-DC replication uses the destination DC's replication identity.
Use LDAP ports, not a Global Catalog endpoint. `request.Partition` is explicit;
the clients' default partition settings do not substitute another NC.

Before submission the SDK reads the authenticated servers' DSA objects, requires
recognized directory types and synchronized servers, compares configuration and
partition objectGUIDs, verifies NC-head/readiness bits and full-replica listings,
resolves the source object, and checks that the destination has the same parent
object. DNs containing colons cannot inject options: the wire value uses the
resolved source DSA and object GUID alternative DNs. A GUID identity uses the 16
LDAP objectGUID octets in Windows GUID byte order. Deleted source objects are
not eligible. All checks precede the only Modify; they are observations, not a
transaction that prevents concurrent changes. Missing objects/partitions,
inaccessible reads, mismatched identities and partial GC replicas fail closed.

The normal server operation requires **DS-Replication-Synchronize** on the NC
root. The SDK does not simulate Windows authorization from a fetched ACL;
the destination authorizes the request at execution. LDAP codes, diagnostics,
and cleanup errors remain available through the returned error chain. Diagnostic
text is omitted from ordinary `Error()` strings. Missing/hidden attributes do not
prove that the caller has no rights or that an attribute is unset.

`ObjectSyncAccepted` means a success response was parsed after the synchronous
operation. `ObjectSyncRejected` records a server failure; it is not a rollback
guarantee. `ObjectSyncUncertain` means a response could not establish the outcome;
the native writer retires the connection even after a successful abandon. Inspect
the destination independently before deciding whether another request is needed.
There is no SDK replay or forest-wide synchronization. `NotAttempted` means the
write boundary was not reached. Accepted remains accepted if readback, context,
or cleanup later fails.

Normal readback compares the same object's GUID and each requested source value
set with the destination, using exact bytes independent of value order. Empty
`Properties` compares `objectClass` only. Select a meaningful controlled fixture
attribute to test a change. Verification is a snapshot comparison of those
properties, not proof that all attributes/linked values have converged or that a
specific request caused equality. Nonempty complete source values are required:
absent/hidden and ranged attributes cannot be declared equal. Concurrent writes
may produce a readback mismatch after successful replication. Results preserve
both objects and successfully compared property names. Raw attributes may
contain directory data; only persist selected evidence appropriate to the test.

For `PasswordOnly`, omit `Properties`. The SDK requires a writable source, an
RODC destination and their common default domain NC. It queries
`msDS-IsUserCachableAtRodc` on the destination DSA using a **critical**
`LDAP_SERVER_DN_INPUT_OID` control naming the resolved account. This checks the
separate **Read-Only-Replication-Secret-Synchronization** right and the RODC's
policy snapshot. Only `RevealSecretsAllow` (1) permits submission; deny (0), no
policy (2), missing/unknown values and unsupported controls stop before writing.
The source DC still enforces its own current password replication policy.

The wire suffix is exactly `:SECRETS_ONLY`. Readback resolves the account on the
destination and checks the RODC computer's constructed `msDS-RevealedList` for a
`unicodePwd` marker referring to that same GUID. This observes a current cache
marker without reading any password values. It does not compare secrets or
prove they were newly cached. An absent, inaccessible, or ranged marker list
leaves the accepted result unverified with an error, never a second write.

## Validation and qualification

`go test ./...` runs portable validation/workflow tests and, on Windows amd64 or
arm64, native control and Modify encoding/ownership tests. They cover missing or
different NC/object/parent identities, deleted objects, unsynchronized servers,
unreachable source, permissions, RODC restrictions/policy, uncertain submission,
accepted readback/cleanup failures, and one-write behavior. Existing shared
writer tests cover cancellation, transport/result failures and native cleanup.
`scripts/lab/test-object-sync-collector.ps1` exercises the reference collector
offline with mocked directory commands, including read-only mode, target binding,
GUID byte order, multivalue preservation, cache-marker parsing and overwrite guards.

`TestSyncObjectLab` and `scripts/lab/collect-object-sync.ps1` provide the opt-in
native/reference workflow described in the script. They create no fixtures and
change no policy. The reference collector records OS, AD module and PowerShell
versions and selected object values; an actual PowerShell sync needs its explicit
`-ApplyReferenceSync` switch. Capture a controlled source-only change and restore
the fixture externally under the lab's existing ownership process. Keep source
and destination observations quiescent during comparison. Do not infer causality
from an already converged object.

For a reviewed disposable fixture, set these variables explicitly on the Windows
test machine (the current Windows token supplies both LDAP identities):

```powershell
$env:AD_OBJECT_SYNC_LAB_ALLOW_CHANGES = 'disposable-object'
$env:AD_OBJECT_SYNC_LAB_SOURCE = 'dc1.example.test'
$env:AD_OBJECT_SYNC_LAB_SOURCE_PORT = '389'
$env:AD_OBJECT_SYNC_LAB_DESTINATION = 'dc2.example.test'
$env:AD_OBJECT_SYNC_LAB_DESTINATION_PORT = '389'
$env:AD_OBJECT_SYNC_LAB_PARTITION = 'DC=example,DC=test'
$env:AD_OBJECT_SYNC_LAB_OBJECT = 'CN=Fixture,OU=Lab,DC=example,DC=test'
$env:AD_OBJECT_SYNC_LAB_PROPERTIES = 'description'
$env:AD_OBJECT_SYNC_LAB_EXPECT = 'accepted'
$env:AD_OBJECT_SYNC_LAB_REVISION = '<40-character tested source commit>'
$env:AD_OBJECT_SYNC_LAB_RUN_ID = '<unique owned run ID>'
$env:AD_OBJECT_SYNC_LAB_OUTPUT = '<new native JSON path>'
go test -tags integration -run '^TestSyncObjectLab$' -count=1 -timeout 150s .
```

For the RODC case set `AD_OBJECT_SYNC_LAB_PASSWORD_ONLY=1` and leave properties
unset. Negative cases use explicit `EXPECT` values `not-attempted`, `rejected`
or `uncertain`; review the captured error to confirm the intended failure cause.
Keep any transport disruption and fixture mutation outside this harness. The
outer lab owner must allow the test's 120-second context to report its result;
terminating it early can leave an unknown server outcome.

The reference collector requires explicit source/destination hosts and ports,
partition, object, revision, run ID and new output path. Ordinary comparisons
support string properties `description` and `displayName`. Add
`-ApplyReferenceSync` to invoke `Sync-ADObject`, or omit it for read-only snapshots.
It records both DCs' advertised OS versions when computer objects exist, the
collector OS/module/PowerShell versions, before/after snapshots and an RODC cache
marker. Preserve separate server inventories for exact builds/patches and AD LDS
hosts. Set `AD_OBJECT_SYNC_LAB_REFERENCE` to a successful reference JSON to check
matching provenance/projection before the SDK mutation and compare destination
GUID/value sets afterward. Read-only reference snapshots are deliberately not
accepted as evidence of a PowerShell sync. Restore and reapply the same controlled
fixture change externally between oracle and SDK runs; keep those mutation
records with the evidence. Neither runner creates or restores fixtures.

No live object synchronization has been performed for this feature. Server
2016/2019/2022/2025, AD LDS, RODC cache/restriction cases, missing destination
objects, permissions, linked/ranged values, and Windows arm64 live behavior all
remain to be qualified. Compilation and mock coverage do not replace these runs.

## Protocol references

- [MS-ADTS replicateSingleObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d3d19d15-8427-4d4d-8256-d5fb11333292)
- [Alternative forms of DNs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/92a54869-38d7-4e71-a3be-5f67a0dcdd7e)
- [nTDSDSA replica lists](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ebf2419-1169-4413-88e2-12a5ad499cf5)
- [RODC policy attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5abb497-8397-4afa-92ce-001ba3696697), [DN input control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5072bd62-1051-4f45-a87b-b06f92236b43), [extended access checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e6685d31-5d87-42d0-8a5f-e55d337f47cd)
- [RevealSecretsPolicy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/dff72b44-5a85-45b8-bc9b-a6faab723610), [source policy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/1df2d582-38b8-4812-bc4d-c26eb39f99e2)
- [msDS-RevealedList](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4ffbc8e2-4701-492b-a63b-29f76ec62b15)
- [Sync-ADObject reference](https://learn.microsoft.com/en-us/powershell/module/activedirectory/sync-adobject?view=windowsserver2025-ps)

Integration note: this feature stacks on the shared writer from PR89. Its small
`baseObjectReadControls` callback refactor intentionally matches PR85/88; retain
one shared implementation when those branches merge. The writer is unchanged.
