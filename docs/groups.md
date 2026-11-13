# Group lifecycle

The SDK provides `Group`, `Groups`, `CreateGroup`, `UpdateGroup`, and `DeleteGroup`.
They reuse the connection, identity resolver, typed/raw filters, attribute
conversions and native writer. No PowerShell or RSAT is used at runtime.

```go
parent, err := ad.IdentityByDN("OU=Groups,DC=example,DC=test")
// Check err before using the identity.
sam := "ApplicationReaders"
created, err := client.CreateGroup(ctx, ad.CreateGroupRequest{
    Parent: parent, Name: "Application Readers", SAMAccountName: &sam,
    Category: ad.GroupSecurity, Scope: ad.GroupGlobal,
})
// Inspect err and created.Mutation.State, including on failure.
```

Creation requires an explicit parent, category and scope. It does not guess a
Users container, derive a SAM name, or append `$`. An omitted SAM name is left
to the server; callers requiring a particular account name must supply it.
Literal names are escaped as one RDN value through the schema-aware object
creator. The server enforces schema, SAM uniqueness and group constraints.

`Group` takes explicit DN/GUID identities for AD DS or applicable AD LDS groups.
AD DS also accepts SID and literal unqualified SAM identities. A resolved user
or other account is rejected by its class before any group mutation. Missing
typed properties remain nil; unknown `groupType` bits and raw attributes remain
available. An unknown scope is distinct from a missing value. Builtin groups
are projected as DomainLocal following the Microsoft group mapping.

`Groups` accepts the existing `SearchOptions`, intersecting its typed or raw
filter with the group class. For example:

```go
groups, err := client.Groups(ctx, ad.SearchOptions{
    Base: "OU=Groups,DC=example,DC=test", Scope: ad.ScopeSubtree,
    TypedFilter: ad.FilterBitAnd("groupType", 0x80000000),
    PageSize: 256,
})
// Check err, groups.Observation.Complete and .LimitReached.
```

Empty Base selects the configured partition or server default naming context.
Search scope, paging, result limits, deadlines and partial results retain their
existing meanings. `Observation` preserves raw rows even when conversion or a
later page fails. A successful LDAP search is not proof that every requested
attribute was visible. The underlying native filter limitations still apply.

Updates supply only the properties to change. Nil pointers omit a property;
empty strings are literal values, not clear operations. `Changes` accepts the
shared Set/Clear/AddValues/RemoveValues model for other attributes. Supplying a
typed field and a raw change for the same attribute is an error. `ManagedByDN`
requires an explicit DN; there is no implicit principal lookup.

Category/scope changes use the observed `groupType`, preserve unrelated bits,
and submit delete-exact-old followed by add-new in one strict LDAP Modify.
This prevents silently replacing a concurrently changed type. A changed value
or invalid scope transition retains the server's native error; the SDK does
not replay, change membership, or attempt an intermediate scope automatically.
Other property changes are in the same Modify. Raw `groupType` patches are
rejected so they cannot accidentally erase unrelated flags.

An already-satisfied category/scope-only request performs no write and returns
the observation with `ObjectWriteNotAttempted`. It still selects requested
additional properties. `ExpectedVersion` is rejected for this no-op because no
server request would enforce it. Other mutations inherit the explicit critical
assertion-control requirement from [generic object writes](directory-objects.md).

Deletion targets the resolved GUID and performs a leaf delete; group members
are not deleted. The mutation result distinguishes server acknowledgement,
post-write observation and verification. Accepted followed by failed readback
remains accepted with an error. Uncertain writes are never repeated. Clear or
hidden/ranged properties cannot be verified merely by their omission.

Direct member addition/removal, TTL/permissive-modify options and bounded
complete ranged retrieval are documented in [group memberships](group-memberships.md).
Ordinary `Group`/`Search` requests for raw `member;range=...` values retain their
partial state; use `GroupMemberLinks` to follow all ranges. No large-group,
scope-transition or permission differential test against live AD is claimed.
Server 2016/2019/2022/2025 and applicable AD LDS qualification remain open.

Unit tests cover class guards, literal Unicode naming, exact atomic flag changes,
unknown-bit preservation, no-op/version behavior, partial reads, readback failure,
native diagnostic retention and no uncertain replay. The shared writer's real
WinLDAP tests cover protocol encoding and ownership. The runnable
`examples/groups` defaults to reading and requires `-apply` for a write.

References: [New-ADGroup](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adgroup?view=windowsserver2025-ps),
[Set-ADGroup](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adgroup?view=windowsserver2025-ps),
[groupType flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/11972272-09ec-4a42-bf5e-3e99b321cf55).
