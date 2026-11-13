# User lifecycle

`User`, `Users`, `CreateUser`, `UpdateUser`, and `DeleteUser` provide typed user
operations through the existing native connection, identity, filter, value and
write APIs. They support AD DS `user`/`inetOrgPerson` objects and applicable AD
LDS schema classes. Computer subclasses are excluded. No runtime PowerShell or
RSAT is used.

Creation requires an explicit parent identity and literal name. The schema-aware
creator resolves the naming attribute and escapes the name as one RDN value.
Class defaults to `user`; `inetOrgPerson` is an explicit alternative. The server
enforces required attributes, uniqueness, schema and access permissions. Supply
`SAMAccountName` when a particular SAM name is required; it is not derived from
the display name. Default-container discovery and custom structural user classes
are outside this slice.

```go
parent, err := ad.IdentityByDN("OU=People,DC=example,DC=test")
// Check err before using parent.
sam, display := "jli", "Jörg 李"
created, err := client.CreateUser(ctx, ad.CreateUserRequest{
    Parent: parent, Name: "Jörg, 李",
    Properties: ad.UserProperties{SAMAccountName: &sam, DisplayName: &display},
})
// This creates disabled without an initial password. Check err and every stage
// result before making another write, including when creation was accepted.
```

Creation always starts disabled. For AD DS it explicitly sets NORMAL_ACCOUNT
and ACCOUNTDISABLE, without inheriting the server's default password exemption.
AD LDS uses `msDS-UserAccountDisabled` and `ms-DS-UserPasswordNotRequired`.
`InitialPassword` invokes the shared administrative password reset after a
verified creation observation. Its non-nil UTF-8 byte slice is caller-owned and
follows [password lifetime and protection rules](account-passwords.md). A nil
slice omits the stage; an explicit empty slice requests an empty password subject
to server policy. Known insufficient session encryption is rejected before Add.

`Properties.Enabled=true` enables only after successful password setup. Omitting
initial password setup while enabling additionally requires explicit
`PasswordNotRequired=true`; the directory still decides whether it is permitted.
Existing users can be enabled or disabled through `UpdateUser` or the shared
account-control API. Such updates do not promise that a usable password exists.

`UserCreationResult` retains Add, password and enablement outcomes independently.
The stages share the caller's deadline and one overall client timeout, but are
not a transaction. Any failed, uncertain or unverified stage stops the workflow;
the SDK never automatically deletes an accepted creation, rolls back, or replays
a password or enablement operation. Nil stage pointers mean those stages were
not entered. `Complete` means all requested stages and observations completed,
not successful logon or replication. `User` is the last successful typed
observation; inspect its stage and errors before treating it as current. Other
clients may change the object between stages or before readback.

`User` accepts DN/GUID identities on both directory types. AD DS additionally
accepts SID and literal unqualified SAM identities. All resolution is pinned to
the selected server and naming context, with no ambiguous-match fallback.
`Users` intersects `SearchOptions` filters with user classes, excluding computers:

```go
users, err := client.Users(ctx, ad.SearchOptions{
    Base: "OU=People,DC=example,DC=test", Scope: ad.ScopeSubtree,
    TypedFilter: ad.FilterEqual("department", ad.FilterText("Engineering")),
    PageSize: 256,
})
// Check err, users.Observation.Complete and .LimitReached.
```

Empty search Base selects the configured partition or default naming context.
Search scope defaults to Base, just as in `Search`. Partial raw observations are
retained on search/decoding errors. Typed fields map names such as Surname to
`sn`, EmailAddress to `mail`, Office to `physicalDeliveryOfficeName`, City to `l`,
State to `st`, and ManagerDN to `manager`. ManagerDN is an explicit DN, without
implicit principal lookup. LastLogonDate retains the raw `lastLogonTimestamp`
FILETIME; it is not an exact latest logon time. AccountExpires and PasswordLastSet
retain precision and raw sentinel values. Nil means not returned, not false or
zero. `Raw.Values` distinguishes absent, unloaded, complete and ranged data;
service principal names and certificates also expose `AttributeValues` directly.

Updates use non-nil `UserProperties` fields. An empty string is a literal value;
it is not a clear. Use the shared `AttributeChange` model for explicit Clear,
Set, AddValues, RemoveValues, raw binary certificates and multivalue attributes.
Typed/raw conflicts are rejected. One disjoint remove/add pair is submitted
remove-first in the same strict Modify. Clear or hidden/ranged values cannot be
proved by omission, so acceptance and `Verified` remain distinct.

Enabled, PasswordNotRequired, PasswordNeverExpires and SmartcardLogonRequired
reuse the shared account-control helpers. AD DS updates preserve unrelated UAC
bits and delete the exact observed old value before adding the new value in one
Modify. A concurrent change rejects the whole Modify; there is no replay or
permissive modify. AD LDS updates the applicable independent boolean attributes;
unsupported options fail explicitly. Already-satisfied flag-only updates perform
no write and return the verified observation. They reject ExpectedVersion because
no server request would enforce that assertion. Ordinary updates and leaf deletes
inherit [generic object concurrency and readback rules](directory-objects.md).
Raw UAC, the corresponding managed LDS flags, `unicodePwd` and `userPassword`
changes are rejected by the user API. Use the shared password operations for
password changes and resets. Other account-control and ACL properties remain in
their dedicated APIs rather than being synthesized from UAC bits.

`DeleteUser` is leaf-only, targets the resolved GUID and does not remove group
objects or other users. Native LDAP status and private diagnostic fields remain
available; ordinary error strings do not expose diagnostic text. Accepted writes
with failed readback remain accepted with errors and retained raw candidates.

Portable tests cover Unicode mapping and naming, sentinels, partial results,
strict flag updates, raw conflicts, duplicate creation, password-policy failures,
uncertain writes, staged stop behavior, encryption rejection and leaf deletion.
A loopback test runs the public update through actual WinLDAP, checks one atomic
Modify with exact GUID/UAC wire values and Unicode text, native rejection without
replay, and ownership cleanup. The shared password and object writer tests cover
their native encodings. `examples/users` defaults to a read and requires `-apply`
for each mutation; its create operation deliberately leaves the account disabled.

This is a draft implementation slice of issue #18. Full lifecycle comparisons
against the ActiveDirectory PowerShell module on Server 2016/2019/2022/2025 and
applicable AD LDS remain open, including live policy/permissions, duplicate names,
schema normalization and initial-password failure behavior. No live qualification
or issue acceptance is claimed by these local tests.

References: [New-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2025-ps),
[Set-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-aduser?view=windowsserver2025-ps),
[creating a user](https://learn.microsoft.com/en-us/windows/win32/ad/creating-a-user),
[UAC flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557),
[AD LDS bindable attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/c44e4c75-407c-4657-9217-4ee6548dc6f8).
