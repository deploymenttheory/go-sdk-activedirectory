# Account password-change permission

`AccountPasswordChangePermission` reads the SELF/Everyone Change-Password ACE
pattern. `SetAccountCannotChangePassword` installs explicit deny rules when
true, or explicit allow rules when false. This permission is not stored UAC bit
`0x40` and is separate from `AccountControlPatch`.

```go
identity, err := ad.IdentityByAccountName("example-user")
if err != nil { return err }
observed, err := client.AccountPasswordChangePermission(ctx, identity,
    ad.ResolveIdentityOptions{})
// Inspect observed.Permission and err together.

changed, err := client.SetAccountCannotChangePassword(ctx, identity, true,
    ad.ObjectMutationOptions{})
// Inspect changed.Mutation.State even when err is non-nil; never retry blindly.
```

The shared account rules accept AD DS user/computer/service-account identities
and applicable AD LDS bindable accounts. Class and naming-context validation
precede any write. DN/GUID/SID/account-name handling is the same as
[account control](account-control.md); no alternative identity syntax is added.

## Permission meaning

The permission uses `ADS_RIGHT_DS_CONTROL_ACCESS` (`0x100`) in object-specific
ACEs for GUID `ab721a53-1e2f-11d0-9819-00aa0040529b`. The principals are SELF
(`S-1-5-10`) and Everyone (`S-1-1-0`), matched by SID bytes without localized
account-name lookup. Microsoft's [LDAP modification reference](https://learn.microsoft.com/en-us/windows/win32/adsi/modifying-user-cannot-change-password-ldap-provider)
describes the allow/deny pair.

`AccountPasswordPermission` retains the original descriptor and separate explicit
and inherited allow/deny observations for each principal. Its nullable
`CannotChangePassword` describes the recognized reference pattern: either
matching deny makes it true. It is **not an effective-access check** for an
arbitrary token, an evaluation of all generic rights, or a prediction that a
password change will succeed. Other permissions, account state and password
policy can still prevent a change. Missing/unreadable descriptors and ambiguous
patterns remain unknown rather than false.

Additional `Properties` are selected in the same controlled descriptor read and
retained in `Permission.Raw` and mutation before/after observations, including
no-ops and partial readback errors. They are not copied from a potentially stale
identity preflight. Mutation observations also select GUID, USN, name and class.

The setter changes explicit matching rules and installs missing explicit rules.
Unrelated ACEs and inherited ACEs are preserved byte-for-byte. Matching explicit
rules with other rights retain those rights; an ambiguous planned pattern is
rejected before dispatch instead of removing unrelated rights to force a result.
Unknown/callback/inheritance-qualified matching rules are not rewritten as
ordinary rules. A requested allow is rejected when a recognized inherited deny
would remain. The setter never edits the parent or disables ACL inheritance.

## Writes, concurrency and outcomes

The read requires `READ_CONTROL`; a changed DACL requires `WRITE_DAC`. The server
remains authoritative for account capabilities and permissions. Reads and writes
use the critical [DACL-only SD flags control](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0),
so owner, group and SACL are outside the update. Native Windows descriptor APIs
construct the self-relative output using the shared OU descriptor machinery.
NULL DACLs and unsupported descriptor forms fail safely.

The default edit preserves the **observed snapshot**, not unseen concurrent
DACL changes. `ExpectedVersion` requires a supported critical RFC4528 assertion
for the same endpoint, GUID and observed USN. Unsupported controls are rejected.
A no-op rejects `ExpectedVersion` because it sends no guarded server request.
Without a version, an already-installed pair returns a verified observation and
`ObjectWriteNotAttempted`.

One LDAP Modify writes the DACL. The result distinguishes planned changes,
accepted/rejected/uncertain submission, subsequent raw observations and
verification. A successful reply followed by denied or failed readback remains
accepted, with an error and unverified result. Verification requires the same
GUID/naming context, requested pattern, and all expected ACE bytes (server
reordering is allowed). There is no reconnect, replay, rollback or second write.

## Reference and validation

`scripts/reference-account-password-permission-local.ps1` invokes only the
installed Microsoft module's inspected **local descriptor** methods,
`ADAccountFactory.SetCannotChangePassword` and `ScanACLForChangePasswordRight`.
It performs no directory connection or account operation. The retained four
synthetic cases in `testdata/account-password-permission-local-reference.json`
pin file version `10.0.26100.7920` and assembly SHA-256
`0DF8B9B0B77C652BB65971C3745B2B7E99AA899A0390CDDAB12142ED96EB1FC7`.
Portable policy tests and actual Windows descriptor tests compare their ACE
multisets and observed fields with that reference.

The module removes opposite-type matching rules and adds desired rules. This
SDK deliberately preserves unrelated mask bits and inherited rules rather than
copying broad removals. Such unusual ACLs can therefore produce an explicit
unsupported/unknown result. The local comparisons cover ordinary explicit pairs;
they do not establish parity for every custom ACL or server version.

`examples/accountpermission` reads by default; `-operation deny` or `allow`
requires `-apply`. Issue #22 remains open for live qualification: real user,
computer and applicable service-account/LDS fixtures, permission-denied and
concurrent-update cases, and PowerShell/raw ACL comparisons across supported
server versions. No password change, authentication attempt or live AD mutation
was performed for these local tests.
