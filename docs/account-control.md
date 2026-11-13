# Account control

`AccountControl` reads stored options and server-computed lockout/password state.
`EnableAccount`, `DisableAccount`, `UnlockAccount`, and `UpdateAccountControl`
perform explicit mutations using the existing native connection.

```go
account, err := ad.IdentityByAccountName("fixture-user")
// Check err before using the identity.
result, err := client.DisableAccount(ctx, account, ad.ObjectMutationOptions{})
// Inspect result.Mutation.State even if err is non-nil.

enabled, neverExpires := true, false
result, err = client.UpdateAccountControl(ctx, ad.AccountControlRequest{
    Identity: account,
    Patch: ad.AccountControlPatch{
        Enabled: &enabled,
        PasswordNeverExpires: &neverExpires,
    },
})
```

The shared account identity rules accept DN/GUID for AD DS and applicable AD LDS
accounts, and SID/unqualified SAM names for AD DS. Users, computers and service
accounts inheriting the user class are accepted; groups and unrelated objects
fail before writing. AD LDS user/inetOrgPerson and returned msDS-BindableObject
classes are supported. Custom schema classes that omit those returned classes
need additional schema resolution and are not inferred from an object SID.

`AccountControlPatch` uses pointers so omitted fields remain unchanged. It covers
the stored account-control booleans, including delegation, preauthentication,
home-directory and password requirements. Each AD DS change starts with the
observed `userAccountControl`, preserves all unrelated bits, and deletes that
exact old value before adding the replacement in one strict LDAP Modify. A
concurrent change rejects the operation instead of being silently overwritten.
There is no permissive-modify control and no retry.

AD LDS stores supported options in separate attributes: `msDS-UserAccountDisabled`,
`ms-DS-UserPasswordNotRequired`, `msDS-UserDontExpirePassword`, and
`ms-DS-UserEncryptedTextPasswordAllowed`. Assigning one of these does not replace
an unrelated flag. Missing values are not treated as false: the requested value
is submitted explicitly, and visibility/permission failures remain observable.
AD DS-only options on an AD LDS connection fail before any mutation.

`ChangePasswordAtLogon=true` writes `pwdLastSet=0`; false writes the special -1
instruction and verifies a positive server-assigned timestamp afterward. It
does not copy -1 into a timestamp result. Requiring a password change while
passwords never expire is rejected, considering the effective requested flags.
Setting `PasswordNeverExpires=true` also rejects an existing `pwdLastSet=0`.
Missing, hidden or malformed timestamps cannot establish that this combination
is valid. An explicit `ChangePasswordAtLogon=false` overrides that preflight
requirement by writing `pwdLastSet=-1` in the same Modify; its readback must still
contain a positive timestamp. Other flag changes do not acquire this requirement.
The directory remains authoritative for privileges, policy and account types.

Stored UAC and `msDS-User-Account-Control-Computed` remain separate in the result.
`LockedOut` and `PasswordExpired` are projected only from the computed value.
An old nonzero `lockoutTime` alone does not prove the account is still locked.
Missing computed values remain nil. `UnlockAccount` writes only `lockoutTime=0`;
it does not enable a disabled account or modify stored lockout bits. This is an
observation of one server, not proof of replication convergence or future login.

An already-satisfied flag-only change performs no write and returns a verified
observation with `ObjectWriteNotAttempted`. Extra requested properties are still
selected. Such a no-op rejects `ExpectedVersion` because no atomic server
assertion would be executed. Actual writes inherit the explicit supported
critical assertion-control requirement from [object mutations](directory-objects.md).

Acknowledgement, readback and verification remain distinct. A successful write
followed by an inaccessible readback returns accepted state and an error. Native
status and diagnostic fields are retained. An uncertain operation is never
replayed or automatically rolled back. Requesting a clear/hidden/ranged value
cannot make omission prove success.

Local tests cover every stored flag, unknown-bit preservation, AD LDS names,
computed state, conflicting flags, no-op/version semantics, partial failures
and uncertain outcomes. Actual WinLDAP loopback tests exercise public disable
and unlock methods, conditional modification order, rejection and ownership.
The `examples/accountcontrol` program defaults to reading; writes require an
explicit operation and `-apply`.

Issue #22 remains open for password-change ACL permissions and live qualification:
actual lockouts, state transitions, privilege/policy failures and PowerShell
comparisons on supported servers and AD LDS. No live account mutation or
authentication attempt is claimed by these local tests.

References: [Set-ADAccountControl](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountcontrol?view=windowsserver2025-ps),
[UAC flags and computed state](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties),
[AD LDS bindable attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/c44e4c75-407c-4657-9217-4ee6548dc6f8),
[computed account state](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2).
