# Default domain password policy (draft)

`Client.DefaultDomainPasswordPolicy` reads the password and lockout settings on
the connected AD DS server's default domain naming-context root.
`Client.UpdateDefaultDomainPasswordPolicy` applies an explicit typed patch using
one conditional native WinLDAP Modify, then reads back the policy.

This is an implementation slice for [issue #25](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/25).
Disposable-directory round trips, fixture restoration, and PowerShell
differential qualification remain pending. Update examples are intended for
those disposable directories, and the issue remains open.

## Runnable example

The default invocation is read-only, using the current Windows identity with
signed/sealed Negotiate:

```powershell
go run ./examples/passwordpolicy -server dc1.example.test
```

An optional `-domain 'DC=example,DC=test'` asserts the intended domain. It must
match the server's default domain; the SDK does not fall back to another domain
or follow referrals. The library uses `Config.Partition` for this assertion.
AD LDS, application naming contexts, and cross-domain targets are rejected.
Reads may use an RODC; updates require a synchronized writable DC and a writable
domain NC. The existing credentials and transport configuration also applies.

Supplying policy options explicitly performs an update:

```powershell
go run ./examples/passwordpolicy -server dc1.example.test -min-length 12 -history 24 -complexity true
go run ./examples/passwordpolicy -server dc1.example.test -lockout-duration 30m -lockout-window 10m -threshold 5
```

Additional options are `-max-age`, `-min-age`, and `-reversible-encryption`.
Intervals accept Go duration strings such as `720h`, `30m`, `0`, or `never`.
The SDK does not edit Group Policy or fine-grained password policies, and this
read does not compute a user's resultant policy.

## Typed values and omission

`DomainPasswordPolicyUpdate` uses pointers. Nil leaves a setting untouched;
non-nil zero or false is explicit. An empty patch is rejected. A patch whose
values already match returns verified with `PasswordPolicyWriteNotAttempted`.

| Go field | Domain attribute | Representation |
| --- | --- | --- |
| MaxPasswordAge | maxPwdAge | PolicyInterval; explicit zero writes PolicyNever |
| MinPasswordAge | minPwdAge | PolicyInterval |
| LockoutDuration | lockoutDuration | PolicyInterval |
| LockoutObservationWindow | lockOutObservationWindow | PolicyInterval |
| LockoutThreshold | lockoutThreshold | uint16, including zero |
| MinPasswordLength | minPwdLength | uint16 |
| PasswordHistoryCount | pwdHistoryLength | uint16 |
| ComplexityEnabled | pwdProperties bit 0x1 | optional bool in the patch |
| ReversibleEncryptionEnabled | pwdProperties bit 0x10 | optional bool in the patch |

The returned policy exposes the complete `PasswordProperties` bitmask, plus
`ComplexityEnabled()` and `ReversibleEncryptionEnabled()` accessors. Both
boolean updates preserve every other bit. The conditional write guards the
complete previous bitmask, so a concurrent change to an unrelated bit causes
failure rather than being overwritten.

`PolicyInterval` counts positive 100ns ticks and serializes to a negative LDAP
delta time. It covers values larger than Go's `time.Duration`; `PolicyNever`
represents LDAP `-9223372036854775808`. Use
`PolicyIntervalFromDuration(30*time.Minute)` for ordinary durations, or
`PolicyInterval(ticks)` for longer finite values. `Duration()` rejects overflow;
the constructor rejects negative and sub-100ns values without rounding.

Explicit maximum-password-age zero follows the PowerShell cmdlet and writes
the never-expire sentinel. Other interval fields preserve zero literally.
For indefinite lockout, use `PolicyNever` explicitly. Validation compares the
merged lockout observation window and duration, so an omitted existing window
can make a shorter duration invalid. Password history is bounded at 1024;
minimum password length is bounded at 256, or 14 when the domain's `uASCompat`
is nonzero. The directory still enforces its permissions and other constraints.

For example:

```go
length := uint16(12)
complexity := true
result, err := client.UpdateDefaultDomainPasswordPolicy(ctx, ad.DomainPasswordPolicyUpdate{
    MinPasswordLength: &length,
    ComplexityEnabled: &complexity,
})
// Inspect err, result.WriteState, and result.Verified before proceeding.
```

## Failures and qualification

Each changed attribute is deleted using its exact observed value and then added
with its desired value in the same atomic Modify. No permissive-modify control
or unconditional replacement fallback is used. Only changed attributes are
written. Concurrent edits return `ErrPasswordPolicyChanged`; permission failures
return `ErrPasswordPolicyPermission`, retaining `LDAPError` and its native code,
matched DN, and diagnostic data. Ordinary error strings omit sensitive LDAP
diagnostics.

`WriteState` distinguishes not attempted, accepted, rejected, and uncertain
writes. Accepted writes remain accepted when readback fails and return
`ErrPasswordPolicyReadback`. Lost responses return `ErrPasswordPolicyUncertain`
and retire the LDAP session. Cancellation, Close, and abandon cannot undo a
submitted write. No write, failed conditional update, or uncertain result is
automatically replayed; read state from a fresh connection before any further
decision. `Verified` describes the connected replica, not forest convergence.

Portable tests cover exact interval round trips, missing/malformed values,
explicit zeros, omitted values, unknown flags, conditional failure, domain and
RODC targeting, constraints, permission failures, uncertainty, and readback.
Windows boundary tests exercise the public policy update through the shared
native Modify implementation; existing FSMO cleanup/cancellation tests continue
to cover that implementation. No live directory updates were performed while
developing this slice.

Remaining qualification uses isolated Server 2016/2019/2022/2025 domains:
capture server/module versions; compare native reads with
`Get-ADDefaultDomainPasswordPolicy`; round-trip each setting and representative
combined patches against `Set-ADDefaultDomainPasswordPolicy`; verify unrelated
bits, permission failures, concurrent edits, interrupted responses, RODCs, and
restoration. Restore known fixtures only after reconciling each write outcome.

## Primary references

- [Get-ADDefaultDomainPasswordPolicy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2025-ps)
- [Set-ADDefaultDomainPasswordPolicy, including zero maximum-age handling](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy?view=windowsserver2025-ps)
- [MS-SAMR domain attribute update constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e270cd0a-5295-41be-9e89-2c3dc3a39536)
- [maxPwdAge signed 100ns storage](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/49fecab6-8d35-4a9a-8cd3-ceec7093486a)
- [Password property bit definitions](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-domain_password_information)
- [Lockout threshold schema range](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/8424289e-0a60-433e-abd7-02ff0c1afd1b)
