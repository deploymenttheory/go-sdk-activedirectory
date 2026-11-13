# Local managed service account installation

`InstallLocalServiceAccount` and `UninstallLocalServiceAccount` install and
remove a managed service account's credentials on the **executing Windows
host**, mirroring `Install-ADServiceAccount` and `Uninstall-ADServiceAccount`
(issue #47). They call the native managed-account APIs directly; runtime
PowerShell, AD Web Services and an installed agent are not required. Native
execution supports Windows amd64 and arm64; portable input validation and
models build elsewhere.

These are **local** operations. The account is resolved over LDAP against the
explicit endpoint you configure, but the credential change happens on this
machine. LDAP credentials are never forwarded to the Net APIs.

Observed reference behaviour is recorded in
[local service accounts](research/local-service-accounts.md).

## The host and the account must agree

The account and the executing host must belong to the same joined AD DS
domain; otherwise `ErrServiceAccountHost`. The host is identified
independently of the LDAP endpoint, so pointing the client at one domain while
running on a machine joined to another is rejected rather than half-applied.

For a standalone account, an association with another visible computer is
reported as `ErrServiceAccountOtherHost` and requires explicit `Force`. `Force`
is **not** a retry flag and not a native directory-create request.

### Replication is a precondition

The reference cmdlets take no `-Server`: they resolve the account through the
host's own domain controller locator. In the lab, an account created against
one controller was **not found locally** until it had replicated. An account
you have just written against an explicit endpoint is therefore not
necessarily usable on this host yet. This SDK resolves the account over your
configured endpoint, but the native install still depends on local host state;
do not assume immediacy.

## Passwords

`AccountPassword` supplies bytes directly. `PasswordPrompt` is the
non-interactive equivalent of `PromptForPassword`: the callback owns its UI,
the returned bytes transfer to the SDK, and they are erased on every exit — so
never return a shared or reusable buffer. Explicit `AccountPassword` takes
precedence.

**Neither form applies to a group managed account**, whose password the
directory manages. Supplying one for a gMSA is reported in
`PasswordOptionsIgnored` rather than silently dropped.

The request redacts itself on every formatting path — `String`, `GoString`,
`MarshalJSON`, `MarshalText`, and therefore `%v`, `%s`, `%#v` and `%+v`. A unit
test asserts all of them, including when the request is embedded in another
struct, because adding a path that prints fields by default would leak the
credential.

## Outcomes are observed, not assumed

`Before` and `After` report Netlogon-store presence as a **tri-state**: true,
false, or unknown. Unknown is never read as absent, because installing over an
unknown state could be a silent overwrite.

`Verified` means the post-operation observation actually showed the requested
state; `Complete` follows it. A successful native status with an observation
that disagrees is `ErrServiceAccountLocalObservation`, not a success.

Native status preserves the NTSTATUS bit pattern and is never reinterpreted as
a Win32 error. `STATUS_ACCESS_DENIED` and `STATUS_PRIVILEGE_NOT_HELD` both
match `ErrServiceAccountLocalPermission`. Formatted errors carry no account or
password text.

`PartialEffectsPossible` is set whenever a native call was attempted: a
synchronous operation can change both local state and a standalone account's
directory link before returning an error. **No call is ever replayed
automatically**, and an uncertain outcome is `ErrServiceAccountLocalUncertain`
— reconcile before trying again.

`Preview` performs read-only preparation: no prompt is called and no native
mutation is attempted. It does not reserve an identity or prove permissions.

## Uninstall

Uninstall is **idempotent** — removing an account that is not installed
succeeds, which the lab confirmed. `ForceRemoveLocal` permits the documented
offline removal phase, and only on one specific reply
(`STATUS_NO_SUCH_DOMAIN`) with no error and no cancellation. It is never used
to repeat an unknown or interrupted online operation.

## Concurrency

Local workflows in this process are serialised through a gate, so two
installs cannot interleave. External tools and other processes remain
concurrent — the gate is not a machine-wide lock. A caller whose context is
already cancelled does not wait on it. Synchronous native calls are allowed to
finish before their owned input buffers are erased, even after cancellation.

## Readiness

`ServiceAccountReadiness` mirrors `Test-ADServiceAccount` (issue #48). It
reports whether **this host can use the account**, not whether the account is
installed locally: a group managed account reads ready before it is ever
installed and still ready after it is uninstalled.

A native differential run paired every cmdlet result with the underlying
readings and found the reference's answer matches `NetIsServiceAccount`
exactly across every observed state, so that is what this mirrors. `Ready` is
nil only alongside an error — an incomplete reading is never reported as "not
ready", because that is indistinguishable from a genuine negative and could
send a caller to reinstall a working account.

### Uninstall verification is scoped on purpose

For a group managed account the native presence reading **never flips** after a
successful uninstall. Requiring it would fail every such uninstall, so
verification is scoped to standalone accounts and a gMSA uninstall completes
*unverified*, reporting the presence it actually read. No reading that
distinguishes a gMSA's local installation has been found; nothing here claims
to report one.

## Not implemented here

`Reset-ADServiceAccountPassword` (#49) is **not** implemented. The lab settled
that it requires local installation (`Referenced service account is not
installed on this computer`), which makes it a local operation, but not which
native call reproduces it. It remains `unverified` and is not guessed at.
