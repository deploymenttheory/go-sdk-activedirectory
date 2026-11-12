# Headless conditional expressions

The `conditions` package builds conditional ACE expressions and uses native
Windows APIs to compile them into SDDL. This is the agreed headless replacement
for `Show-ADAuthenticationPolicyExpression`. It constructs descriptor text
without opening an editor, invoking PowerShell, or connecting to a directory.

## Build and compile

```go
expression := conditions.All(
    conditions.Compare(
        conditions.Claim{Scope: conditions.User, Name: "Department"},
        conditions.Equal,
        conditions.Text("Finance"),
    ),
    conditions.MemberOf(false, "S-1-5-32-544"),
)
sddl, err := conditions.Compile(conditions.ACE{
    TrusteeSID: "S-1-1-0",
    AccessMask: 0x100,
    Condition:  expression,
})
if err != nil {
    return err
}
```

The trustee and nonzero access mask are explicit. This example produces a
conditional allow ACE for Everyone with the illustrated mask; callers must
choose rights appropriate to their target object. Set `Deny: true` to create a
conditional deny ACE. The compiler returns a DACL-only descriptor and does not
write it to an object. A runnable example is in
[`examples/conditions`](../examples/conditions/main.go).

`NormalizeSDDL` accepts a full descriptor and returns Windows' text
representation, preserving owner, group, DACL, and SACL information. Windows may
use SID abbreviations or normalize expression formatting, so input and output
need not be textually identical.

## Expression surface

Typed builders support User, Device, and Resource claim references; string and
integer values; comparisons; existence; token membership; and boolean
composition with `All`, `Any`, and `Not`. `MemberOf(true, ...)` tests device token
membership. Numeric SID strings are required by the typed API.

Builders retain errors until `Render` or `Compile` is called. `Render` works on
all platforms and checks construction, encoding, and size limits. It does not
invoke the Windows expression parser. Strings reject embedded quotes, NUL, and
control characters; the typed API does not assume Go or JSON escaping is valid
Windows condition syntax.

`Raw` accepts the native condition language for constructs outside the typed
surface. Pass it to `Compile` for Windows syntax validation. Raw input is not
executed as a shell command.

## Validation boundary

`Compile` and `NormalizeSDDL` run on Windows amd64 or arm64; other platforms return
`ErrUnsupported`. Successful compilation establishes that Windows accepted the
syntax. It does not establish that a claim exists in AD, that a user has that
claim, or that an authentication policy will allow the intended logon. Unknown
claim references can be syntactically valid.

Inputs must be nonempty, NUL-free UTF-8 and at most 65,535 bytes. Native ACL size
limits can reject an expression before that text limit is reached. Invalid typed
construction wraps `ErrInvalidExpression`; native parsing failures retain their
underlying Windows errors.

## PowerShell parameter mapping

The SDK replaces the editor's interaction with explicit inputs and returned
text. It does not accept or silently ignore GUI and connection parameters.

| PowerShell parameter | Headless Go behavior |
| --- | --- |
| `AllowedToAuthenticateFrom` | Construct an expression for the source-device policy property; the caller chooses the property when storing it. Device membership uses `MemberOf(true, sid)`. |
| `AllowedToAuthenticateTo` | Construct an expression for the destination policy property; user token membership uses `MemberOf(false, sid)`. |
| `SDDL` | Pass an existing descriptor to `NormalizeSDDL`, or build a new conditional ACE with `Compile`. Normalization preserves descriptor components; it does not provide an interactive editing session. |
| `Title` | Caller-owned application presentation; there is no SDK dialog or title argument. |
| `AuthType`, `Credential`, `Server` | No equivalent on this local compiler. Directory authentication, endpoint selection, and resolving names or claims belong to the caller's separate directory operation. Numeric SIDs and explicit claims remove provider-drive and directory-picker defaults. |
| `WhatIf`, `Confirm` | No prompts or directory mutations occur. Successful calls return text for the caller to inspect and explicitly apply later. |

From/To selects a policy context, not a different SDDL grammar. Compiling an
expression does not prove that it is appropriate for that context. In
particular, a missing directory claim may compile successfully. Authentication
policy assignment and actual logon enforcement require separate directory
qualification.

## Qualification

The package tests also pass on Server 2025 build 26100.32230 (AMD64) in the
isolated reference lab. [Recorded test output and source hashes](../coverage/lab/server2025/native-conditions.json)
cover local syntax, round trips, and caller-owned allocation/free balance across
100 compile/normalize cycles. The tests also inject a missing export, native
access-denied errors at each stage, and cleanup failures; operation and cleanup
errors are retained together. The audit tracks the SID, descriptor, and output
buffers owned by this package, not Windows' internal allocations. These checks
do not establish directory policy semantics or real-directory permission checks.

Run the native and PowerShell reference checks in the disposable
[lab](lab.md):

```powershell
.\scripts\lab\lab.ps1 -Action TestConditions -ServerVersion 2025
```

The harness emits ten native SDDL cases, compares normalization and rejection
with PowerShell/.NET, and stores three From/To cases in temporary audit-only
authentication policies. No account is assigned a policy. It checks readback,
checks a real authorization denial for a newly created ordinary user, and
requires fixture cleanup on both DCs. Native errors injected by unit tests and
actual directory authorization errors are recorded separately. The retained
source snapshot, executable, corpus, and reference script have recorded hashes.
The [Server 2025 comparison](../coverage/lab/server2025/conditions-reference.json)
passed all ten SDDL cases and three policy readbacks, observed access denied,
and confirmed cleanup on both domain controllers (AD module 1.0.1.0,
PowerShell 5.1.26100.7462, schema 91).

CI executes the pure builders on Linux and macOS and the native compiler on
Windows amd64 and arm64. Linux and macOS also cross-compile the native test
executable for both Windows architectures. Each Server-version result is
recorded separately; a passing Server 2025 run does not qualify older Servers.

## Sources

- [AddConditionalAce](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addconditionalace)
- [Conditional ACE SDDL syntax](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)
- [LocalFree return contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree)
- [Authentication-policy expression editor parameters](https://learn.microsoft.com/en-us/powershell/module/activedirectory/show-adauthenticationpolicyexpression?view=windowsserver2025-ps)
- [Authentication-policy SDDL properties and audit mode](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adauthenticationpolicy?view=windowsserver2025-ps)
