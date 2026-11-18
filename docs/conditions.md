# Headless conditional expressions

The `conditions` package builds conditional ACE expressions and compiles them
portably using the MS-DTYP grammar and binary token format. This is the headless replacement
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

`NormalizeSDDL` accepts a full descriptor and returns a deterministic SDDL
representation, preserving owner, group, DACL, and SACL information. It may
use SID abbreviations or normalize expression formatting, so input and output
need not be textually identical.

`DescriptorBytes` compiles SDDL to owned self-relative binary bytes, preserving
all supported descriptor components and conditional ACEs without native allocations. This is
useful for binary directory attributes. The authentication-policy API adds its
own control-access and DACL checks; this generic serializer does not infer them.

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

`Raw` accepts the documented MS-DTYP condition language for constructs outside the typed
surface. Pass it to `Compile` for portable syntax validation. Raw input is not
executed as a shell command.

## Validation boundary

`Compile`, `NormalizeSDDL`, and `DescriptorBytes` use the same portable codec on every platform.
Successful compilation establishes that the supported MS-DTYP syntax and binary bounds are valid.
It does not establish that a claim exists in AD, that a user has that
claim, or that an authentication policy will allow the intended logon. Unknown
claim references can be syntactically valid.

Inputs must be nonempty, NUL-free UTF-8 and at most 65,535 bytes. ACL/ACE wire-size limits,
64 levels of expression nesting, and bounded value counts can reject input before that text limit.
Invalid syntax wraps `ErrInvalidExpression`; malformed binary wraps `ErrInvalidDescriptor`.

`ParseDescriptor` owns and bounds-checks a self-relative binary descriptor. Its `MarshalBinary`
returns the original bytes, including unknown ACE types, reserved fields, capacity, component
order, and aliased offsets. `DACL` and `SACL` return independent snapshots. `WithDACL` and
`WithSACL` return edited copies, preserve unrelated storage and ACE order, and distinguish absent,
NULL, and empty ACLs. Explicit NULL ACLs have different access meaning from empty ACLs.
`OwnerSID`, `GroupSID`, and `Control` expose copied trustees and original control bits.
`WithOwnerSID` and `WithGroupSID` preserve aliased sibling components. The
[offline descriptor example](../examples/securitydescriptors/main.go) adds one conditional
ACE while retaining owner, group, SACL, and the original descriptor.

`Descriptor.SDDL` formats supported security meaning rather than storage layout. It returns
`ErrUnrepresentableDescriptor` for opaque ACEs, application-specific callback data, or control
bits that SDDL cannot express. Binary marshaling remains available. `ParseSDDLWithOptions`
accepts explicit domain/machine SIDs for relative aliases such as `DA` or `LA`; no parser uses
the current host or directory to supply this context. The APIs do not evaluate effective access.

A descriptor read with LDAP SD-flags may contain only selected sections. The caller must retain
that loaded-section scope and write only the intended sections; an unloaded section does not
prove that the directory's owner, group, or SACL is absent.

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

## Portable reference checks

The [independent native corpus](../conditions/testdata/README.md) records local Windows binary
conversions, including conditional operators and all six resource-attribute value types. Portable
tests compare independent binary expectations and canonical SDDL, preserve native rejections and
quirks separately, and fuzz malformed binary/text inputs. These local conversions do not qualify
directory updates or any Server-version acceptance matrix. Portable SDK06 directory qualification
remains pending.

## Historical native qualification

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

The retained checks above exercised the former native compiler. Current package tests exercise
the portable compiler on every CI platform and retain native allocation/reference checks on
Windows amd64 and arm64. Linux and macOS also cross-compile the native reference test
executable for both Windows architectures. Each Server-version result is
recorded separately; a passing Server 2025 run does not qualify older Servers.

## Sources

- [AddConditionalAce](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addconditionalace)
- [Conditional ACE SDDL syntax](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)
- [LocalFree return contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree)
- [Authentication-policy expression editor parameters](https://learn.microsoft.com/en-us/powershell/module/activedirectory/show-adauthenticationpolicyexpression?view=windowsserver2025-ps)
- [Authentication-policy SDDL properties and audit mode](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adauthenticationpolicy?view=windowsserver2025-ps)
