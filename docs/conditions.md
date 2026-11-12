# Headless conditional expressions

The `conditions` package builds conditional ACE expressions and uses native
Windows APIs to compile them into SDDL. It is the initial headless building block
for `Show-ADAuthenticationPolicyExpression` coverage. Authentication-policy
From/To behavior and directory claim semantics still need AD lab validation.

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

The package tests also pass on Server 2025 build 26100.32230 (AMD64) in the
isolated reference lab. [Recorded test output and source hashes](../coverage/lab/server2025/native-conditions.json)
cover local syntax, round trips, and repeated compilation. They do not measure
allocation/free balance, detect leaks, or validate directory policy semantics.

## Sources

- [AddConditionalAce](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-addconditionalace)
- [Conditional ACE SDDL syntax](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)
- [LocalFree return contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree)
