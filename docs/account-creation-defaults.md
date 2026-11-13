# Account creation containers

`CreateUser`, `CreateGroup` and `CreateComputer` accept an omitted `Parent`.
The SDK discovers the selected naming context's configured container before
creating anything. Explicit parent DN/GUID identities retain their existing
behavior and do not perform default-container discovery.

```go
sam := "example-user"
created, err := client.CreateUser(ctx, ad.CreateUserRequest{
    Name: "Example User",
    Properties: ad.UserProperties{SAMAccountName: &sam},
})
// Inspect err and created.Creation.State. This example creates disabled.
```

The selected partition is `Options.Partition`, then `Config.Partition`, then the
server's default naming context. It must be advertised by that connection.
The SDK reads its complete `wellKnownObjects` attribute and selects the protocol
Users GUID for users/groups or Computers GUID for computers. The configured DN
is used verbatim after syntax and naming-context checks, including redirected
OUs, Unicode names and escaped DN values. Fixed `CN=Users`/`CN=Computers` paths
are never synthesized. AD LDS uses the applicable Users well-known mapping,
normally its Roles container; computer creation still requires AD DS.

No default naming context, absent/hidden mappings, malformed/duplicate values,
partial ranges, failed reads or targets outside the selected naming context
produce an error before Add. `AccountCreationParentError` retains the lookup's
raw candidates and underlying errors. A read failure never chooses a fallback
container. The normal creator then resolves the selected parent and uses its
schema-aware naming and native write checks. Discovery and creation share one
overall timeout. They are not atomic against a concurrent redirection or parent
move; an explicit parent can be used when a fixed target is required.

The user, group and computer examples now permit omitting `-dn` for create.
They still require `-apply`; their default operation remains a read.

Portable public-workflow tests cover all three object types, redirected Unicode
containers, explicit-parent precedence, request/config/server partition priority,
AD LDS Roles, unavailable data and failure without writes. Native WinLDAP tests
exercise the actual mapping query/BER response, partial permission failures and
resource cleanup. Local inspection of the installed Microsoft module's
`GetDefaultCreationPathBase` methods confirms the Users/Users/Computers mapping.
No live redirection or creation was performed for these checks. Remaining issue
#18/#19/#20 lifecycle and supported-server/AD LDS qualification still applies.

References: [New-ADUser path defaults](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2025-ps#-path),
[New-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adcomputer?view=windowsserver2025-ps),
[New-ADGroup](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adgroup?view=windowsserver2025-ps),
[well-known objects and AD LDS Roles](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5a00c890-6be5-4575-93c4-8bf8be0ca8d8).
