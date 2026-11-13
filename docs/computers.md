# Computer lifecycle

`Computer`, `Computers`, `CreateComputer`, `UpdateComputer`, and `DeleteComputer`
provide computer account operations through native LDAP. Creating an account
does not join a machine, install a machine secret, configure a secure channel,
register DNS records, or derive SPNs. The SDK operates only on the selected
directory connection.

Reads accept explicit DN/GUID identities on AD DS and on AD LDS schemas extended
with a `computer` class. The default AD LDS schema has no computer class. AD DS
also accepts SID and literal unqualified SAM identities. Managed service account
classes are excluded. Creation, update and deletion require AD DS, following the
documented ADComputer command capabilities. Unsupported directories return a
`DirectoryCapabilityError`; there is no fallback server or partition.

```go
account, err := ad.IdentityByAccountName("APP01$")
// Check err before using account. Identity matching is literal: the resolver
// does not append $, try a second name, or accept an ambiguous result.
observed, err := client.Computer(ctx, account, ad.ResolveIdentityOptions{})
```

`Computers` accepts the existing `SearchOptions` and combines its typed/raw filter
with the computer class and service-account exclusions. Empty Base selects the
configured partition or server default naming context; scope remains explicit.
Paging, result bounds, cancellation and partial results retain their Search
semantics. `Observation` retains raw rows even after permission, decoding or
cleanup errors. Inspect errors and Complete before assuming retrieval finished.

```go
computers, err := client.Computers(ctx, ad.SearchOptions{
    Base: "OU=Servers,DC=example,DC=test", Scope: ad.ScopeSubtree,
    TypedFilter: ad.FilterEqual("operatingSystem", ad.FilterText("Windows Server 2025")),
    PageSize: 256,
})
```

Common typed fields include SAM/DNS/UPN names, description, display name,
location, explicit ManagedByDN, home page and operating-system attributes.
AccountExpires and LastLogonDate preserve raw FILETIME values and sentinels;
LastLogonDate maps `lastLogonTimestamp`, not an exact latest logon. AccountControl
retains stored and server-computed flags separately. Nil values are unavailable,
not false or zero. Raw projections preserve absent/unloaded/ranged states; SPNs,
certificates and `msDS-AllowedToDelegateTo` expose `AttributeValues` directly.

Creation requires an explicit parent and a literal name, escaped using the
schema-aware object creator. It creates class `computer` with workstation-trust
and disabled flags. It does not create a domain controller. Omitted SAMAccountName
derives from Name. Typed SAM names on create/update receive one trailing `$` when
absent; existing suffixes are preserved, while empty names, `$` alone and doubled
trailing suffixes are rejected. Other naming and uniqueness constraints remain
server-enforced. Raw SAM changes are rejected; the literal identity API is
separate from this property normalization.

```go
parent, err := ad.IdentityByDN("OU=Servers,DC=example,DC=test")
// Check err before using parent.
dns := "app01.example.test"
created, err := client.CreateComputer(ctx, ad.CreateComputerRequest{
    Parent: parent, Name: "APP01",
    Properties: ad.ComputerProperties{DNSHostName: &dns},
})
// Creates APP01$ disabled. Always inspect err and the stage results.
```

By default the SDK leaves creation disabled without a password. This differs
from New-ADComputer's random-password/default-enable behavior. InitialPassword
is an explicit caller-owned UTF-8 byte slice using the shared administrative
password reset. Nil omits that stage; an explicit empty slice requests an empty
password subject to directory policy. Known insufficient session encryption is
rejected before Add. See [password protection and lifetime](account-passwords.md).

`Control.Enabled=true` enables only after verified creation and an accepted
password stage. Enabling without password setup requires explicit
`Control.PasswordNotRequired=true`, still subject to directory policy. Password,
enablement and Add outcomes remain separate in ComputerCreationResult. Any error,
uncertain outcome or failed verification stops subsequent stages. No stage is
replayed, and a later failure never automatically deletes the accepted account.
The stages share an overall deadline but are not a transaction. Computer is the
last successful typed observation; Complete is not proof of logon or replication.

Updates combine typed properties, the shared AccountControlPatch and explicit
AttributeChange operations in one atomic Modify. Nil pointers omit a change;
empty text sets a literal empty value. Clear is explicit. Typed/raw conflicts
are rejected. To preserve other SPNs, use AddValues/RemoveValues rather than Set:

```go
changed, err := client.UpdateComputer(ctx, ad.UpdateComputerRequest{
    Identity: account,
    Changes: []ad.AttributeChange{
        {Attribute: "servicePrincipalName", Kind: ad.AttributeRemoveValues,
            Values: []ad.RawValue{ad.NewRawValue([]byte("HOST/old.example.test"))}},
        {Attribute: "servicePrincipalName", Kind: ad.AttributeAddValues,
            Values: []ad.RawValue{ad.NewRawValue([]byte("HOST/app01.example.test"))}},
    },
})
```

Disjoint remove/add pairs run remove-first in the same strict Modify; there is
no permissive modify or automatic retry. DNS/SPN validation, duplicate SPNs,
delegation privileges and schema constraints are enforced by the directory and
retain native LDAP errors. Setting DNSHostName does not synthesize SPNs.

AccountControlPatch exposes shared delegation and security flags while retaining
unrelated UAC bits. Exact-old deletion followed by addition guards the observed
mask server-side. KerberosEncryptionTypes uses Flags32 with the low five
encryption bits (DES 0x3, RC4 0x4, AES128 0x8, AES256 0x10). An explicit zero
clears those bits while retaining other flags. CompoundIdentitySupported changes
0x40 independently. Both use exact-old updates on msDS-SupportedEncryptionTypes,
preserving unknown and unrelated bits. A missing/hidden old mask is unavailable,
not zero, and rejects the update. Computer/services may later update their own
encryption attribute. This API does not report stored flags as negotiated cipher
strength. Newer encryption-type selectors are not exposed by this typed subset.

Raw UAC, managed encryption flags, password attributes and pwdLastSet changes are
rejected by the computer API. Use AccountControlPatch.ChangePasswordAtLogon for
updates; false writes the server instruction -1 and verifies a positive timestamp,
not the literal -1. This option is unsupported during creation. PasswordNeverExpires
cannot be set over a pending password-change requirement unless it is explicitly
cleared in the same request. Password setup uses the dedicated password APIs.

Already-satisfied flag-only updates perform no write and retain requested extra
properties. ExpectedVersion is rejected for such no-ops. Other updates inherit
the [generic object assertion and readback contract](directory-objects.md).
Acceptance, readback completion and Verified are separate: normalization, hidden
or ranged values, or concurrent writes may prevent exact verification.

DeleteComputer defaults to leaf deletion. Recursive=true explicitly requests one
critical tree delete for owned child objects; it is not an atomic subtree action.
A rejected adminLimitExceeded response may already have removed descendants.
PartialEffectsPossible remains true, and the SDK never repeats the request to
finish. This explicit choice differs from Remove-ADComputer's child-deletion
behavior. No machine is unjoined or reconfigured by deleting its account.

This draft slice leaves default-container discovery, random-password generation,
instance/template operations, authentication-policy/silo principal resolution,
resource-based delegation security-descriptor mapping and automatic property
aliases outside the implementation. Raw binary/multivalue changes remain explicit
directory attributes, not claimed typed parity for those features. No runtime
PowerShell or RSAT is used. Live PowerShell comparisons on Server 2016/2019/2022/2025,
extended-schema LDS reads, real naming/SPN/policy/permission cases and full issue
#19 qualification remain open.

Portable tests cover mapping, Unicode, flags, raw conflicts, partial reads,
capability/class guards, explicit recursive partial effects and staged failures.
The actual WinLDAP loopback test checks one GUID-addressed Modify containing
Unicode DNS/SPN values and both conditional masks, native rejection without
replay, and native ownership cleanup. It performs no AD operation.
`examples/computers` reads by default and requires `-apply` for a mutation.

References: [New-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adcomputer?view=windowsserver2025-ps),
[Get-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps),
[Set-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adcomputer?view=windowsserver2025-ps),
[Remove-ADComputer](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adcomputer?view=windowsserver2025-ps),
[computer schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/142185a8-2e23-4628-b002-cf31d57bb37a),
[encryption flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919),
[domain join state](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/29b5bf6a-68a3-4a7c-a8ef-480dcb94a0be).
