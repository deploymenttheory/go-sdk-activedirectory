# Managed service accounts

`ServiceAccount` and `ServiceAccounts` read sMSA/gMSA objects by the shared
explicit identity and search types. `CreateServiceAccount`,
`UpdateServiceAccount`, and `DeleteServiceAccount` manage their directory
lifecycle. dMSAs are rejected; migration and local installation/testing/reset
are separate operations. All execution uses native WinLDAP, including Windows
amd64 and arm64. Portable builds support request construction and validation.

```go
dns := "svc.example.test"
created, err := client.CreateServiceAccount(ctx, ad.CreateServiceAccountRequest{
    Kind: ad.ServiceAccountGroupManaged,
    Name: "svc",
    Properties: ad.ServiceAccountProperties{DNSHostName: &dns},
    PasswordReaders: []ad.Identity{computerOrSecurityGroup},
})
// Inspect created.Creation.State and created.Complete even when err != nil.
```

An omitted parent resolves the MSA container through `otherWellKnownObjects`
GUID `1EB93889E40C45DF9F0C64D23BBB6237`; the SDK never guesses its DN. An explicit
parent and selected domain partition must agree. This follows the directory's
[well-known object mapping](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5a00c890-6be5-4575-93c4-8bf8be0ca8d8).

Creation requires an AD DS LDAP endpoint, a writable domain NC, the appropriate
structural schema class, and a DC reporting the feature's functionality (2008
R2 for sMSA; 2012 for gMSA). There is no blanket forest/domain functional-level
2012 requirement. For gMSA the SDK reads only KDS key identity and validity
metadata and requires a visible key usable at the current ten-hour GKDI interval
start, using the DC's returned time. `Prerequisites` retains these observations
on errors. Hidden validity metadata, partial searches, future keys, or more than
128 keys fail before creation. This conservative check does not establish key
replication throughout the forest, key health, or password-retrieval permission.
No key is created or backdated. See [gMSA requirements](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts),
[KDS validity](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/06f397ae-4022-4d4a-8605-8cff67e9359f),
and [GKDI key selection](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/4cac87a3-521e-4918-a272-240f8fabed39).

Standalone creation first creates a disabled account, sets the explicit password
or a cryptographically random password, then enables it unless `Control.Enabled`
is false. A rejected or uncertain password stage never enters enablement.
Creation, password, enablement, and final observation are separately retained;
there is no rollback or automatic retry. Caller password bytes remain owned by
the caller. Internally generated password bytes are erased and never returned.

Normal gMSA creation requires `DNSHostName`. Set `OutboundAuthenticationOnly`
for the explicit gMSA form that omits DNS and inbound authentication setup.
This is a creation form, not a persistent LDAP flag or a guarantee against
future changes. In that form, DNS, custom interval, retrieval readers, and
compound-identity options must be omitted. gMSAs use server-managed passwords;
`InitialPassword` is rejected. Accounts default to enabled, and the interval
defaults to 30 days. The interval accepts positive signed 32-bit day counts only
at creation; Set cannot change the system-managed interval. These behaviors
follow [New-ADServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount?view=windowsserver2025-ps).

## Properties and access descriptors

| Property | API |
| --- | --- |
| SAM, DNS, display name, description, home page | `ServiceAccountProperties` pointers |
| Account expiration | `AccountExpires *FileTime`; preserves sentinel values without locale conversion |
| SPNs | `ServicePrincipalNames *[]string` replaces/clears; `Changes` supports strict add/remove |
| Kerberos encryption and compound identity | Typed independent masks preserve all other bits using conditional LDAP delete/add |
| Enabled and delegation flags | Shared `AccountControlPatch`; password-policy switches inappropriate for managed passwords are rejected |
| Certificates | `userCertificate` binary `RawValue` through `Attributes`/`Changes`; read as `Certificates` |
| Authentication policy and silo assignment | Explicit `msDS-AssignedAuthNPolicy` / `msDS-AssignedAuthNPolicySilo` DN values through `Attributes`/`Changes`; policy/silo lifecycle and grants remain separate APIs |
| Resource-based constrained delegation | Explicit full `msDS-AllowedToActOnBehalfOfOtherIdentity` descriptor bytes through `Attributes`/`Changes`; this is a caller-supplied whole-value replacement, not a SID-list merge |
| Managed-password retrieval principals | `PasswordReaders` on creation; pointer on update replaces only explicit ordinary Read Property allow grants |

Raw changes retain native server validation for reference class, permissions,
cross-domain and schema restrictions. They cannot bypass the managed interval,
password, retrieval-descriptor, account-control or encryption-field guards.
Typed/raw conflicting assignments are rejected. `ExpectedVersion` uses the
existing critical GUID/USN assertion; a no-op cannot claim it was enforced.

The retrieval descriptor is `msDS-GroupMSAMembership`. Its access check uses
Read Property, as specified by [managed-password processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68).
Updates resolve every supplied principal to a returned SID, remove only bit
`0x10` from ordinary explicit allow ACEs, and add the requested grants. Owner,
group, SACL, descriptor control/RM bits, inherited/deny/conditional ACEs and
unrelated permission bits survive. A conditional delete of the old full value
followed by an add prevents silently replacing a concurrently changed value.
An absent/unreadable or NULL-DACL descriptor cannot be edited. An empty reader
slice removes the editable grants; it does not promise effective denial when
other ACE forms grant access. Read observations similarly describe this ACE
pattern, not effective authorization. New descriptors use SYSTEM owner/group
and an initially empty DACL.

The service-account APIs never request managed-password blobs, historical
passwords, or KDS root key material. Wildcards and numeric attribute aliases
are rejected in extra projections; named password projections are rejected too.
Creation requests redact formatting/JSON. Low-level `Search` remains a separate,
explicit raw LDAP interface.

## Computer associations

`AddComputerServiceAccounts` and `RemoveComputerServiceAccounts` resolve every
service-account identity before one atomic `msDS-HostServiceAccount` Modify.
Duplicate identities are detected by returned GUID. The default is strict;
`Permissive` requires the advertised critical permissive-modify control. Domain,
nesting, sMSA single-host and access restrictions remain server decisions.
These links neither install the account nor grant gMSA password access; see
[Add-ADComputerServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adcomputerserviceaccount?view=windowsserver2025-ps).

`ComputerServiceAccounts` collects contiguous ranges then resolves each returned
DN. Limits default to 100,000 links, 1,000 responses and 64 MiB of attribute
bytes; callers may lower them. Each received raw response survives errors and
limit crossings. GUID and `uSNChanged` must stay stable across all responses.
This detects changes; it does not promise an atomic snapshot or ACL visibility.
Per-link observations/errors survive failed resolution. `AttributeReturned`
distinguishes omission from an explicit empty value set.

Mutation readback uses the same bounded range collector and structural DN
comparison. `Links` retains raw readback ranges, without resolving each linked
account again. `Verified` is true only after the complete link set confirms the
requested change. If removing the last link yields an omitted attribute, the
write remains accepted but unverified. Partial or uncertain results never
authorize replay. Inspect mutation state independently of readback errors.

## Validation and remaining qualification

Portable fixtures cover all creation forms, disabled/password/enable staging,
prerequisite failures, secret/conflicting inputs, descriptor preservation,
common property paths, strict/uncertain outcomes and bounded ranged readback.
Native loopback tests cover gMSA Add, binary descriptor compare-and-write,
Unicode association Modify, the critical permissive control, LDAP rejection
codes, forced GC and zero outstanding native owners. Native SDDL tests retain
conditional, deny, inherited and SACL components. No AD objects are involved.

This remains a draft implementation for issue #46. Live sMSA/gMSA creation,
password-retrieval denial/allowance, KDS visibility and replication, sMSA host
exclusivity, cross-domain references, and PowerShell differential qualification
on Server 2016/2019/2022/2025 have not been run. This work does not claim local
installation/test/reset or dMSA migration parity. The runnable example reads by
default and requires `-apply` for a directory mutation.
