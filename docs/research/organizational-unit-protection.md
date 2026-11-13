# Organizational-unit protection contract

Issue #17 covers typed OU CRUD and accidental-deletion protection. This note
records primary sources and a read-only inspection of Microsoft's installed
reference implementation. No directory connection or mutation was performed.

`New-ADOrganizationalUnit` implicitly enables protection. Its headless default
path is the endpoint's default naming context; AD LDS needs a configured
default naming context or explicit path. The cmdlet documents AD LDS examples.
[Create reference](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adorganizationalunit?view=windowsserver2025-ps).

The property is derived from `nTSecurityDescriptor`, `sdRightsEffective`,
`instanceType`, and `isDeleted`; it is not an independently writable attribute.
[Object model](https://learn.microsoft.com/en-us/powershell/module/activedirectory/about/about_activedirectory_objectmodel?view=windowsserver2025-ps).

Read-only reflection/IL inspection of
`C:/Windows/Microsoft.NET/assembly/GAC_64/Microsoft.ActiveDirectory.Management/v4.0_10.0.0.0__31bf3856ad364e35/Microsoft.ActiveDirectory.Management.dll`,
file version `10.0.26100.7920`, SHA-256
`0DF8B9B0B77C652BB65971C3745B2B7E99AA899A0390CDDAB12142ED96EB1FC7`,
found these local behaviors in `Commands.ProtectedFromDeletionUtil`:

- `ShouldProtectByDefault` selects `organizationalUnit` or OID `2.5.6.5`.
- Enabling checks the parent for an Everyone deny-delete-child rule and adds
  it when absent, then adds the object's deny-delete/delete-tree rule.
- Disabling removes the object's protection rights and retains the parent ACL.
- For ordinary live objects, the observed property combines the object and
  parent checks; missing security descriptor data can make it unknown.
- The reference constants are ordinary deny rules for SID `S-1-1-0`, no
  inheritance/propagation/object GUID flags: object mask `0x00010040`, parent
  mask `0x00000002`.

No directory-aware method was invoked. These observations establish one
installed reference version, not live parity across Windows Server versions.
The parent operation is significant: it affects sibling deletion permission
and cannot be rolled back automatically without risking unrelated use.

Microsoft also describes the object/parent deny permissions as bulk-deletion
protection. [Recovery guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/retore-deleted-accounts-and-groups-in-ad).

Recursive deletion of an unprotected ancestor may remove protected children;
the reference cmdlet explicitly documents this. Preserve the generic CRUD
engine's explicit recursive intent and partial-effects result instead of
treating protection as a universal deletion barrier.
[Remove reference](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adorganizationalunit?view=windowsserver2025-ps).
