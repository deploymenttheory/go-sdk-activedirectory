# Organizational units

`OrganizationalUnit`, `OrganizationalUnits`, `CreateOrganizationalUnit`,
`UpdateOrganizationalUnit`, `DeleteOrganizationalUnit`, and
`SetOrganizationalUnitProtection` use native LDAP and Windows security-descriptor
APIs. They do not invoke PowerShell. This is the implementation slice for
[#17](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/17);
live cross-version qualification remains open.

```go
identity, err := ad.IdentityByDN("OU=People,DC=example,DC=test")
if err != nil { return err }
observed, err := client.OrganizationalUnit(ctx, identity, ad.ResolveIdentityOptions{
    Properties: []string{"ProtectedFromAccidentalDeletion"},
})
// Inspect observed and err together; raw candidates survive incomplete reads.
```

OU identities use the existing explicit DN/GUID constructors and naming-context
rules. A returned class must include `organizationalUnit`. The typed result
includes DN, GUID, name, description, display name, city, country, state, street,
postal code and managed-by DN, alongside the original `Object`. Missing scalar
properties remain nil; malformed values produce an error without discarding
raw bytes. Protection is read only when explicitly selected through
`Properties`; nil means unrequested or unknown, not false.

Search accepts the existing `SearchOptions`, including **explicit** scope,
paging and limits. The zero scope remains the SDK's base-object scope. Supply
`ScopeSubtree` for an OU listing. An empty base selects `Config.Partition`, then
the endpoint's default naming context. Raw or typed filters are intersected with
the OU class filter; specifying both remains invalid. Partial search results and
errors are retained. No search expands to another naming context.

Creation resolves the requested parent and reads the schema's naming attribute.
`Name` is a literal RDN value, so commas and other metacharacters are escaped by
generic CRUD. An omitted parent uses `Options.Partition`, then the configured
partition, then the endpoint default. AD LDS
without either requires an explicit parent. Typed `OUProperties` use nil to
omit a change; a pointer to an empty string sets one empty value. Use a common
`AttributeChange{Kind: AttributeClear}` to clear. `ManagedBy` accepts an explicit
DN. Additional raw attributes use the same validation and exact-value semantics
as [generic object mutations](directory-objects.md).

## Protection and permissions

New OUs default to protection enabled, matching
[`New-ADOrganizationalUnit`](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adorganizationalunit?view=windowsserver2025-ps).
Pass a non-nil false `ProtectedFromAccidentalDeletion` to request an unprotected
creation; nil on **update** leaves protection unchanged.

Protection adds an explicit Everyone (`S-1-1-0`) deny-delete-child ACE on the
parent when needed, then an explicit deny-delete/delete-tree ACE on the OU.
The parent ACE affects sibling deletion permissions. Unprotect removes only the
OU's explicit protection rights and leaves the parent's ACE intact. An OU that
is itself a naming-context head uses its own ACL without an external parent.
When the derived reference property is already false, unprotect is a no-op;
it does not clean up partial protection patterns.
See the [reference investigation](research/organizational-unit-protection.md).

Descriptor reads require `READ_CONTROL`; changed DACLs require `WRITE_DAC` on
the affected objects, in addition to ordinary create/update/delete permissions.
Enabling protection may require rights on both parent and OU. Missing or denied
descriptors stop the workflow before dependent writes. Inherited rights cannot
be removed by this operation. Unknown/object/callback ACE patterns can make the
derived property unknown. NULL DACLs are rejected instead of being converted
from allow-all to a different policy.

The implementation copies unrelated, inherited and opaque ACE bytes. Windows
builds the resulting self-relative descriptor; the critical
[`LDAP_SERVER_SD_FLAGS_OID`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0)
control restricts reads and changes to the DACL. Owner, group and SACL are outside
the update. Readback checks the GUID, requested protection pattern and survival
of expected ACE bytes, allowing server reordering. Unexpected normalization or
missing ACEs produces an unverified result, preserving the accepted write state.

ACL changes are read/modify/write operations. Preservation applies to the
observed descriptor; another writer can race between observation and submission.
A single OU version cannot guard a parent-plus-OU operation, so enabling
protection with `ExpectedVersion` is rejected. An unprotect-only request may use
the common critical assertion control when the endpoint advertises it. Attribute
changes plus protection cannot share one version assertion and are rejected when
that precondition is requested. A no-op cannot enforce a server-side version
assertion and is also rejected when `ExpectedVersion` is supplied. No unsupported
control is silently weakened.

## Outcomes and deletion

Creation, attribute changes, parent ACL changes and OU ACL changes are separate
operations. An error may accompany an accepted object Add or earlier ACL write.
`Object` retains the ordinary mutation state; `Protection.Steps` retains each
target, before/after raw observations, accepted/rejected/uncertain state and
verification. The SDK does not retry, reconnect, or roll back a partial change.
Reconcile these outcomes before deciding what to do next.

Deletion never disables protection implicitly. The server's protected-object
permission error is preserved. `Recursive: true` is explicit tree-delete intent;
its result can have partial descendant effects even when rejected. Protected
children can be removed by recursive deletion of an unprotected ancestor, as
documented by
[`Remove-ADOrganizationalUnit`](https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adorganizationalunit?view=windowsserver2025-ps).
The protection property is not a universal effective-access guarantee.

## Example and validation

`go run ./examples/organizational-units -server dc.example.test -dn
'OU=People,DC=example,DC=test'` reads an OU and its protection state. The example
requires both an explicit write operation and `-apply` before changing anything.
It uses the current Windows identity; application code can use any supported
SDK authentication configuration.

Portable tests exercise typed filters/raw partial results, default protected
creation, explicit unprotected creation, update/delete, class and cancellation
guards, parent-first partial/uncertain outcomes, unknown/inherited ACLs and AD
LDS naming-context roots. Windows host tests call the actual descriptor APIs,
copy object-specific/inherited ACEs, and check the native critical-control
pointer lifetime and termination. `scripts/reference-ou-acl-local.ps1` records
the installed Microsoft reference constants and local .NET ACL transformations;
it makes no directory connection.

No live OU fixture has been run for this change. Protected/unprotected/nested
fixtures, parent/OU permission failures, concurrent writers and raw ACL/typed
PowerShell comparisons remain pending on AD DS 2016/2019/2022/2025 and applicable
AD LDS profiles. Host-only success does not qualify those environments.
