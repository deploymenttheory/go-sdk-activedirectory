# Authentication policies and direct account assignments

`AuthenticationPolicy`, `AuthenticationPolicies`, `CreateAuthenticationPolicy`,
`UpdateAuthenticationPolicy`, and `DeleteAuthenticationPolicy` provide typed
policy CRUD. `SetAccountAuthenticationPolicy` assigns or explicitly clears the
direct policy link on a user, computer, managed-service, or group-managed-service
account. It does not assign a silo, grant silo membership, or calculate an
effective policy. A silo can take precedence over the direct policy link.

These methods use native LDAP, the shared `Identity`, `RawValue`, filters,
`AttributeChange`, and mutation-result APIs. They neither invoke PowerShell nor
contact another endpoint. Policy DN/GUID identities are constrained to
`CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,<configuration NC>`.
The configuration NC is selected explicitly by these policy methods, independently
of `Config.Partition`; a conflicting per-call partition is rejected. Account
assignment uses the account's requested/default domain partition and rejects
cross-domain or application-NC targets. SID/SAM identities are account forms,
not policy-name aliases. Use `FilterEqual("name", FilterText(name))` to find a
policy by name and then use its returned GUID for a mutation.

## Properties and update intent

| Cmdlet property/surface | SDK representation |
| --- | --- |
| Name | Literal `CreateAuthenticationPolicyRequest.Name`, escaped as an RDN; reads preserve `Name`. |
| Description | Optional string in `AuthenticationPolicyProperties`. |
| Enforce | Optional `Enforced` boolean. New policies default to explicit false (audit); updates omit nil. |
| User/Computer/ServiceTGTLifetimeMins | `*Interval100ns` lifetime fields use the exact LDAP positive 100ns count. One minute is 600,000,000 ticks; zero is explicit no override. No rounding or `time.Duration` overflow is hidden. Negative writes are rejected; raw negative/sentinel reads remain available. |
| User/ServiceAllowedToAuthenticateFrom | Optional SDDL strings compiled locally into binary descriptors. |
| User/Computer/ServiceAllowedToAuthenticateTo | Optional SDDL strings compiled locally into binary descriptors. There is no invented computer “From” property. |
| User/ServiceAllowedNTLMNetworkAuthentication | Optional booleans, including explicit false. These allowances concern NTLM when the corresponding From restriction exists; they do not make Kerberos claims available to NTLM. |
| RollingNTLMSecret | Optional `StrongNTLMPolicy`: Disabled, Optional, Required. Unknown stored values are preserved on reads. Microsoft deprecated this feature beginning with Windows 10 1703; the SDK never sets it by default or claims current clients implement it. |
| ProtectedFromAccidentalDeletion | Optional explicit protection change; request the property in read `Properties` to inspect the shared ACL pattern. Nil on creation leaves the schema/default ACL unchanged. |
| OtherAttributes / Add / Remove / Replace / Clear | Raw `Attributes` for creation and shared `Changes` for updates. Binary/multiple/zero-length values remain distinct. Known scalar properties validate syntax; descriptor writes use typed SDDL, while raw Clear is supported. Raw nTSecurityDescriptor and assignment changes require their dedicated operations. |
| Instance | Supply explicit typed properties/raw changes. Returned objects are observations, not implicit dirty-tracked templates; copying operational/identity attributes into a new object is rejected. |
| Filter / LDAPFilter / paging / selected properties | Existing typed/LDAP `SearchOptions`, with the policy class intersected and a default one-level container search. Partial results and raw ranges remain explicit. |
| AuthenticationPolicy assignment | `Policy: &identity` or `Clear: true`, exactly one. |
| AuthenticationPolicySilo assignment | Not implemented here; owned by issue #41. |
| Server / Credential / AuthType | Existing explicit `Client` configuration. |
| PassThru / WhatIf / Confirm / provider/pipeline defaults | SDK calls return typed outcomes and execute when invoked. The example requires explicit operation and `-apply`; the SDK has no prompts, implicit provider selection, or PowerShell pipeline. |

A typed/raw duplicate is an error. Updates preserve omitted attributes and support
one disjoint exact-value remove/add pair in one strict Modify, remove first. They
do not use permissive modify. Empty SDDL is invalid; clear a descriptor with
`AttributeChange{Attribute: "msDS-UserAllowedToAuthenticateFrom", Kind: AttributeClear}`.
Clearing or setting zero is different from omission.

The installed Microsoft module file version `10.0.26100.7920` was inspected
offline for creation defaults. Its generic post-create protection helper returns
false for `msDS-AuthNPolicy` (and true for `organizationalUnit`), so omitted
protection does not add the protection ACL pattern. The SDK's nil protection
matches that behavior. The module also supplies false for the two NTLM allowances
and Disabled for rolling secrets; the SDK preserves nil omission for these
newer schema properties. Supply explicit false/Disabled when those stored values
are required. This avoids silently writing attributes unavailable in a 2012 R2
schema, while retaining explicit prerequisite errors for requested newer fields.

## Headless descriptors

`conditions.Compile` builds SDDL from an explicit trustee, mask, and conditional
expression. Policy fields call `conditions.DescriptorBytes` to validate it using
Windows and obtain owned self-relative binary bytes. The shared conversion
preserves owner, group, DACL, SACL, ACE order and conditions, and releases native
memory before returning. It is available on Windows amd64/arm64; other platforms
return `conditions.ErrUnsupported` for compilation, while portable types/builders
and raw-value inspection remain usable.

Authentication uses `ACTRL_DS_CONTROL_ACCESS` (`CR`, mask `0x100`): From checks
the armored authentication request's PAC, and To checks the requesting PACs when
authenticating to the account's service. The SDK requires a bounded, non-NULL DACL
and a potentially applicable control-access/generic-all ACE, or an explicit empty
DACL (deny all). Ordinary/object allow and deny ACEs and their conditional forms
are preserved. Unknown DACL ACE types and ACLs containing only unrelated or
inherit-only rights are rejected for writes. No ACL is silently rewritten into
an allow-all or deny-all policy. Other masks and supported ACEs are retained.

Windows syntax acceptance does not establish that a claim exists, that the KDC
supplies it in the selected context, that device armoring/Dynamic Access Control
is configured, or that any principal can authenticate. Stored descriptors are
read as exact `RawValue` bytes, including unknown/invalid values; reads do not
normalize or repair them. Audit mode and enforced mode remain distinct stored
states, and a verified directory write is not a verified logon decision.

## Prerequisites, protection, and results

Policy reads require AD DS and DC functionality at least Windows Server 2012 R2.
Writes additionally require domain functionality at least 2012 R2, schema version
69, a synchronized writable DSA, and a full LDAP endpoint. NTLM allowance/rolling
attributes require schema version 85 and DC functionality at least 2016. These
guards do not upgrade the directory or configure client/KDC policy. AD LDS,
RODC/GC writes, missing required observations, invalid conditions, and unsupported
preconditions produce explicit errors. The server retains final permission,
schema, naming, and reference-constraint authority.

Attribute writes are single native LDAP Add/Modify/Delete operations. Optional
accidental-deletion protection follows a verified attribute write using the
existing parent/object DACL workflow. Enabling protection can add a parent deny
delete-child ACE affecting siblings. Disabling removes only the recognized
explicit object protection rights; it does not undo the parent's rule or remove
unrelated/inherited ACEs. Each protection step has its own accepted/rejected/
uncertain state. A later failure never rolls back or obscures an earlier accepted
Add/Modify. `Options.ExpectedVersion` cannot atomically guard a combined attribute
and protection workflow, and that combination is rejected.

`Mutation` reports submission/reply separately from readback and `Verified`.
Readback uses the returned/previous GUID. Accepted writes with incomplete
readback retain raw candidates. Missing attributes can be ACL-hidden, so a Clear
can be accepted and return `ErrObjectVerification` with `Verified=false`.
Assignments compare returned DN structure, preserve silo observations, and never
replay uncertain writes. Deletes are leaf deletes; the SDK does not unprotect or
explicitly edit referring accounts/silos. Server-side linked-value cleanup and
reference failures remain server behavior. The entire multi-stage mutation uses
one configured timeout budget.

## Run and qualification

`go run ./examples/authenticationpolicies -server dc.example.test` reads policies.
Explicit `-operation` and `-apply` enable one selected write. The example prints
submission and verification status and never retries.

Portable tests cover lifecycle, exact/zero lifetimes, omitted/unknown raw values,
assignment and clear, conflicts, capability/scope checks, partial results, shared
timeouts, ACL-step outcomes, and descriptor bounds. Windows tests drive the public
create, descriptor update, delete, assign, and clear APIs through actual WinLDAP
against a loopback peer, checking exact bytes, permissions, ownership and one
submission. The descriptor compiler has native ownership and cleanup-error tests.

No live AD changes or authentication attempts were performed for this feature.
PowerShell differential results, actual audit/enforcement events, client armoring,
the deprecated rolling-secret behavior, and server/module version matrices remain
open qualification work. Issue #40 is not complete or accepted based on local tests.

## Primary references

- [Policy cmdlet surface](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adauthenticationpolicy?view=windowsserver2025-ps)
  and [account assignment](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountauthenticationpolicysilo?view=windowsserver2025-ps).
- [Policy schema class](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/df2ed14b-c69d-4680-86ac-2e0c3d9c78af)
  and [TGT lifetime schema units](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/51b8ff85-94b4-43cf-b5b2-087814548cef).
- [Windows schema updates, Sch68/Sch85](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/schema-updates)
  and [policy deployment requirements](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/how-to-configure-protected-accounts).
- [KDC policy selection](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/80f6b0ad-18a4-4dad-ae7f-a2b5da0c7e49),
  [AS access checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/a076994a-47a9-4d16-af77-d4abb523afe4),
  and [TGS access checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2e5dcf34-4b51-44a0-b45a-277ed616ca39).
