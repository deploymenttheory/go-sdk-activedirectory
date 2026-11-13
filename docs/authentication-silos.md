# Authentication policy silos

`AuthenticationPolicySilo`, `AuthenticationPolicySilos`,
`CreateAuthenticationPolicySilo`, `UpdateAuthenticationPolicySilo`, and
`DeleteAuthenticationPolicySilo` provide native silo lifecycle and search.
`GrantAuthenticationPolicySiloAccess` and `RevokeAuthenticationPolicySiloAccess`
manage permission to join. `SetAccountAuthenticationPolicySilo` independently
assigns or clears the silo and direct authentication policy on an account.

Grant is a strict LDAP Add of one account DN to `msDS-AuthNPolicySiloMembers`;
revoke is a strict Delete of that value. These operations preserve unrelated
grants and do not edit security descriptors. Microsoft defines this attribute as
a writable multivalued DN link, link ID 2204. Offline inspection of the installed
module file version `10.0.26100.7920` confirms that Grant/Revoke use the shared
member Add/Remove workflow and map `Members` to that attribute. No directory
connection or module mutation command was invoked during that inspection.

Account assignment is a separate `msDS-AssignedAuthNPolicySilo` link. Granting
does not assign, revoking does not clear assignment, and assignment does not
grant. The KDC uses both links to determine whether an account belongs to a silo;
an assigned-but-ungranted account is not a member under that protocol rule.
The SDK permits either staging order. `RequireGranted: true` optionally requires
a complete, positively observed grant before assignment. Missing/hidden grants
return `ErrAuthenticationSiloGrant`; incomplete reads remain incomplete errors.
This read is not an atomic assertion on another object's grants. A concurrent
revoke can occur after preflight, and no result claims an effective logon decision.

## Properties and intent

| Cmdlet surface | SDK representation |
| --- | --- |
| Name | Literal create `Name`, escaped into a schema-validated CN; reads preserve the stored name. |
| Description / Enforce | Optional `Description` / `Enforced`. Nil omits an update; explicit false means audit. Creation defaults to false. |
| UserAuthenticationPolicy | Explicit DN/GUID `*Identity` resolved to a policy in this forest, then stored in `msDS-UserAuthNPolicy`. |
| ComputerAuthenticationPolicy | The same explicit reference semantics for `msDS-ComputerAuthNPolicy`. |
| ServiceAuthenticationPolicy | The same explicit reference semantics for `msDS-ServiceAuthNPolicy`. |
| Members | `AuthenticationPolicySiloResult.Members` contains server-visible grant links. It does not mean the accounts are assigned. |
| Assigned accounts | `AssignedAccounts` separately reads `msDS-AssignedAuthNPolicySiloBL`. |
| ProtectedFromAccidentalDeletion | Optional separate protection workflow; nil leaves the schema ACL unchanged. The inspected module's default protection helper returns false for this class. Request the property explicitly when reading its ACL pattern. |
| OtherAttributes / Add / Remove / Replace / Clear | Shared `Attributes`/`Changes`, with binary and multivalue preservation. Known references are resolved and class/scope checked. Use `AttributeClear` to clear a policy reference. Grant/assignment/backlink and raw security-descriptor fields require their dedicated APIs. |
| Instance | Explicit typed/raw input, rather than implicit dirty tracking of returned observations. |
| Filter / LDAPFilter / selected properties / paging | Shared `SearchOptions` in `AuthenticationPolicySiloSearchOptions`; the silo class is intersected with the caller's filter. |
| AuthenticationPolicySilo / AuthenticationPolicy assignment | Independent `Silo`/`Policy` identities or `ClearSilo`/`ClearPolicy`; at least one, with contradictory set+clear rejected. Both changes use one atomic Modify on the account. Existing `SetAccountAuthenticationPolicy` remains available. |
| Server / Credential / AuthType | Explicit configured `Client`, with no referrals or credential forwarding. |
| WhatIf / Confirm / pipeline / PassThru | Calls execute and return typed results. The example defaults to reads and requires `-apply` for writes; no runtime prompts or PowerShell pipeline are provided. |

Typed/raw duplicates and contradictory changes fail. Disjoint exact-value
remove/add pairs use the existing strict single-Modify semantics. Duplicate grant
and missing revoke values retain server errors; the SDK does not silently switch
to permissive modify or retry. Missing referenced policies fail before a silo
write. Clears remain useful for removing references that cannot be resolved.
Scalar reads preserve absent/unknown raw values instead of inventing defaults.

## Scope, range reads, and outcomes

Silo objects are constrained to
`CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,<configuration NC>`.
Policies must be in the corresponding `AuthN Policies` container. These methods
choose the configuration NC explicitly; a conflicting per-call partition is an
error. Account identities use the shared DN/GUID/SID/SAM forms in the connected
DC's domain. Cross-domain/application-NC account targets are rejected without
referral or lookup fallback. Use name filters and returned GUIDs for name lookup.

Reads require AD DS and DC functionality at least 2012 R2. Writes reuse the
authentication-policy prerequisite checks: schema version at least 69, domain
functionality at least 2012 R2, a synchronized writable DSA, and a full LDAP
endpoint. AD LDS and RODC/GC writes return explicit capability/target errors.
Server permission/schema/reference diagnostics remain available as `LDAPError`.

Grant and assignment backlink reads use the shared native range reader, not
the public raw search projection. Every range retains raw observations and checks
the silo GUID and `uSNChanged` against the initial observation. Gaps, duplicate
structurally equivalent DNs, malformed DNs, changing versions and partial native
errors prevent `Complete=true`. `MaxMembers` bounds each linked set, defaults to
16384 and accepts up to 1048576. Reaching a bound before known completion returns
partial values and `LimitReached=true`. Omitted attributes can represent a normal
empty set: enumeration completes with `AttributeReturned=false`, which is not
proof that no ACL-hidden values exist. This is not a transactional snapshot.

Each linked set also permits at most 1000 range responses and 64 MiB of cumulative
returned attribute names and value bytes. Crossing either budget returns
`LimitReached=true` without claiming completion. The received raw response remains
in `Observations`, including the response that crosses the byte budget; the byte
budget bounds further processing, not memory already returned by native LDAP.
Cancellation is checked while charging response bytes, materializing each DN and
looking up a grant, in addition to the native operation's context checks.

Mutation acceptance, readback completion and effect verification are distinct.
Accepted writes retain raw candidates after a partial readback failure. Grant
verification needs a returned matching DN; revoke needs a complete returned set
without that DN. An omitted attribute cannot prove a revoke or clear, so an
accepted request can return `ErrObjectVerification` with `Verified=false`.
Assignment compares returned DNs structurally. No error triggers automatic replay,
rollback, unprotection, account reassignment or removal of referenced policies.

Optional accidental-deletion protection reuses the existing parent/object ACL
workflow. Its individual outcomes remain separate from the accepted Add/Modify;
parent protection can affect sibling deletion. Unrelated ACEs are preserved.
Combined attribute/protection changes cannot share an atomic USN precondition and
are rejected when `ExpectedVersion` requests that guarantee. Each public mutation
has one timeout budget across its preflight, write, readback and protection stages.

## Usage and qualification

`go run ./examples/authenticationsilos -server dc.example.test` lists silos and
their grant/assignment counts. An explicit operation plus `-apply` selects a
mutation. Supply `-require-granted` to require the optional grant observation
before assignment. The example does not retry an uncertain result.

Portable tests cover lifecycle, per-class policy references, grant/assignment
separation, range continuity/limits/changes, omitted values, preconditions,
permission errors and accepted/uncertain readback outcomes. Actual WinLDAP
loopback tests inspect every public mutation's wire request, success/LDAP50
responses, range continuation, partial range replies and native ownership.
No live AD writes or authentication attempts were made. PowerShell differential
results, actual grant/revoke/assignment enforcement and server-version matrices
remain qualification work; this implementation does not close issue #41.

## Primary references

- [Silo class and properties](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/811a077a-2a7b-41e3-8496-e439b0f3b8e9),
  [Sch68 linked-attribute definitions](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/schema-updates).
- [Silo creation](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adauthenticationpolicysilo?view=windowsserver2025-ps),
  [grant](https://learn.microsoft.com/en-us/powershell/module/activedirectory/grant-adauthenticationpolicysiloaccess?view=windowsserver2025-ps),
  [assignment](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountauthenticationpolicysilo?view=windowsserver2025-ps).
- [KDC membership decision](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/089c5fed-a29d-472d-8388-8ed04d8010bf),
  [policy selection](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/80f6b0ad-18a4-4dad-ae7f-a2b5da0c7e49).
