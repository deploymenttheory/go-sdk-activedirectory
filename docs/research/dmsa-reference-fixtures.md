# dMSA migration reference fixtures

Research date: 2026-11-12. Repository baseline: `ffee945f5bd259a86d59c32d1c37622958fc2be3`.
This is an implementation contract for [issue #50][ticket], not migration execution
evidence. It includes source research and supplied read-only metadata probes;
no directory mutation, VM lifecycle operation, provisioning, or media download
was performed for this checkpoint. The ticket remains open. Its native `blocked_by` relationship
was read through GitHub's API: the sole blocker is [closed issue #8][lab-ticket].

## Scope and existing evidence

The four reference operations are `Start-ADServiceAccountMigration`,
`Complete-ADServiceAccountMigration`, `Undo-ADServiceAccountMigration`, and
`Reset-ADServiceAccountMigration`. Issue #50 requires executable fixtures,
complete side-effect capture, repeats/conflicts/permissions/partial failures,
and explained recovery before subsequent SDK migration implementations. Reference
PowerShell is permitted; the SDK retains its native Windows implementation with
no runtime PowerShell or RSAT dependency. [Ticket][ticket]

The existing harness uses Windows PowerShell 5.1, an owned private Hyper-V switch,
two writable DCs, one member, per-profile locking, protected credentials, run IDs,
and source/binary hashes. The credential fixture provides stronger cleanup
precedent than the older recursive reference cleanup: validate GUID/name/marker,
remove known children independently, delete the OU nonrecursively, and confirm
absence on both DCs. Reuse those conventions. [Lab guide](../lab.md),
[lab entry point](../../scripts/lab/lab.ps1),
[credential fixture](../../scripts/lab/reference-credentials.ps1)

The committed Server 2025 evidence records AMD64 build `26100.32230`, AD module
`1.0.1.0`, PowerShell `5.1.26100.7462`, schema `91`, and 2016 domain/forest levels.
All four commands expose `AuthType`, `Credential`, `Identity`, `Server`, and
`SupersededAccount`; the installed parameter-set name is `Identity`, while the
pinned documentation calls it `ADServiceAccountMigrationParameterSet (Default)`.
These are inventory observations, not proof of migration behavior.
[Recorded environment](../../coverage/lab/server2025/README.md),
[installed module](../../coverage/lab/server2025/module.json),
[pinned reference](../../coverage/reference.json)

Two fresh read-only probes from owned `ADSDK25DC1` are retained alongside this
report. The first captured six schema objects because its search filter omitted
`msDS-SupersededServiceAccountState`; this is a collector omission, not an absent
attribute. The corrected probe captures seven objects: one dMSA class, two state
attributes and four link attributes. Both record build `26100.32230`, module
`1.0.1.0`, module assembly version `10.0.0.0`, file version `10.0.26100.7309` and
assembly SHA-256 `10116057543299F2FC333E4C1DA6B24411E050D043724376CAF5B3BCF49ED731`.
[First probe](dmsa-reference-evidence/server2025-contracts-readonly.json),
[corrected probe](dmsa-reference-evidence/server2025-contracts-complete-schema.json)

| Read-only artifact | Capture time (UTC) | Captured file SHA-256 |
| --- | --- | --- |
| `server2025-contracts-readonly.json` | `2026-11-12T18:37:58.7492509Z` | `8659432A8831D57E1C8744065D7188DF995849AC638A14BAC888CEE416BB3921` |
| `server2025-contracts-complete-schema.json` | `2026-11-12T18:39:25.6829761Z` | `0D9014F50E323701A525CC472641F04895DA5620FAE5E6C8B016B504E52266A0` |

The [evidence attributes](dmsa-reference-evidence/.gitattributes) preserve these
captured JSON bytes across checkout. These probes created no accounts, executed
no migration, and read no KDS secrets. Their additional `dsrolesrv.dll` reflection
metadata does not identify a dMSA implementation path. The probe is from one DC;
it does not establish replication, member readiness or the full preflight below.
[Probe contents](dmsa-reference-evidence/server2025-contracts-complete-schema.json)

All migration entries and behavioral scenarios remain `unverified` with empty
evidence in the [coverage inventory](../../coverage/inventory.json). Preserve
that state during research and fixture development. Reference execution does
not by itself qualify a native SDK implementation. The applicable
[contribution guide](../../CONTRIBUTING.md) adds no lab-specific procedure; no
applicable `AGENTS.md` was found in the worktree or inspected ancestors.

## Documented contract and unresolved documentation

| Operation | Documented phase contract | What is still an observation to collect |
| --- | --- | --- |
| Start | Link an ordinary user account to a dMSA. Identity accepts DN/GUID/SID/SAM; the superseded account is a DN. [Start][start] | Exact initial state accepted, write order, existing ACE handling, output/error form, and retry behavior. |
| Complete | Requires a pair previously linked by Start and completes supersession. [Complete][complete] | Order and atomicity of changes; treatment of preexisting destination values; original-account/service behavior. |
| Undo | Started becomes unlinked; completed returns to started. The pair must previously have been linked by Start. [Undo][undo] | Exact reverse changes, numeric unlinked values, retained data, and required service recovery. |
| Reset | Reset migration and unlink a previously started pair. [Reset][reset] | Behavior from each phase, repeat behavior, enablement/SPN/ACL restoration, and differences from Undo. |

Microsoft's overview describes Start as adding legacy-account read and
`msDS-GroupMSAMembership` write access on the dMSA, establishing links, and setting
migration state 1. Complete removes those grants, sets state 2, transfers SPNs,
copies constrained-delegation data, policy and trusted-to-auth-for-delegation
state, adds silo membership, and disables the legacy account.
[Overview, account attributes][overview-attributes]

The same overview advises two ticket lifetimes (14 days) after SD changes before
completion, recommends four (28 days) in Start, and separately describes
10-hour ticket renewal. It does not identify a policy explaining this arithmetic.
Treat this as rollout guidance with unresolved terminology, not a proven cmdlet
timer or a KDS activation delay. Record actual Kerberos policy and elapsed times;
label shorter lab transitions `accelerated_lab_observation`.
[Overview, migration flow][overview-flow]

The following discrepancies must stay visible in the evidence:

- The overview's Start list uses `msDS-SupersededAccountState` and
  `msDS-SupersededManagedServiceAccountLink`; schema sources identify
  `msDS-SupersededServiceAccountState` and `msDS-SupersededManagedAccountLink`.
  Use schema-verified LDAP names. [Overview][overview-attributes],
  [state schema][legacy-state], [link schema][legacy-link]
- The setup page describes standalone state 3 and directs migration users
  through that creation flow. Its state-setting sample uses a `Properties`
  parameter. Do not copy that sample blindly: capture installed command
  metadata, the as-created state, and a separate state-3 case; use only a
  supported mutation parameter during eventual fixture setup. The fresh probe
  confirms `Set-ADServiceAccount` has `Replace` and no `Properties` parameter;
  state mutation itself remains untested. [Setup][setup], [Set reference][set-account],
  [fresh parameter metadata](dmsa-reference-evidence/server2025-contracts-complete-schema.json)
- The current Learn rendering of `New-ADServiceAccount` inspected for this
  research omitted `CreateDelegatedServiceAccount`, although the setup guide,
  pinned reference, and installed inventory include it. Preserve both source
  provenance and installed syntax. [Creation reference][new-account],
  [setup][setup], [pinned reference](../../coverage/reference.json),
  [fresh parameter metadata](dmsa-reference-evidence/server2025-contracts-complete-schema.json)
- Generic `-Server` prose mentions LDS/snapshots, but command Notes exclude LDS,
  snapshots, and RODCs. Apply the operation-specific Notes. [Start][start],
  [Complete][complete], [Undo][undo], [Reset][reset]

## Profile and prerequisites

The proposed first profile is a freshly provisioned, disposable Server 2025
domain with two writable DCs and one Server 2025 member. Keep it separate from
ordinary CRUD qualification through a profile/fixture ownership marker and the
existing profile mutex. Do not adopt a directory merely because its DNS name is
`ad.sdk.test`. Validate lab ID, VM IDs, domain SID, forest root, DC GUIDs, member
secure channel, and isolated switch before mutation. This is a design choice
based on the [existing ownership model](../../scripts/lab/lab.ps1) and
[issue #50][ticket].

| Gate | Minimum documented support or boundary | Proposed executable preflight |
| --- | --- | --- |
| OS/DC | At least one discoverable Server 2025 DC; every workload host must support dMSA. [FAQ][faq] | Use two 2025 writable DCs and a 2025 member; capture full build/UBR, edition, architecture, domain discovery and selected DC. Fail if any claimed workload host is unsupported. |
| Functional levels | Server 2025 DCs support 2016 or 2025 levels; new 2025 forests require at least 2016. No explicit dMSA-specific higher minimum was found in the reviewed setup/FAQ. [Levels][levels], [Server 2025 changes][new-server], [setup][setup] | Start at explicit 2016 levels, as in the base lab. Record rather than silently raise them. A success qualifies only that level; a failure requires diagnosis before a separate 2025-level profile. |
| Schema | The dMSA class and migration attributes first appear in Server 2025. [Class][class], [dMSA state][dmsa-state], [legacy state][legacy-state] | Read class/attribute definitions on both DCs; verify LDAP names, GUIDs, syntaxes, multiplicity and link IDs. Schema `objectVersion` alone is insufficient. |
| KDS | A root key is required. General KDS guidance describes a convergence wait of up to ten hours and limits backdating to single-DC tests. [Start][start], [KDS][kds] | Reuse an owned effective key or create one once in the disposable profile; persist its ID and effective/creation times. Verify key metadata on both DCs and readiness after the documented wait. Never export root-key material or delete/recreate keys as a retry. |
| Client | Client policy enables dMSA logon, and designated machines receive retrieval authorization. [Setup][setup] | Record/set `DelegatedMSAEnabled=1` under the documented Kerberos policy path, record Credential Guard state, and read back the intended member computer SID in the retrieval descriptor. |
| Principals | Creation/migration requires Domain/Enterprise Admins or equivalent rights. gMSA migration and merging multiple legacy accounts are unsupported. [Setup][setup], [FAQ][faq] | Provision with the disposable administrator; run permission tests with separate ordinary actors. Use ordinary enabled users as legacy accounts, one dMSA per pair, no privileged service identity. |
| Credentials | Negotiate is default; Basic requires SSL; insufficient directory permission is an error. [Complete][complete] | Start with current-identity and explicit Negotiate. Keep passwords in protected memory/credential transport and out of arguments/results. Basic/TLS remains unqualified until a trusted-certificate endpoint is explicitly provisioned. |
| Scope | Cross-forest setup discusses two-way trust. [Setup][setup] | Initial fixture is same-domain; it makes no cross-forest or RODC claim. Record this as scope, not proof those configurations are unsupported. |

The exact patch level that first implements or fixes each behavior is not
established here. Do not infer it from the major OS name or AD module version.
The runtime authorization protocol separately checks dMSA class and the calling
context's read-property right in `msDS-GroupMSAMembership`; it can return success
while `Authorized` is false. Record outcomes rather than equating object
existence with authorization. [MS-SAMR opnum 77][samr]

## Fixture families

These are proposed experiments, not facts about the commands. Each row gets
fresh GUID-marked objects and a separately stored expected baseline.
The design implements [issue #50][ticket].

| Family | Owned contents and purpose |
| --- | --- |
| `minimal` | One ordinary enabled legacy user, one new dMSA, known original password, unique DNS name, AES setting, no SPNs/delegation/policy. Record as-created dMSA state before any state edit. Establish phase behavior without optional data. |
| `standalone` | A separate dMSA configured to documented standalone state 3 and authorized member. Probe Start/Reset separately; never relabel this as the as-created baseline. |
| `populated` | Legacy user with two unique synthetic SPNs, a protected resource readable by its SID, explicit canary ACEs, constrained delegation to owned target SPNs, and a resource-based delegation descriptor naming only an owned ordinary principal. |
| `policy` | Separate pairs for direct policy assignment, silo access without assignment, and silo assignment. Include two owned silos to distinguish membership from assignment. Both policies and silos are audit-only. |
| `preservation` | Give the dMSA distinct preexisting SPNs, ACEs, retrieval principals, delegation and policy values. Determine union/replace/reject behavior and whether Undo/Reset preserves unrelated destination values. |
| `disabled-origin` | Legacy account disabled before Start. Do not run a successful-service assertion on it; measure whether recovery preserves its original disabled state. |
| `delegation-flags` | Separate fixtures for `TRUSTED_TO_AUTH_FOR_DELEGATION`, `TRUSTED_FOR_DELEGATION`, and no delegation. Never combine flags merely to simplify a test. Record raw UAC and each bit. |
| `faults` | Ordinary migration actor with narrowly scoped fixture rights, separate read-only observer/administrator, and disposable conflicting pairs. Deny or remove one required right at a time; keep recovery privileges outside the denied actor. |

Audit-only policy/silo configuration permits storage and relationship checks;
it does not prove enforcement. Granting silo access and assigning a silo are
distinct fixture operations. [Policy/silo schema and enforcement][policies],
[silo creation][new-silo], [grant access][grant-silo]

Delegation variants are security-sensitive even inside the lab: constrain every
SID, SPN, service and target to owned nonprivileged fixtures; do not authenticate
administrators to those services. UAC `ACCOUNTDISABLE` is `0x2`,
`TRUSTED_FOR_DELEGATION` is `0x80000`, and
`TRUSTED_TO_AUTH_FOR_DELEGATION` is `0x1000000`. These are different flags.
[UAC definitions][uac]

## Capture contract

Implement a capture function that accepts explicit server, object GUID, expected
DN/class/marker, and an attribute allowlist. Resolve and validate ownership on
each read. Every field records `present`, `absent`, `read_denied`, or `read_error`;
never serialize a failed read as an empty value. Absent and numeric zero remain
different. Unknown required fields make evidence incomplete. This is the
proposed assertion boundary for [issue #50][ticket].

Capture each pair, related fixture objects and service at these boundaries:
baseline before setup changes; ready immediately before the command; immediately
after command success **or failure**; after convergence on DC2; after a fresh
service/logon probe; before and after recovery; after cleanup. Timestamp each
object read separately because a multi-object capture is not an atomic snapshot.
Keep the operation error even when capture or cleanup also fails.
[Ticket][ticket], [existing error aggregation](../../scripts/lab/reference-credentials.ps1)

| Capture group | Exact fields/representation |
| --- | --- |
| Identity and provenance | `objectGUID`, `objectSid`, `distinguishedName`, `objectClass`, `sAMAccountName`, marker; server/DC invocation identity, UTC interval, capture implementation hash. |
| Migration state | Both `msDS-DelegatedMSAState` and `msDS-SupersededServiceAccountState` where applicable; presence plus integer, without assuming reset means zero. |
| Links | `msDS-ManagedAccountPrecededByLink`, `msDS-ManagedAccountPrecededByLinkBL`, `msDS-SupersededManagedAccountLink`, `msDS-SupersededManagedAccountLinkBL` on both objects; preserve raw DNs and separately resolve GUIDs. |
| ACLs | Raw `nTSecurityDescriptor` bytes, SDDL, owner/group/control flags, and ordered ACE records: SID, type, mask, flags, object/inherited-object GUID, inheritance. Capture pair, OU, resource and related policy/silo ACLs. Record exactly which SD sections were requested/returned. |
| Retrieval authorization | Raw/parsed `msDS-GroupMSAMembership` descriptor and projected `PrincipalsAllowedToRetrieveManagedPassword`. Compare the raw descriptor independently of the module projection. |
| Account behavior | Raw `userAccountControl`, `msDS-User-Account-Control-Computed`, projected `Enabled`, `accountExpires`, `pwdLastSet`, `msDS-SupportedEncryptionTypes`; record UAC bit deltas rather than replacing the integer. |
| Service names/delegation | Sorted `servicePrincipalName`, `msDS-AllowedToDelegateTo`, raw/parsed `msDS-AllowedToActOnBehalfOfOtherIdentity`; also collect forest/domain search results locating every fixture SPN. |
| Policy/silo relationships | `msDS-AssignedAuthNPolicy`, `msDS-AssignedAuthNPolicySilo`, `msDS-AuthNPolicySiloMembersBL`; related policy assignment backlinks and silo `msDS-AuthNPolicySiloMembers`, enforcement flags and policy references. Read every side of each owned relationship. |
| Related authorization | Legacy/dMSA group memberships and owned resource ACL/read result, to expose effects not explained by link fields. |
| Replication | All available attribute/value metadata names and versions on both DCs, originating server/USN/time/version, `uSNChanged`, `whenChanged`, read times and convergence deadline. Metadata discovery must expose changes outside the value allowlist without reading secret values. |
| Service/client | Service name, executable SHA-256, configured account, PID, start/stop result, token SID/groups/logon ID, nonce read result, authentication package and selected KDC where observable, event IDs/record IDs/times, client policy and cache-isolation method. |

The schema contains two distinct forward links with their own backlinks: legacy
to dMSA uses link IDs 2222/2223; dMSA to legacy uses 2224/2225. They are not simply
one reciprocal LDAP link pair. Verify their live definitions and inspect all four
fields; do not write backlinks as a recovery operation.
[Legacy forward link][legacy-link], [dMSA forward link][dmsa-link],
[schema updates, Sch89.ldf][schema]

Use `System.DirectoryServices.Protocols` for an independent LDAP capture, pinned
to the same DC, with `SecurityDescriptorFlagControl` requesting owner, group,
DACL and SACL. A privileged capture identity may be needed; if a section cannot
be read, record the limitation and fail the full-ACL evidence gate instead of
reporting an empty ACL. Keep ordered binary fidelity alongside a comparison view.
[Security descriptor control][sd-control]

Use `Get-ADReplicationAttributeMetadata -ShowAllLinkedValues` as a second view.
It exposes attribute and linked-value replication metadata. The design may use
same-DC metadata and audited writes to establish observed mutation boundaries,
but must not invent a total write order from timestamps, documentation bullet
order, or values seen only after return. Any changed attribute outside the value
allowlist becomes an unexplained effect until classified and, if nonsecret,
added to capture. Secret-attribute metadata may identify a change without
exporting its value. [Metadata reference][metadata]

Only collect explicitly approved nonsecret attributes. Never request wildcard
account properties or retain `msDS-ManagedPassword`, password history, key
packages, KDS root-key data, ticket blobs, credential buffers, or raw invocation
lines containing credentials. This is a fixture evidence rule: the protocol's
dMSA key package contains current/previous keys, including legacy-account keys.
[MS-KILE key package][key-package],
[existing credential redaction](../../scripts/lab/reference-credentials.ps1)

## Executable scenario matrix

`U` below means an observed unlinked baseline; it does not prescribe a numeric
state. `S` and `C` mean Start and Complete succeeded and all captures were taken.
Each sequence is a fresh pair unless a repeat is explicitly part of the case.
Run the minimal, populated and applicable policy/preservation variants; keep
failures as first-class evidence. The matrix directly expands the scenarios in
the [coverage inventory](../../coverage/inventory.json) and [issue #50][ticket].

| Scenario ID | Command sequence or input | Required result evaluation |
| --- | --- | --- |
| `start-unlinked` | `U -> Start` | Check documented phase/link/ACL changes; explain every other delta. Capture both as-created and separately configured standalone inputs. |
| `complete-started` | `U -> Start -> Complete` | Check transfer/removal effects against nonempty fixture data and preserve raw source/destination values. Exercise service probes before/after. |
| `undo-started` | `U -> Start -> Undo` | Verify unlinked phase; compare every captured field against the original and ready baselines; probe original service/credentials. |
| `undo-completed` | `U -> Start -> Complete -> Undo` | Verify return to Start; compare against the captured earlier Start state; report retained or reversed optional data and service behavior. |
| `undo-twice` | Previous row then `Undo` again | Verify completed-to-started-to-unlinked separately; do not infer that one Undo reverses all migration. |
| `reset-started` | `U -> Start -> Reset` | Determine exact reset state and restoration/retention for all fields and service behavior. |
| `reset-completed` | `U -> Start -> Complete -> Reset` | Same full comparison, including enablement, SPN ownership and credentials. |
| `reset-unlinked` | Reset on fresh U, after Undo-to-U, after Reset | Record error/no-op/mutation independently; require full captures for each. |
| `repeats` | Start twice in S; Complete twice in C; Undo again in U; Reset twice | Measure error class/code, no-op or additional changes. Do not assume idempotency. |
| `wrong-phase` | Complete in U; Start in C; Undo on never-linked pair | Confirm exact behavior and capture side effects even on error. |
| `wrong-partner` | After pairing A/B, invoke every command with A/C or D/B | Capture all four owned accounts and references; distinguish validation rejection from partial writes. |
| `manual-conflict` | On isolated pairs, alter one forward link or state to reference another owned fixture | Capture prepared corruption, invoke each applicable command, then exercise measured recovery. Never use privileged or unrelated accounts. |
| `identity` | Fresh pairs: dMSA DN/GUID/SID/SAM, escaped/Unicode DN; wrong class and missing identities; non-DN legacy identity | Compare resolution and error semantics; distinguish input rejection from server mutation. |
| `permissions` | Current identity, valid explicit Negotiate, invalid secret, ordinary denied actor, and scoped successful actor | Establish a successful control for the same prepared request, then verify denial and complete before/after state. |
| `partial-failure` | Each identified mutation boundary with one targeted denied right | Require evidence of changed earlier state plus failed later operation where obtainable; recover and rerun with fresh fixtures. A preflight rejection alone is not a partial failure. |
| `lost-response` | Let a separately controlled invocation finish, withhold its result from the coordinator | Test coordinator reconciliation from readback; label this lost-response simulation, not an interrupted server transaction. |
| `destination-preservation` | All applicable transition/recovery rows with existing dMSA canaries | Explain overwrite/union/rejection and every canary change. |
| `disabled-origin` | Transition/recovery rows with originally disabled legacy account | Distinguish original disablement from migration disablement. |
| `endpoint` | Explicit DC1 and DC2 on fresh pairs; unavailable endpoint; missing capability preflight | No silent fallback or replay. Older-server/LDS/RODC execution requires a separately owned profile and remains untested here. |

All four command pages document the phase/identity inputs; they do not establish
idempotency or multi-object rollback. Matrix outcomes not specifically promised
therefore remain versioned observations. [Start][start], [Complete][complete],
[Undo][undo], [Reset][reset]

### Controlled failure mechanism

Implementation proposal: first prove a scoped actor can perform the exact
prepared operation. Recreate that baseline, then deny one operation to that
actor on one owned object: dMSA DACL write; dMSA state/link/retrieval descriptor;
legacy state/link/UAC/SPN; destination SPN/delegation/policy assignment; or silo
membership. Resolve object-property GUIDs from live schema. Keep a distinct
observer able to capture all objects, and a recovery administrator unaffected by
the injected ACE. Record the exact injected ACE and the successful control.
This implements the inventory's denied-rights and mutation-boundary scenarios.
[Coverage inventory](../../coverage/inventory.json)

Discover actual write boundaries with changes visible after denied calls,
replication metadata, and narrowly scoped directory-change auditing if needed.
Audit setup is itself an owned configuration change with prior-state restoration.
If the module prevalidates everything or the boundary cannot be interrupted,
state that limit; do not fabricate an observed partial transaction by manually
constructing final JSON. Manually edited inconsistent pairs are separate
recovery fixtures. Do not kill a DC, stop AD DS, partition replication, or alter
time merely to force a failure. This is the proposed bounded fault strategy for
[issue #50][ticket].

### Service and credential evidence

The FAQ says the service uses the dMSA after completion while remaining
configured with the old account; it warns that deleting the original breaks the
service. Keep the original through all transition and recovery probes.
[FAQ][faq]

Build one harmless reference Windows service from retained source using existing
guest tooling or a host-built executable; retain source/toolchain/binary hashes.
Run it only on the owned member, initially under the ordinary legacy account.
Give it an owned LDAP resource with a unique nonce and a protected ACL granting
access to the legacy SID, plus explicit observer/recovery access. Validate the
resource is denied to another ordinary fixture principal. This is a proposed
functional probe, not an existing artifact. [Ticket][ticket]

At U, S, C, Undo and Reset boundaries: stop only this service, start a fresh
instance, challenge it to read a newly changed nonce using its own network
identity, and capture its token, authentication result and relevant DC/client
events. Require the returned nonce to match the independently captured resource
and correlate PID/logon/event IDs. A running service status or a JSON field
`authenticated=true` is insufficient. Record service-scoped cache handling;
never purge all administrator/system tickets as an incidental test step.
This is the proposed service assertion for [issue #50][ticket].

Also compare explicit original-password authentication before and after each
transition, plus a known-invalid password control, using a path that reports
the actual authentication mechanism and result. Do not infer password acceptance
from a successful LSA/Negotiate operation: KDC supersession responses can direct
the client to another principal. Distinguish a new old-password authentication,
dMSA redirection, existing tickets, and cached logon. If the chosen helper cannot
make that distinction, credential behavior remains unknown.
[MS-KILE supersession response][superseded]

Enable the member's Kerberos Operational channel for the owned run, record its
prior state, and capture relevant 307/308/309 event fields without secrets.
Events are corroboration, not the sole proof of a successful resource operation.
For learning, compare retrieval authorization before/after a service logon in S,
including a separate initially unauthorized-member case. [Setup event table][setup]

Machine-authorization denial needs an independently controlled unauthorized host
or a proven fresh-key-fetch experiment. The base three-VM topology alone does
not supply a second member. Add a second owned 2025 member for this evidence or
leave that claim explicitly unqualified; do not run the fixture service on a DC
to save a VM. Credential Guard, multi-host, delegation enforcement and policy
enforcement are separate behavior qualifications. The core ticket must still
explain all configured field changes and recovery; audit-only field migration
does not establish those wider security properties. [SAMR authorization][samr],
[policy enforcement][policies], [ticket scope][ticket]

## Recovery, cleanup and acceptance

For each failure, preserve the operation record, independent current captures,
injected changes, service state and the last verified phase. Pause that fixture's
service, remove only the known fault-injection ACE after ownership checks, and
choose a recovery sequence supported by an already observed equivalent case.
Read before every action and retain each step. No blind replay and no generic
"clear both links" compensation. If no verified path exists, mark recovery
unknown and quarantine the fixture for inspection/rebuild. [Ticket][ticket],
[inventory recovery expectations](../../coverage/inventory.json)

Recovery is successful only when independent readback matches the declared
target across ACLs, both states, all links, SPNs, delegation, policy/silo
relationships, account enablement, resource access and original credentials.
Compare against the intended target baseline, not merely absence of links.
Record any justified retained value explicitly. If extra manual compensation is
necessary, label and measure it separately from the cmdlet's behavior.
[Ticket][ticket]

Cleanup follows recovery evidence, and cannot replace it. Attempt independent
owned resource removals even if one fails: stop/remove the named service, remove
its logon-right grant and only its files, restore event/policy settings, detach
owned policy/silo relationships, remove exact owned accounts/targets/policies/
silos, then remove the empty OU nonrecursively. Confirm absence on both DCs;
verify surviving canaries and member configuration against baseline. A lookup
failure is not evidence of absence. Aggregate operation, capture, recovery and
cleanup errors separately. This extends the
[credential cleanup pattern](../../scripts/lab/reference-credentials.ps1).

The eventual implementation should add these reviewable components (names are
proposals, not currently available commands):

| Component | Responsibility |
| --- | --- |
| `scripts/lab/test-dmsa.ps1` | Owned host orchestration, source/helper hashes, profile gating, result retrieval. |
| `scripts/lab/reference-dmsa.ps1` | Guest preflight, fixture ownership ledger, scenario runner, independent capture, recovery and cleanup. |
| `scripts/lab/dmsa-capture.ps1` | Explicit LDAP attribute/SD reads, stable typed representations, denied/absent distinction, metadata collection. |
| `scripts/lab/test-dmsa-capture.ps1` | Offline malformed/denied/partial captures, descriptor fidelity and missing evidence rejection. |
| `scripts/lab/test-dmsa-cleanup.ps1` | Offline wrong-owner, lost creation response, partial cleanup and aggregate-error checks. |
| `scripts/lab/dmsa-service/` | Retained harmless service/helper source and independent nonce/authentication probes. |
| `coverage/lab/server2025/dmsa/<run-id>/` | Sanitized raw captures, command outcomes, reviewed assertions and explicit unknowns for each actual execution. |

Use offline checks to verify harness behavior, not Microsoft migration behavior.
The evidence evaluator must recompute assertions from raw captures, require the
scenario manifest, verify hashes and fixture ownership, reject missing/duplicate
scenario IDs and unknown capture fields, and correlate service outputs with
independent results. It must never accept a runner-authored `passed` flag as its
oracle. Run two fresh fixture sets and compare normalized outcomes only after
explaining differences; never normalize away permission, UAC, ACL ordering,
presence/absence or recovery changes. [Issue #50][ticket],
[existing repeated-run precedent](../../coverage/lab/server2025/README.md)

Retain per-run OS/UBR, module assembly/file versions and hashes, command parameter
metadata, schema definitions, levels, KDS nonsecret metadata, policies, source and
binary hashes, all scenario preconditions, outcomes, capture paths and unknowns.
Each assertion records `documented_contract`, `observed_build_behavior`, or
`harness_invariant` with its source. Evidence status remains `incomplete` while
any required side effect, mutation boundary, credential/service behavior or
recovery result is unexplained. Partial coverage must say exactly which scenario
is missing; it must not close #50 or promote native SDK coverage. [Ticket][ticket]

## Outstanding observations

No dMSA migration result has been collected by this research. The first lab run
must resolve: initial numeric states; state-3 compatibility; exact ACE addition/
removal and canary preservation; SPN move/merge ordering; policy assignment versus
silo access/assignment; all Undo/Reset reverse or retained effects; original
password and fresh service behavior; permission requirements and actually
reachable partial-failure states; deterministic recovery; and cleanup after
lost responses. The functional-level floor for dMSA specifically, rollout-wait
terminology, and minimum serviced OS build remain documentation/research gaps.
These are the unresolved questions derived from [issue #50][ticket] and the
documented boundaries above, not claims of product defects.

[ticket]: https://github.com/deploymenttheory/go-sdk-activedirectory/issues/50
[lab-ticket]: https://github.com/deploymenttheory/go-sdk-activedirectory/issues/8
[start]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/start-adserviceaccountmigration?view=windowsserver2025-ps
[complete]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/complete-adserviceaccountmigration?view=windowsserver2025-ps
[undo]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/undo-adserviceaccountmigration?view=windowsserver2025-ps
[reset]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/reset-adserviceaccountmigration?view=windowsserver2025-ps
[overview-attributes]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview#account-attributes-for-dmsa
[overview-flow]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview#migration-flow-for-dmsa
[setup]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa
[faq]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-faq
[new-account]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount?view=windowsserver2025-ps
[set-account]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adserviceaccount?view=windowsserver2025-ps
[levels]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels
[new-server]: https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-windows-server-2025
[kds]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key
[class]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/2c3e6e0a-134d-47e3-9ed5-edb71145def3
[dmsa-state]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c354638a-5e30-43e5-b7f0-9233d83fec8b
[legacy-state]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/188941fa-3e05-4d4e-89e7-bb70ad67a737
[legacy-link]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c5b9ddb6-a9dd-4bdc-9a68-775fb346f21e
[dmsa-link]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/6ce9e113-5c1e-4ba3-8078-419dd4e33561
[schema]: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/schema-updates
[samr]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/38d8c44c-292a-4a2e-a6a7-75450ab6439f
[key-package]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/87f5f362-e53c-4949-9a6c-bc9184054517
[superseded]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/79170b21-ad15-4a1b-99c4-84b3992d9e70
[policies]: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos
[new-silo]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adauthenticationpolicysilo?view=windowsserver2025-ps
[grant-silo]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/grant-adauthenticationpolicysiloaccess?view=windowsserver2025-ps
[uac]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
[sd-control]: https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.securitydescriptorflagcontrol?view=netframework-4.8.1
[metadata]: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationattributemetadata?view=windowsserver2025-ps
