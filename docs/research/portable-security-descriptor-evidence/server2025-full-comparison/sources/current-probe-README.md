# Task-local atomic NTSD reference probe

This is the bounded native reference experiment proposed in
`sdk06-atomic-acl-diagnosis-and-probe.md` for unresolved issue #195. It is not
an SDK implementation or evidence that either candidate is supported by AD.
Only task-local files under `tmp/` changed. No lab calls were made while
implementing or testing this helper.

## Files and scope

- `sdk06-atomic-acl-probe.ps1`: separate `PrepareProbe` and `Cleanup` actions.
- `test-sdk06-atomic-acl-probe.ps1`: offline orchestration, ownership and actual
  .NET request construction tests. Mock success models test the orchestration;
  they do not establish AD NTSD semantics.
- `sdk06-atomic-acl-probe-review.json`: exact helper/test hashes and final test
  receipts for both PowerShell 5.1 and 7, produced after the final runs.

The helper accepts only the selected Server 2025 DC1 and DC2 FQDNs below, the
exact `DC=ad,DC=sdk,DC=test` naming context, a fresh ASCII run identity and an
explicit snapshot mask of 4, 7 or 15. Its native adapter refuses execution
outside `ADSDK25DC1` or `ADSDK25MEM`. Root must independently verify the exact
owned VM GUID, profile, private switch and readiness through the approved
PowerShell Direct mechanism before invoking it. A matching computer name is
not a substitute for that outer ownership check.

The caller supplies the existing protected lab Administrator credential in
memory. The script neither obtains credentials from ambient state nor writes
them. It does not create an account, change group membership, modify policy,
change a descriptor outside the five owned OUs, or change `dSHeuristics`.
The username must explicitly name Administrator in a domain-qualified form;
root must supply the actual existing Server 2025 domain administrator.

## Root invocation contract

The following is guest-side usage after root's approved outer ownership and
source/hash validation. `$admin25` denotes the existing in-memory credential;
never embed its password in source, argv, logs or a journal. Root may create a
ScriptBlock from the reviewed bytes and pass the same parameter values through
its existing protected PowerShell Direct channel instead of persisting source.
These examples have not been invoked against a lab by the implementing agent.

```powershell
# Run exactly ONE selected mask for this fresh run. A different mask requires
# a new RunId and separate prepare/cleanup lifecycle.
$probeArgs = @{
    RunId = 'sdk06-cas2-20261119t-probe7'
    OldSnapshotMask = 7
    Credential = $admin25
    Server = 'adsdk25dc1.ad.sdk.test'
    PeerServer = 'adsdk25dc2.ad.sdk.test'
    JournalBase = 'C:\adsdk-atomic-acl-reference'
}
& .\sdk06-atomic-acl-probe.ps1 -Action PrepareProbe @probeArgs

# Collect/review public journal records even if preparation throws. Cleanup
# is a separate explicit root action, using the same exact identity and mask.
& .\sdk06-atomic-acl-probe.ps1 -Action Cleanup @probeArgs
```

A fresh run creates one root OU and four child OUs, each with a random
nonce-bearing description, exact recorded DN and independently pinned GUID.
Every operation opens its own explicit Kerberos LDAP connection to the selected
FQDN on port 389, requests signing and sealing, disables referral chasing, and
disposes the connection. The journal describes those as requested native
settings; it does not fabricate a measured cipher or portable SDK protection.
Connections never change selected server, backend or authentication mechanism.

Each action has a ten-minute deadline checked before native calls, plus at most
20 seconds for each native LDAP operation. An in-flight native/SSPI operation is
subject to native timeout behavior; this helper does not claim a hard external
process interrupt. Cleanup's final both-DC replication observation is bounded
to 120 seconds within that action budget. Native timeouts/missing replies keep
nullable LDAP codes, actual local API error codes and submission observations
separate.

## Durable evidence and comparison gates

Before any directory mutation the helper saves executing ScriptBlock AST text
as UTF-8 without BOM, its SHA-256, the exact ownership manifest and a durable
CreateNew/WriteThrough event. This source basis is explicit; the journal does
not claim to have copied arbitrary original file encoding/BOM bytes. Each next
intent, response and reconciliation creates a new event file. No old event is
overwritten. Cleanup verifies the retained source hash and latest state, and
refuses corrupt latest state rather than loading an earlier safe-looking one.
The root journal directory must be new or carry the exact helper purpose marker;
paths must stay inside it without traversing reparse points. It contains no
credential payload. Public raw descriptor bytes belong only to disposable OUs.

RootDSE is checked for the explicit host, naming contexts, AD DS capability and
SD-flags control. The directory service's `dSHeuristics` is read only. An unknown
or enabled character-5 `fLDAPUsePermMod` prevents all provisioning/test writes.
Its absence is interpreted as the documented default only under the caller's
explicit existing-administrator prerequisite.

For every fresh child the helper records independent NTSD reads with critical
SD-flags 4, 7 and 15, including response codes, exact base64 bytes, hashes,
revision, controls, offsets, owner/group and ACE bytes. It then sends each
returned value in an LDAP Compare WITHOUT the SD-flags control. Actual Compare
TRUE(6) for the explicitly selected mask is mandatory before any candidate
mutation. A FALSE(5), unsupported comparison, read refusal or missing result
leaves that case unsubmitted; another successful mask is never selected instead.
The Compare preflight is not labelled CAS. The expected old value still goes
inside the one Modify request.

Each candidate adds only an explicit, non-inheriting ReadProperty(16) object
ACE for Everyone, scoped by a unique random object-type GUID. All original ACE
bytes and available owner/group/SACL values are retained; object ACL revision 4
is used. This grants no write, owner, administrator or inheritance rights.

The four fresh children receive at most these candidate requests:

| Child | Atomic Modify candidate |
| --- | --- |
| match-delete-add | DELETE exact old NTSD; ADD exact desired NTSD |
| stale-delete-add | Same original old/new request after concurrent setup |
| match-delete-replace | DELETE exact old NTSD; REPLACE exact desired NTSD |
| stale-delete-replace | Same original old/new request after concurrent setup |

The write control is critical DACL-only mask 4. Neither permissive-modify nor
assertion controls are added. Native runtimes can encode equivalent BER lengths
differently; actual control bytes are preserved, and offline tests decode the
integer rather than requiring a particular valid length encoding.

Each stale setup is one clearly labelled ordinary fixture REPLACE on a separate
fresh connection, adding a different harmless tagged ACE. It is never an SDK
write, atomic claim, CAS retry or fallback. Independently observed current
Compare TRUE(6), original-old Compare FALSE(5), and the concurrent tag are all
required before submitting the unchanged stale candidate. Failure to establish
those gates leaves the candidate unsubmitted. No mutation is retransmitted;
a lost response stops later test mutations after independent read reconciliation.

Before each mutation all known live GUID/DN/class/marker identities and the
complete owned subtree are checked. Foreign, moved, duplicate, missing or
unknown identities stop the action. Post-state retains all measured sections,
actual outcomes, desired/concurrent tags and preservation checks. Omitted or
refused sections remain unknown. LDAP53 is a refusal, not successful stale
protection. A universal refusal, no-op or success for a stale overwrite does not
establish a CAS route. `collection_complete` means only the bounded experiment
finished; `qualified` remains false in every report.

## Separate cleanup

Preparation never automatically removes objects. Cleanup reloads the exact run,
mask, source and latest ownership state. A create intent without a pinned GUID
requires independent owner reconciliation; it is not blindly adopted. Cleanup
checks the whole live set before every deletion, then verifies an exact owned
leaf has no descendants, deletes each child once, and deletes the empty root
last. It sends no tree-delete control and performs no recursive AD deletion.
A previously submitted delete that remains present is not retried automatically.
All cleanup errors retain the journal for root to reconcile.

Cleanup claims completion only after separate DC1 and DC2 connections report
actual LDAP32 for every known GUID and exact DN, plus zero results from exact
marker searches. LDAP0 with zero entries, referrals, timeouts and missing results
do not establish absence. Public journals/source remain on disk for collection;
there is no recursive filesystem removal or secret cleanup claim.

## Offline verification and decision

Run `test-sdk06-atomic-acl-probe.ps1` with each shell. It creates only task-local
mock journals and reports `native_ldap_calls=0`. Tests cover all four cases,
fixed mask/no fallback, exact request order and operands, control decoding,
source-before-intent-before-mutation, lost results, deadlines, foreign/moved
identities, no delete replay, both-DC absence, source tampering, latest journal
corruption, endpoint/mask/input guards and no ambient native execution.

Only root's later actual positive/stale/concurrent results can establish the
next protocol decision. If no selected representation gets CompareTRUE, resolve
that representation gap first. If matching candidates still refuse, retain the
real diagnostics and keep #195 open. A successful matching/stale strategy would
justify a separately reviewed actual-session SDK regression and minimal fix;
it does not automatically qualify all server/client profiles or silently remove
explicit GUID/uSNChanged ExpectedVersion requirements.

## Child ScriptBlock scope correction

Root's first actual source `0c6414e4...` invocation stopped with a private
function lookup error before directory context/provisioning. Root independently
verified both controllers had no created objects; no CAS outcome is inferred.
The original source and original offline receipts remain retained unchanged.

The corrected helper retains reviewed native functions and the per-action
credential/deadline environment in one private, non-exporting module, with
explicitly module-bound callbacks. This preserves function lifetime when the
source is invoked as a child ScriptBlock through PowerShell Direct. It changes
no request, comparison, ownership, cleanup or qualification policy.

`test-sdk06-atomic-entry-scope.ps1` deliberately does not dot-source the helper.
It reproduces the original lookup failure, then verifies the fixed budget and
nested request-construction paths after the child invocation has ended. Wrong
endpoint/shape guards stop before any LDAP connection. It passes eight checks
in both PowerShell 5.1 and 7, alongside all 79 original orchestration guards.
The new exact hashes and four receipts are in
`sdk06-atomic-acl-probe-review-ddcb6975.json`. No corrected live result is claimed.
