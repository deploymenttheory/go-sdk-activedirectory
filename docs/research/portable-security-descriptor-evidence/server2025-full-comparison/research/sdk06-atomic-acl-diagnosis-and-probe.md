# SDK-06 atomic NTSD diagnosis and bounded native probe proposal

Reviewed 2026-11-19. This is a task-local research/probe proposal for #195,
not an SDK implementation, server qualification, or permission to run it.
No lab, guest, VM, SSH, SDK/provider source, or Git index was changed.
The companion [primary-source review](sdk06-atomic-acl-primary-source-research.md)
contains the broader protocol inventory and 26 primary references.

## Diagnosis supported by the existing bytes

I verified every one of the 15 entries in
`docs/research/portable-security-descriptor-evidence/server2025-cas/index.json`.
The retained native run `sdk06-cas-20261118t184659109z` used contacts, explicit
Kerberos signing/sealing, and critical SD-flags4 for both read and modify. It
never called the SDK. Both two-change DELETE(old)+ADD(new) attempts returned
actual LDAP53 with diagnostic `00002077`, `WILL_NOT_PERFORM`, data87; independent
readback was unchanged. The separate actor's ordinary REPLACE succeeded. That
establishes permission and that the replacement descriptor shape was accepted;
it does not establish an atomic old-value check.

Both before descriptors are 1,448 bytes. Their self-relative headers have
control `0x8c04`, owner/group/SACL offsets `0/0/0`, and DACL offset20. They are
DACL projections. A stored NTSD owner cannot be NULL under
[MS-ADTS6.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a).
Consequently the label 'matching old' proves agreement with the DACL-only read,
not equality to the complete stored descriptor.

[SecDesc comparison](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5dcca0b6-169c-4f21-9392-8974ae5e4e1d)
uses [octet equality](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b99c5ac7-7eec-4232-8048-3d39b761c055):
identical length and bytes. The SD-flags rules describe section selection for
read/update; they do not specify a projection of an expected DELETE value.
This is an evidence gap, not a proven explanation of LDAP53. The diagnostic
[0x2077](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--8200-8999-)
is ERROR_DS_ILLEGAL_MOD_OPERATION. It does not identify which inner modification
was rejected, and is distinct from LDAP16/ERROR_DS_CANT_REM_MISSING_ATT_VAL.
No normative prohibition on every NTSD DELETE request was found in this review.

The ordinary gMSA `msDS-GroupMSAMembership` references read/wrote the whole
attribute without SD-flags or permissive modify. Their successful matching
and actual LDAP16 stale cases therefore do not establish the same operation
on NTSD, nor validate a projected expected value. Their existing bytes remain
unchanged under `docs/research/portable-security-descriptor-evidence/server2025-gmsa-cas/`.

## Current implementation is correctly gated, not complete

`activedirectory/internal/model/directory_descriptor_controls.go` requires
advertised SD-flags plus critical RFC4528 assertion support, derives the
GUID/uSNChanged condition from the controlled snapshot when needed, and keeps
caller-supplied ExpectedVersion. OU and password-ACL writers send REPLACE with
these critical controls. The unsupported assertion guard currently prevents
submission. `portable_descriptor.go` explicitly records DACL-only section scope.
No inspection here demonstrates an SDK encoding defect that can already be
fixed to produce a supported atomic NTSD mutation.

The gMSA reader-only path has a separate strict whole-value guard and narrowly
maps a real rejected LDAP16 to concurrency. NTSD53 must not be reclassified as
an ordinary stale result. Never weaken the existing gate to unconditional
REPLACE or read/check/REPLACE.

## Protocol routes and limits

[RFC4511 section4.6](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6)
orders a Modify's changes atomically. That makes strict value-specific
DELETE(expected)+REPLACE(desired) a distinct candidate from the refused
DELETE+ADD shape: the guard would remain inside the same request. The RFC does
not establish Windows NTSD acceptance; a missing response remains uncertain.

Permissive ADD(expected)+REPLACE(desired) is another unproven candidate.
[Permissive modify](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/49cdb1e3-3baa-4c7c-8cde-7c26b13d3ba7)
suppresses an exact duplicate ADD, but a different value only guards the write
if NTSD's single-valuedness is enforced before the following REPLACE. Final
single-valuedness alone proves no such guard. Do not implement this shape from
that inference. The first proposed probe below excludes it to stay bounded.

AD does have the [batch extension](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ee97400e-e551-4b4a-9a60-998e89493b3c),
OID1.2.840.113556.1.4.2212. It rolls back on inner failure, but Windows' documented
inner operations exclude Compare and its accepted inner controls exclude
assertion and expected-entry-count. Search success is not an assertion that
one row matched. Batch+Search+REPLACE is therefore not a demonstrated CAS.
Inner failure may have outer success, so an eventual batch adapter would need
all inner statuses and transaction outcome, not only the outer LDAP code.

## Proposed bounded native reference: compare gate, then four fresh targets

This proposal uses one explicit Server2025 DC and the already protected existing
Administrator credential. It creates only a fresh disposable OU and four child
OUs beneath it. It makes no user/group membership, account, password, policy,
DNS, service, KDS, network, or schema change. Parent/root owns execution through
approved PowerShell directly; this researcher performs no lab call.

Inputs are an explicit selected DC FQDN, expected domain NC, caller PSCredential,
owned profile identity, unique ASCII RunId, and explicit OldSnapshotMask in
`4|7|15`. A run is bounded to five owned OUs, four CAS attempts, per-operation
20-second timeout and a ten-minute test deadline checked before every call.
An in-flight native call may finish within its operation bound; stop new test
mutations at the deadline and use a separately bounded independent cleanup.
Run the mask variants as separate
fresh invocations. Do not silently choose a different mask after failure.

Before provisioning, verify exact selected host/RootDSE/domain/profile, capture
OS/module versions, supported controls/extensions and the effective
[dSHeuristics character5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5).
If fLDAPUsePermMod is enabled or cannot be established, do not call the proposed
strict deletion a valid guard. That heuristic can enable permissive semantics
even when the request omits the control. Do not change it for this experiment.
Require SD-flags support. Use explicit .NET LDAP AuthType.Kerberos with requested
signing/sealing to the one selected host; record these as reference settings,
not a fabricated negotiated-cipher result. Never log the credential or its
serialized request arguments.

Provision the root/children exclusively with GUID/DN/class/description markers,
no accidental-deletion protection. Publish the root GUID and every child GUID
before the next mutation. All later operations independently recheck exact
owned identity and location. Do not reuse an existing RunId or object.

### Compare/section measurements for each fresh target

1. Read objectGUID and NTSD three times with critical read SD-flags4,7,15.
   Preserve exact descriptor bytes/hash, revision/control/offsets and actual
   response status for each. An omitted or refused SACL is not evidence it is
   absent. A denied mask15 is a recorded prerequisite/refusal, not an excuse
   to infer a full value from mask4.
2. Issue native LDAP Compare for NTSD using each exact returned value. Omit
   SD-flags on Compare: its specified scope is read/update, not a defined
   comparison projection. Record `read_mask`, `compare_control=absent`, actual
   LDAP5/6/18/etc and diagnostic, without mapping unsupported/false to success.
3. Before any 'matching' CAS, Compare on the explicitly chosen old snapshot
   MUST actually return compareTrue(6). Otherwise record the case unsubmitted
   and preserve the evidence. Do not select another mask or assume logical ACL
   equivalence. Optional comparison-with-control experiments must be labelled
   separately and must not satisfy this unprojected gate.

This preflight Compare only validates the test's expected bytes. It is NOT the
CAS guard. The old-value operand must still be sent inside the Modify below,
so another writer between Compare and Modify cannot be ignored.

### Four cases, each on its own newly created child OU

| Case | Request submitted as one Modify |
| --- | --- |
| match-delete-add | DELETE exact expected NTSD value; ADD desired NTSD value |
| stale-delete-add | Same unchanged expected-old request after independent concurrent setup |
| match-delete-replace | DELETE exact expected NTSD value; REPLACE with desired NTSD value |
| stale-delete-replace | Same unchanged expected-old request after independent concurrent setup |

Every Modify uses critical write SD-flags4, no permissive control, no assertion
substitute, and one exact GUID-addressed owned target. Only a harmless explicit
ReadProperty ACE is added to the desired DACL; original administration entries,
owner/group and all unrelated ACE bytes are retained. A unique object-ACE tag
can distinguish desired/concurrent additions without granting write/owner rights.
Use a valid ACL revision for object ACEs. Preserve the actual builder and bytes.

For each stale case, first establish Compare(expectedOld)=TRUE. A separate real
authenticated fixture connection then performs one explicitly labelled ordinary
REPLACE adding a different harmless concurrent ACE. This is fixture setup,
never an asserted atomic write or SDK fallback. Independently read it, prove
Compare(current)=TRUE and Compare(originalExpected)=FALSE(5), then submit the
original strict CAS request unchanged. If the stale comparator is unknown or
not FALSE, do not submit/classify a stale case.

A matching candidate requires actual LDAP0, intended ACE present, all original
unrelated/admin ACEs and owner/group retained, and independently observed full
post-state. A stale candidate requires an actual server rejection with precise
LDAP/diagnostic, desired ACE absent and concurrent ACE/current value preserved.
An unchanged no-op or a universal LDAP53 is not a working atomic route.
Successful stale replacement falsifies that strategy; do not retry it.

After every response, reconcile the owned object independently before cleanup.
Keep read masks/compare codes separate from modification outcome. If no write
response arrives, stop further test mutations, record uncertainty and reconcile;
do not retransmit. Server normalization and inherited-ACE recomputation must be
recorded rather than silently filtered from the diff. Preservation of currently
unloaded sections is not established from a DACL-only after-read.

Cleanup each exact child GUID only after marker/class/DN and no-descendant
checks; remove the empty root OU last. Never use recursive AD deletion. Refuse
unknown descendants, moved identities or ownership mismatch, retaining a public
reconciliation journal. Verify both-DC absence independently. Retain executed
source hashes, requested/observed controls, all exact before/current/proposed/
after bytes, statuses and cleanup; no private credential payload.

## Decision after the reference

- No CompareTRUE prerequisite: resolve the representation/comparison limitation
  first; no matching-write conclusion is possible under this proposed gate.
- Both shapes refuse matching inputs: preserve those actual results; a supported
  atomic NTSD path is still not established. Do not code an always-unsupported
  replacement and mark #195 complete.
- A shape succeeds matching and rejects valid stale inputs while preserving
  state: propose a minimal actual-session red test and SDK integration for that
  exact supported route before editing production. Keep all remaining profile,
  malformed/refusal/lost-result and unknown/inherited-content qualifications.
- Any future descriptor-value guard must not silently discard an explicit
  caller GUID/uSNChanged ExpectedVersion. That broader version condition still
  requires its own supported atomic enforcement or precise refusal.

No product contract relaxation, SDK code change, fallback, merge or closure is
proposed here. This identifies the next discriminating evidence instead of
claiming either a supported route or universal impossibility.
