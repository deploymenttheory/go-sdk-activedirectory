# NTSD Compare refusal and next bounded atomic-write experiment

Reviewed 2026-11-19. This is a diagnosis/proposal for unresolved #195, not an SDK
change, live invocation, supported-route claim or contract relaxation. The
implementing agent made only public host-file reads and primary-document reads.
Root owns every actual lab invocation. SDK07/10 source/index leases are released;
this note and its additive audit are confined to root `tmp/`.

## What the actual reference establishes

Root executed source `ddcb697567cf9345578de34c23b0a59a28e8eaa5994592a226d7338212a2ae80`
as run `sdk06-cas2-20261119t023520965z-m15`. Each of four fresh child OUs returned
LDAP0 for masks 4/7/15. The representations were 1688/1744/1864 bytes. Full15
had nonzero owner/group/SACL/DACL offsets 1808/1836/20/140 and control 0x8c14.
Thus this run did obtain a descriptor with all selected sections; an omitted
owner/SACL does not explain these full15 observations.

All twelve standalone, no-control Compare requests returned actual LDAP53:
`00002095: SvcErr: DSID-03080160, problem 5003 (WILL_NOT_PERFORM), data 0`.
All four candidate CAS requests remained unsubmitted. That is an unavailable
comparison oracle, not a rejected matching/stale atomic Modify experiment.
No mask7/4 rerun is justified by this result: they were already measured too.

All five OU creations and five exact leaf deletions received LDAP0. The helper's
historical cleanup flag remains false after a later RuntimeException. Root's
independent report separately verifies all five GUIDs and DNs absent with
actual LDAP32 on both DCs. Its unscoped domain marker search returned three
references; the advertised critical DOMAIN_SCOPE control produced LDAP0, zero
objects and zero references on both DCs. A future cleanup should explicitly
scope that marker search; it must not discard referrals or rewrite the old flag.
The referral evidence is consistent with the helper's explicit reference guard,
but the original exception did not preserve an exact failing command/message.

`tmp/sdk06-ntsd-full15-compare-observation.json` is an additive host-only audit
with exact public input hashes, all twelve status/section observations, source
hash and separate historical/independent cleanup facts. Its SHA256 is
`5526950ac4a84aed82faa1e79307fab72539d7e1d9d9922bdd2e1dfca0fd3208`.
Original H: records were not modified.

## Primary rules and the limits of the diagnosis

- [MS-ERREF Win32 codes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d)
  maps 0x2095 to ERROR_DS_GENERIC_ERROR (8341). It does not identify an NTSD
  matching/authorization cause. Earlier Modify0x2077 is the distinct
  ERROR_DS_ILLEGAL_MOD_OPERATION (8311); neither diagnostic proves stale rejection.
- [MS-ADTS 3.1.1.2.2.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad58bcc9-1ce3-4b4c-98b2-a79b62a39259)
  maps String(NT-Sec-Desc) to SecDesc and exposes only presence, with equalityMatch
  absent. Its stated scope is LDAP **search filters**. The separate
  [SecDesc rule](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5dcca0b6-169c-4f21-9392-8974ae5e4e1d)
  defines octet comparison; it does not advertise a standalone Compare API.
- [RFC4511 4.10](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.10)
  defines Compare through the attribute's EQUALITY rule; an error is distinct
  from TRUE/FALSE. [RFC4512 2.5.1 and 4.1.3](https://www.rfc-editor.org/rfc/rfc4512.html#section-2.5.1)
  distinguish equality assertions from value addition/removal and disallow AVAs
  when equality matching is unspecified. Inference: these rules support treating
  standalone NTSD Compare as an unsuitable oracle. No exact MS-ADTS clause found
  mandates this NTSD-specific LDAP53 diagnostic or proves every Windows version
  universally refuses it. The search table alone cannot prove that AD lacks
  an internal comparator used during Modify.
- [MS-ADTS Modify constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/76df255d-dc67-4c1f-adc6-1e5b60021304)
  independently specify strict missing-value removal failure without permissive
  modify, final schema compliance, and additional NTSD constraints. NTSD-specific
  DELETE acceptance and section matching remain unproven by the zero-submission
  run. [RFC4511 4.6](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6)
  requires ordered atomic changes, while a lost response remains uncertain.
  AD's [transactional semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1b6bc13c-fd9e-4168-a721-f9d7a0150a8c)
  do not turn separate reads and writes into one transaction.
- [SD flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499)
  select read/write sections, not a version predicate. AD can recompute inherited
  ACEs at commit under [NTSD processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e42f988c-72a0-4f8d-a705-7235eac175d9).
  Keep exact raw states and explicit/inherited/owner/group/SACL observations.

## Proposed next experiment: full15 stable reads, strict Modify guards

This requires root's separate review before helper implementation/invocation.
Use a fresh run and one root OU plus four child OUs, with the same exact
GUID/DN/class/nonce guards, durable source/intent journals, existing Admin25,
explicit Kerberos signing/sealing, bounded native connections, no retries and
separate independently verified cleanup. Require read-only fLDAPUsePermMod=false.
Require advertised critical DOMAIN_SCOPE only for domain-wide marker searches;
never accept unknown/partial referral results as absence.

Use **only full15** snapshots. Do not send further Compare requests. On each
fresh target read objectGUID, uSNChanged and full15 NTSD twice through independent
connections to the same selected DC. Require identical GUID, USN and exact raw
bytes, successful reads and present owner/group/DACL/SACL. This is a test-data
stability prerequisite, explicitly not the atomic guard.

1. On `match-delete-add`, construct N from exact old O by adding only one unique,
   explicit, non-inheriting ReadProperty object ACE. Submit exactly one Modify:
   DELETE NTSD=O; ADD NTSD=N, critical write SD-flags4, no permissive/assertion.
   Independently read full15 afterward. Require actual LDAP0, intended tag,
   retained unrelated ACEs, owner/group/SACL and exact recorded normalization
   before describing the shape as a matching positive. A refusal is not support.
2. On `match-delete-replace`, make the same independent measurement with DELETE O;
   REPLACE N. This is a predeclared different fresh case, never fallback/retry.
3. Only if a shape actually passes its matching positive, use its fresh stale
   child. Record full15 O and N. A separate fixture connection performs one
   clearly labelled ordinary REPLACE adding a different harmless concurrent ACE.
   Capture current C twice: stable GUID, changed USN, exact C != O, concurrent
   tag present, unrelated sections retained. Then submit the **unchanged original
   O/N** strict pair once. No refresh of expected-old, retry or unconditional
   replacement is allowed.
4. A valid stale result needs an actual old-value rejection (normatively LDAP16
   for the missing strict old value), desired tag absent, concurrent tag present
   and unchanged C. Retain precise diagnostics. A universal53, unknown result,
   no-op, mismatched post-state or successful stale overwrite is not a guard.
   Missing responses stop later mutations and are reconciled independently.

If both matching shapes refuse, stop without two unnecessary stale setup writes:
there is still no supported atomic route. If a shape passes matching and stale,
propose a separate fresh two-writer barrier experiment: both clients hold the
same O and submit distinct proposed tags once. Exactly one acknowledged success
and one precise stale rejection, with winner-only post-state, is required.
A missing response is uncertain; two successes falsify the candidate. This
follow-on is not executed or silently bundled into the first bounded run.

## Product/version requirements remain unchanged

The read prerequisite above is not replacing any server guard. O remains inside
one atomic Modify. A positive strict NTSD byte-value guard would still not prove
an object GUID/uSNChanged condition or prevent ABA/non-NTSD updates. Current
`InternalDirectoryDACLWriteControls` derives GUID/uSNChanged even when the caller
omits ExpectedVersion and preserves explicit caller versions. That contract
cannot silently become descriptor-only CAS.

A later version-control negative should change only a harmless separate owned
attribute such as displayName (keeping the description ownership marker fixed),
prove GUID/NTSD unchanged but uSNChanged advanced, then show whether the proposed
route can enforce the old explicit version. Without a supported atomic version
predicate, that requirement remains unresolved; preflight reads, touching
uSNChanged, unconditional REPLACE, or an always-unsupported substitute do not
complete #195. Full15 privileged reference reads also do not qualify callers
who cannot load SACLs, other server versions or unknown/inherited sections.

Do **not** promote ADD(expected)+REPLACE with permissive modify. The
[permissive-control rule](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/49cdb1e3-3baa-4c7c-8cde-7c26b13d3ba7)
only suppresses duplicate/missing-value errors. RFC4511 permits intermediate
schema violations, and AD checks final schema compliance; neither proves an
immediate single-value failure before the later REPLACE. A stale differing ADD
could therefore be removed by that REPLACE and overwrite current state. No
normative eager single-value guarantee or actual stale refutation has been
established. This alternative is excluded from the proposed first experiment.

No SDK fix is justified yet. The next concrete evidence is actual full-value
matching strict Modify success and valid stale/concurrent refusal, followed by
an independently supported object-version condition. Keep #195 and its dependent
release/contract gates open, with all historical failures unchanged.
