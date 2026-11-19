# Native full-descriptor comparison reference

This is evidence for the open atomic `nTSecurityDescriptor` investigation in
#195. It changes no SDK/runtime behavior and establishes no supported atomic
route, SDK defect, or universal NTSD limitation. The two actual references used
native .NET LDAP, separate from the portable SDK. Their controls, executed
sources, exact results and independent cleanup records are
[retained without rewriting](portable-security-descriptor-evidence/server2025-full-comparison/README.md).

| Actual Server 2025 reference | Observed outcome |
| --- | --- |
| `sdk06-cas2-20261119t022715454z-m15`, source `0c6414e4...` | Private helper function resolution failed before directory context or provisioning; all five creation intents false, zero CAS submissions; independent both-DC no-created-object proof |
| `sdk06-cas2-20261119t023520965z-m15`, source `ddcb6975...` | Five OU creations; twelve successful descriptor reads; twelve standalone Compare LDAP53 refusals; zero CAS/stale-setup submissions; five leaf deletions acknowledged LDAP0; historical helper cleanup false, independent scoped both-DC absence verified |

The first failure belongs to the reference harness. A child ScriptBlock's
`GetNewClosure` module could not resolve private helper functions. Corrected
source retains the reviewed functions and per-action environment in a private,
non-exporting module. Offline tests reproduce the original lookup failure and
pass eight child-entry/lifetime checks in PowerShell 5.1 and 7 without LDAP
calls. Each shell also passes the original 79 mocked ownership/orchestration
guards. Those tests verify tooling; they do not qualify AD or the SDK.

## What the full15 reference measured

Four fresh GUID/DN/class/nonce-owned child OUs were beneath one owned root OU.
The selected snapshot mask was explicitly 15. Independent connections used
explicit Kerberos credentials with requested signing/sealing; the records do
not invent a measured cipher. The helper read `dSHeuristics` and established
strict-modify preconditions without changing it. No account, group, password,
server policy or existing object's descriptor was changed by this reference.
The five additions and five deletions are actual disposable directory mutations.

Each target returned LDAP0 for descriptor reads with critical SD-flags 4, 7 and
15. The exact returned lengths were 1,688, 1,744 and 1,864 bytes. Full15 had
nonzero owner/group/SACL/DACL offsets 1808/1836/20/140 and control `0x8c14`.
The full15 observation therefore has all selected sections; an omitted owner
or SACL does not explain its standalone Compare result.

All twelve Compare requests omitted controls and returned actual LDAP53:

```text
00002095: SvcErr: DSID-03080160, problem 5003 (WILL_NOT_PERFORM), data 0
```

`0x2095` is `ERROR_DS_GENERIC_ERROR` (8341), not a precise stale-value or
NTSD-modification classification. The earlier projected delete/add probe's
`0x2077` is a distinct illegal-modification error. The diagnostic suffix is
debugging information, not an additional portable result code.
[MS-ERREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d)

CompareTRUE was a self-imposed prerequisite of this experiment. It failed, so
the helper correctly submitted **zero atomic Modify candidates** and zero
independent stale-setup replacements. This run did not test whether a complete
old descriptor can guard a strict Modify; it cannot establish matching success,
stale rejection, or universal NTSD CAS support/absence.

## Cleanup facts remain separate

All five exact leaf Delete requests received LDAP0. A later RuntimeException
left the helper's historical `cleanup_complete=false`; that original flag is
unchanged. The later independent read-only report is a separate observation.

On each selected DC it establishes actual LDAP32 for every one of the five
recorded GUIDs and exact DNs. Its unscoped domain marker search returns LDAP0,
zero entries and **three references**, explicitly marked unused for absence.
With the advertised critical DOMAIN_SCOPE control `1.2.840.113556.1.4.1339`, the
same marker search returns LDAP0, zero entries and zero references. Only that
scoped search contributes to the absence proof. The audit preserves both
results rather than dropping referrals or relabelling the historical cleanup.
[Independent report](portable-security-descriptor-evidence/server2025-full-comparison/full15-ddcb6975/independent-scoped-cleanup-audit.json)

## Protocol interpretation and remaining experiment

AD's supported-comparison table exposes only presence for SecDesc syntax, and
explicitly scopes its table to LDAP search filters. The separate SecDesc rule
defines octet comparison behavior. RFC4511 Compare uses an attribute's EQUALITY
rule; RFC4512 restricts assertions when equality is unspecified. Together these
support treating standalone Compare as an unsuitable oracle here. No exact
NTSD-specific rule requiring this LDAP53 diagnostic was found; the filter table
does not prove every internal Modify comparison behaves identically.
[Supported comparisons](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad58bcc9-1ce3-4b4c-98b2-a79b62a39259),
[SecDesc rule](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5dcca0b6-169c-4f21-9392-8974ae5e4e1d),
[RFC4511 4.10](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.10),
[RFC4512 2.5.1](https://www.rfc-editor.org/rfc/rfc4512.html#section-2.5.1)

Strict missing-value removal and ordered atomic Modify are distinct questions.
The retained [next-probe proposal](portable-security-descriptor-evidence/server2025-full-comparison/research/sdk06-ntsd-compare-diagnosis-and-next-probe.md)
uses reproducible full15 reads as test-data preparation, retaining exact-old
bytes **inside one Modify**. It proposes separate strict DELETE+ADD and
DELETE+REPLACE matching positives, valid stale controls only for a successful
shape, and a later controlled two-writer test. No proposal was implemented or
invoked in this evidence PR. A stable read is not the server-side guard, LDAP53
is not a stale success, and permissive ADD-old+REPLACE has no established eager
single-value stale guard.
[Modify constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/76df255d-dc67-4c1f-adc6-1e5b60021304),
[RFC4511 4.6](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6)

Even a future descriptor-byte CAS positive would not by itself enforce the SDK's
implicit or explicit object GUID/uSNChanged `ExpectedVersion`, prevent ABA, or
cover a non-descriptor concurrent update. Full object-version requirements,
unknown/inherited-section preservation, privileges, client/server qualification
and lost-result behavior remain required. No preflight-as-CAS, unconditional
replacement, retry, always-unsupported substitute or contract relaxation is
introduced. #195 remains open.

## Retention and verification

The evidence directory includes every original public JSON/text file and both
guest journals, frozen executed helper versions, review metadata, six PS5.1/7
offline receipts, exact test sources, primary research and the next proposal.
Historical pre-invocation reviews keep their original claims at their original
time. An original README prefix is recovered only after matching its recorded
length and SHA256; its later appended version is separately retained.

`artifact-hashes.json` records original byte lengths/SHA256 under the existing
`-text` Git rule. The reusable auditor verifies those actual binary `git
cat-file` blobs, both zero-CAS outcomes, every cleanup distinction and all
Go/module blob identities against base `0cab072e56a3c60e8a7c3a9a17b5c52fde2cb898`.
No repeat Go test run is claimed for this documentation-only update; required
PR CI runs independently. No lab/VM/SSH/LDAP calls are part of preservation,
auditing or the PR.
