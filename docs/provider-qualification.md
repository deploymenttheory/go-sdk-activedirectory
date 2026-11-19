# Provider foundation qualification ledger

**SDK-11 remains incomplete under [#212](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/212).** This audit prepares the release decision for a
qualified provider subset; it neither approves a release nor promotes the SDK's
151-operation coverage inventory. Its SDK source baseline is
`0cab072e56a3c60e8a7c3a9a17b5c52fde2cb898`, with tooling-only candidate
`ac4cade4c93fdfd4214c2e5acf9397676daf53b5`. That retained audit is historical.
The integration status below was refreshed against merged main
`09f321444f0d40baeb55106f85457fb41e607fc8` on 2026-11-19; integration does not
complete the remaining feature and release gates.

The approved [provider product rules](https://github.com/deploymenttheory/terraform-provider-activedirectory/blob/fbf49c8b4e8307f00d596064b8ceb8ba77cbda00/docs/plans/activedirectory-provider/README.md#product-rules)
and [SDK-11](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/176)
require per-feature evidence. Closed implementation issues, native captures,
planned provider resources and offline checks do not qualify a portable backend.
The SDK's broader [v1 gate](sdk-readiness.md) remains separate.

## Retained foundation evidence

| Feature | Actual source and scope | Evidence and integration state |
| --- | --- | --- |
| Verified TLS/simple bind | `ca38eb1`, Go 1.27.4; Windows/Linux **amd64**, LDAPS/StartTLS, all four server versions | [16 SDK cells, 16 direct public TLS cells, 72 controlled peers](research/portable-ldap-validation.md); merged, independent cleanup retained |
| Portable Kerberos over TLS/CBT | `958d4a4`, Go 1.27.4; explicit password/keytab/FILE cache, LDAPS/StartTLS, mutual authentication | [All four server profiles](research/portable-kerberos-validation.md) merged; [PR #201](https://github.com/deploymenttheory/go-sdk-activedirectory/pull/201) integrated the complete 2016 proof and restoration records, originally audited at immutable head `7df55aa7fd91662470ab2fcc1bff5909aff79c5b` |
| SASL Sign/Seal and connection-loss recovery | Same `958d4a4`; plain LDAP with the exact required layer, real AD writes, forwarded record faults, retirement and independent reconciliation | [SASL ledger](research/portable-sasl-validation.md); all four profiles merged through PR201, including retained failed/control-recovery attempts |
| Historical publication/API boundary | `ac4cade`, raw committed bytes; canonical module ZIP, fresh independent downloaded consumer, Windows amd64 unit execution; six OS/arch builds | [Retained report](research/provider-qualification-evidence/consumer-ac4cade/report.json), [source hashes](research/provider-qualification-evidence/consumer-ac4cade/source-manifest.json); covers the historical main baseline plus verification tooling and predates integrated SDK09/RPC work |

Each Kerberos/SASL profile contains **84 process cases: 68 actual AD/context
cases, 12 local configuration refusals and four local expired-credential
refusals**. Local refusals are never server interoperability evidence. The audit
checks exact unique case identities rather than accepting the manifest's counts
or `passed` flag. Reordered schema reads retain `not-attempted` mutation state;
tampered/truncated write replies retain `uncertain` state. Both require actual
fault forwarding, session retirement, no second write and independent read-only
reconciliation. The four merged profiles retain 272 actual AD/context cases,
48 local configuration refusals and 16 local expired-credential refusals.

The [machine-readable audit](research/provider-qualification-evidence/authentication-audit.json)
is the unchanged historical report. It checks raw Git artifact hashes,
2,755 canonical authentication build inputs,
437 canonical TLS runtime inputs, observed protection/refusal/expiry facts,
unchanged five-file caller credential inventories on both clients, child
fixture/relay cleanup, exact policy restoration, two-DC outer absence and private
credential retirement. The TLS historical archive/checkout variant is not
relabeled as wholly identical to raw Git blobs. Independent TLS cleanup and
bad-certificate peers are checked separately from actual AD TLS positives.

`ChannelBindingSent` means the actual certificate-derived binding was emitted.
Mutual authentication alone does not prove that the peer checked it;
`ChannelBound` stays unconfirmed. Correct bindings accepted and missing/tampered
bindings refused with actual LDAP49/`SEC_E_BAD_BINDINGS` under the recorded Always
policy establish interoperability for those lab policies. Unprotected LDAP and
AD's invalid TLS-plus-SASL-layer combination fail locally without fallback.

## Open release and feature gates

| Gate | Concrete remaining requirement | Owner/tracker |
| --- | --- | --- |
| Portable mutation contracts | Finish both Server2016 client cells, including distinct privileged deletion proof; retain all normalization, accepted-clear, hidden-read and partial membership/site requirements | [#174](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/174) implementation and [PR202](https://github.com/deploymenttheory/go-sdk-activedirectory/pull/202) are merged; the [mutation ledger](research/portable-mutation-matrix-qualification.md) retains the remaining gates. Runtime `8c891f4c83e8ceabfc7d93637751e71f33f26ac2` is outside the historical consumer baseline |
| PowerShell-compatible ACL workflows | Ordinary OU/password-permission updates use GUID-addressed DACL replacement; explicit versions still require server enforcement. Verify actual cmdlet parity and retain concurrent-writer limits | [#195](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/195); user selected AD PowerShell semantics after the atomic NTSD alternatives were refused |
| gMSA descriptor qualification | Complete applicable remaining client/server cells, permission/inheritance and failure coverage; do not extrapolate the [Windows2025 matching/stale result](research/portable-security-descriptor-lab.md) to other clients/servers | #195; Server2019 fixture preparation is blocked by the recorded KDS prerequisite, not proven unsupported |
| Candidate packaging after integration | Repeat the isolated consumer for the actual final candidate after required feature PRs land; the retained `ac4cade` proof predates merged SDK09/direct-RPC additions and does not qualify them | SDK-11; historical `eb99133` and `ac4cade` consumer reports remain historical |
| Acceptance infrastructure | Retain protected credential delivery, target DNS/KDC/trust and client provenance plus independent cleanup; SDK lab observations do not complete provider acceptance-job provisioning | Provider [LAB-02 #19](https://github.com/deploymenttheory/terraform-provider-activedirectory/issues/19), still open |

Other features have their own gates rather than becoming blanket blockers for
every provider resource. Portable policy/expression code is merged, with
four-server proof merged through [PR203](https://github.com/deploymenttheory/go-sdk-activedirectory/pull/203),
closing [#198](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/198).
The complete authentication matrix and restoration proof similarly merged through
PR201, closing [#194](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/194).
Direct replication RPC implementation [#172](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/172)
and [PR204](https://github.com/deploymenttheory/go-sdk-activedirectory/pull/204) are merged;
the [replication ledger](research/portable-replication-validation.md) retains the
uncompleted matrix, credential, permission and parity requirements.
Release only features whose complete requirements are evidenced; this ledger
does not infer coverage from these PR titles or promote either feature.

In particular, replication's Windows/Linux Server2016 cells, remaining
keytab/cache sources, ordinary-account refusals and partial-result/parity cases
remain unqualified. Closed #172/#174 record merged implementation history;
they do not waive these explicit gates. The [SDK epic #165](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/165)
and [programme index #164](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/164)
remain open. The explicit continuation gates are
[#209](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/209)
for replication/discovery,
[#210](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/210)
for remaining mutation qualification,
[#211](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/211)
for actual delegated cross-domain moves, and
[#212](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/212)
for final provider foundation qualification. Atomic ACL/descriptor work remains
in #195. Closed implementation tickets do not waive any of these requirements.

Infrastructure absence, an unmerged evidence PR, an observed server refusal and
an intentionally excluded product surface are different states. For example,
early gMSA `Key does not exist` during fixture creation means no SDK case ran.
The [KDS prerequisite note](research/kds-qualification-prerequisites.md) separates
documented replication waiting guidance from actual key-interval eligibility;
it neither requests key material nor authorizes additional keys/backdating.

macOS receives portable tests/builds, with **no live AD claim**. The fresh consumer
executed on Windows amd64; Linux/macOS and both arm64 variants were cross-builds
only in that run. Historical Linux unit/race runs remain separately labeled.
CI's macOS unit execution is platform coverage, not lab acceptance. No amd64
capture qualifies arm64 live behavior. AD LDS, host-local service-account and DC
cloning operations remain outside the provider programme.

## Reproduce the offline checks

These tools make no directory, SSH, guest or lab calls. They need Python 3.10+,
Git and the SDK's declared current Go version (currently **1.27.4**). They never
read credential files, use a Windows runtime gateway, modify source, retry a
directory mutation or overwrite an old output directory/report.

```powershell
python -m unittest discover -s scripts/qualification -p 'test_*.py' -v
python scripts/qualification/audit_auth_evidence.py --root . --revision HEAD `
  --output tmp/auth-audit-fresh.json
python scripts/qualification/module_consumer.py --root . --revision HEAD `
  --go C:/path/to/current/go.exe --output tmp/module-consumer-fresh
```

The selected revision now includes all four merged authentication profiles. Use
`--pending-auth-revision` only when deliberately auditing an older snapshot
against an immutable, separately reported candidate commit. Git
history is needed for the pinned build-source checks. A missing record/commit
fails the audit; it is never converted to passing or unsupported coverage.

The consumer uses `git cat-file` raw blobs, rejects gitlinks/symlinks, nested
modules and private/tool-state paths, and stages every committed file. A separate
fresh tooling module pins `golang.org/x/mod v0.43.0` and checks canonical ZIP rules;
no dependency or local replacement is added to the SDK. A fresh consumer cache
downloads that exact ZIP through a local file proxy. Every downloaded file and
every compiled SDK import is checked against the candidate and module-cache
boundary. Public tests exercise secure configuration rejection, credential
redaction and portable descriptor/conditional round trips without network I/O.
All six Windows/Linux/macOS amd64/arm64 consumer builds are recorded separately
from actual host execution.

The adversarial tests reject missing/changed licenses, nested modules, gitlinks,
checkout-vs-Git byte substitution, replacement/cache escapes, fabricated CBT
refusal, weak/inferred protection, forwarded-fault omissions, lost uncertainty,
incomplete cleanup and changed caller files. A passing audit means these retained
records are consistent. It does not decide release readiness.

The isolated `Provider qualification audit guards` workflow executes those
offline guards on Windows and Linux without lab secrets. The heavier fresh-cache
consumer and full-history evidence audit remain explicit release-candidate
checks; ordinary CI does not claim to have run them or a live directory matrix.

No new live run is applicable to this offline tooling/documentation change.
Required live evidence remains with the feature owners and the open gates above;
PR205 remains draft with `Closes #176` reserved for merge after the delivery
ticket's acceptance criteria and remaining gates are complete.
