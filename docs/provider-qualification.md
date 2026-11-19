# Provider foundation qualification ledger

**SDK-11 remains incomplete.** This audit prepares the release decision for a
qualified provider subset; it neither approves a release nor promotes the SDK's
151-operation coverage inventory. Its SDK source baseline is
`0cab072e56a3c60e8a7c3a9a17b5c52fde2cb898`, with tooling-only candidate
`ac4cade4c93fdfd4214c2e5acf9397676daf53b5`. PR status below is the audit's
2026-11-19 snapshot, not a claim about future merges.

The approved [provider product rules](https://github.com/deploymenttheory/terraform-provider-activedirectory/blob/fbf49c8b4e8307f00d596064b8ceb8ba77cbda00/docs/plans/activedirectory-provider/README.md#product-rules)
and [SDK-11](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/176)
require per-feature evidence. Closed implementation issues, native captures,
planned provider resources and offline checks do not qualify a portable backend.
The SDK's broader [v1 gate](sdk-readiness.md) remains separate.

## Retained foundation evidence

| Feature | Actual source and scope | Evidence and integration state |
| --- | --- | --- |
| Verified TLS/simple bind | `ca38eb1`, Go 1.27.4; Windows/Linux **amd64**, LDAPS/StartTLS, all four server versions | [16 SDK cells, 16 direct public TLS cells, 72 controlled peers](research/portable-ldap-validation.md); merged, independent cleanup retained |
| Portable Kerberos over TLS/CBT | `958d4a4`, Go 1.27.4; explicit password/keytab/FILE cache, LDAPS/StartTLS, mutual authentication | [2019/2022/2025 captures](research/portable-kerberos-validation.md) merged; 2016 proof separately audited from immutable pending [PR #201](https://github.com/deploymenttheory/go-sdk-activedirectory/pull/201) head `7df55aa7fd91662470ab2fcc1bff5909aff79c5b` |
| SASL Sign/Seal and connection-loss recovery | Same `958d4a4`; plain LDAP with the exact required layer, real AD writes, forwarded record faults, retirement and independent reconciliation | [SASL ledger](research/portable-sasl-validation.md); same three merged profiles and separately audited 2016 candidate |
| Current candidate publication/API boundary | `ac4cade`, raw committed bytes; canonical module ZIP, fresh independent downloaded consumer, Windows amd64 unit execution; six OS/arch builds | [Fresh report](research/provider-qualification-evidence/consumer-ac4cade/report.json), [source hashes](research/provider-qualification-evidence/consumer-ac4cade/source-manifest.json); covers the main baseline plus verification tooling, excludes unmerged SDK09/RPC work |

Each Kerberos/SASL profile contains **84 process cases: 68 actual AD/context
cases, 12 local configuration refusals and four local expired-credential
refusals**. Local refusals are never server interoperability evidence. The audit
checks exact unique case identities rather than accepting the manifest's counts
or `passed` flag. Reordered schema reads retain `not-attempted` mutation state;
tampered/truncated write replies retain `uncertain` state. Both require actual
fault forwarding, session retirement, no second write and independent read-only
reconciliation. The three merged profiles retain 204 actual AD/context cases;
the separately reviewed 2016 candidate adds 68, without changing merge status.

The [machine-readable audit](research/provider-qualification-evidence/authentication-audit.json)
checks raw Git artifact hashes, 2,755 canonical authentication build inputs,
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
| Authentication evidence integration | Merge the independently audited complete Server2016 matrix and restoration proof; keep failed/control-recovery captures unchanged | [#194](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/194), candidate PR201 |
| Portable mutation contracts | Complete applicable Linux/Windows four-server qualification for normalization, accepted clears, hidden reads, partial membership/site effects and deletion proof; retain ordinary visibility limits and distinct privileged proof | [#174](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/174), draft [PR202](https://github.com/deploymenttheory/go-sdk-activedirectory/pull/202); immutable runtime `8c891f4c83e8ceabfc7d93637751e71f33f26ac2` is outside this baseline |
| Atomic ACL workflows | Demonstrate an AD-enforced atomic route for OU protection/password-change DACL writes, or obtain an explicit product decision; retain guarded refusal meanwhile | [#195](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/195); matching and stale native `nTSecurityDescriptor` delete/add were both refused LDAP53 |
| gMSA descriptor qualification | Complete applicable remaining client/server cells, permission/inheritance and failure coverage; do not extrapolate the [Windows2025 matching/stale result](research/portable-security-descriptor-lab.md) to other clients/servers | #195; Server2019 fixture preparation is blocked by the recorded KDS prerequisite, not proven unsupported |
| Candidate packaging after integration | Repeat the isolated consumer for the actual final candidate after required feature PRs land; current proof excludes unmerged SDK09/direct-RPC additions | SDK-11; historical `eb99133` consumer report remains historical |
| Acceptance infrastructure | Retain protected credential delivery, target DNS/KDC/trust and client provenance plus independent cleanup; SDK lab observations do not complete provider acceptance-job provisioning | Provider [LAB-02 #19](https://github.com/deploymenttheory/terraform-provider-activedirectory/issues/19), still open |

Other features have their own gates rather than becoming blanket blockers for
every provider resource. Portable policy/expression code is merged, with
four-server proof pending [PR203](https://github.com/deploymenttheory/go-sdk-activedirectory/pull/203).
Direct replication RPC has its own [#172](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/172)
qualification and draft [PR204](https://github.com/deploymenttheory/go-sdk-activedirectory/pull/204).
Release only features whose complete requirements are evidenced; this ledger
does not infer coverage from these PR titles or promote either feature.

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
  --pending-auth-revision 7df55aa7fd91662470ab2fcc1bff5909aff79c5b `
  --output tmp/auth-audit-fresh.json
python scripts/qualification/module_consumer.py --root . --revision HEAD `
  --go C:/path/to/current/go.exe --output tmp/module-consumer-fresh
```

Fetch the immutable pending commit first if it is not present locally. Omit
`--pending-auth-revision` to audit only evidence in the selected revision. Git
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

No new live run is applicable to this offline tooling/documentation change.
Required live evidence remains with the feature owners and the open gates above;
this preparation PR uses `Refs #176`, not a closing keyword.
