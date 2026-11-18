# Portable descriptor live collector

`TestPortableServiceAccountDescriptorLab` in the acceptance package is opt-in. It requires an independently prepared isolated `AD.SDK.TEST` fixture and explicit JSON stdin. Normal unit tests skip it. This collector is not evidence of a successful live run until its actual source, binaries, results and independent cleanup have been retained.

The first retained [Windows/amd64 → Server 2025 gMSA result](portable-security-descriptor-evidence/server2025-windows-gmsa/README.md) passes the matching/stale cases with independent cleanup. Its exact source/binary basis and orchestration provenance limits are recorded separately; other required qualification cells remain open.

Build the acceptance test binary from a frozen source tree. Set linker variable `github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/acceptance.portableDescriptorLabBuildRevision` to that exact commit, and independently retain source/build-input and binary digests. Execute only this test with `ADSDK_DESCRIPTOR_LAB_INPUT=stdin`. Supply one JSON object, bounded to 128 KiB:

```json
{
  "endpoint": "adsdk25dc1.ad.sdk.test:389",
  "realm": "AD.SDK.TEST",
  "spn": "ldap/adsdk25dc1.ad.sdk.test",
  "username": "owned-fixture-actor",
  "credential_source": "cache",
  "cache_path": "/protected/owned-fixture.ccache",
  "run_id": "sdk06-owned-unique-run",
  "source_revision": "exact-frozen-source-commit",
  "result": "/fresh/public-result.json",
  "fixture_ou": "OU=sdk06-owned-unique-run,DC=ad,DC=sdk,DC=test",
  "fixture_guid": "independently-recorded-ou-guid",
  "matching_guid": "independently-recorded-matching-gmsa-guid",
  "stale_guid": "independently-recorded-stale-gmsa-guid",
  "reader_dn": "CN=read-only-principal,DC=ad,DC=sdk,DC=test",
  "reader_guid": "independently-recorded-reader-guid"
}
```

The fixture OU must have description `sdk06-descriptor-parent:<run_id>`. Its exact `CN=matching` and `CN=stale` children must be disabled gMSAs with descriptions `sdk06-descriptor-gmsa:<run_id>:matching` and `sdk06-descriptor-gmsa:<run_id>:stale`. Preparation supplies required schema attributes, including managed-password interval30, and grants only the actor's required fixture access. No credential generation, ambient authentication, password retrieval, KDS root-key change or server-policy modification occurs in the collector.

`credential_source` must explicitly select `cache` or `password`. Cache requires a nonempty `cache_path` with suitable tickets or a usable TGT and no password. Password requires `password_base64` containing1–4096 decoded bytes and an empty cache path. Inputs are mutually exclusive, with no fallback. A password is delivered only through the protected process stdin channel, never arguments, environment variables or captured journals. The bounded input and decoded password buffers are cleared; formatting and JSON/text serialization of the input object are redacted. Public output contains no input object or credentials.

Both connections use the public SDK with explicit portable Kerberos, LDAP and required SASL Seal. Actual protection observations must establish an AES17–20 profile, at least128 bits, mutual authentication and complete session facts. LDAP Seal has no TLS or CBT claim. Endpoint, RootDSE, object GUID, marker and disabled-account guards precede writes. Results use CreateNew semantics and never overwrite a prior capture.

The matching case calls the unwrapped public `UpdateServiceAccount` reader workflow. Its proposed bytes are recomputed from the independently checked preflight using the SDK editor for comparison; this is not a wire capture. The accepted public result and complete readback must verify the requested descriptor. Client-side preservation includes owner/group/SACL/control, original unused storage and unrelated ACEs.

The stale case interposes a private test wrapper after the public workflow's descriptor snapshot and before its actual strict delete/add. A second real authenticated connection performs an exact-old/new fixture CAS inserting a benign Write Property ACE in the retrieval descriptor. The wrapper forwards the original public-workflow request unchanged. It never manufactures LDAP16, replaces the snapshot, retries the write, or exposes a production hook. Evidence must show that the actual server rejects the stale request, the public result remains rejected with LDAP16/concurrency classification, and an independent read equals the concurrent value with the proposed reader edit absent.

The outer lab runner owns account/credential creation, private-file digest checks, fixture descriptors/delegation, both-DC replicated absence, and exact marker/GUID cleanup. A failed, accepted-but-unverified or uncertain operation requires independent reconciliation; it never authorizes replay. This collector covers the gMSA descriptor path only. It does not resolve the guarded `nTSecurityDescriptor` atomic-update constraint or substitute for the complete Windows/Linux × Server2016/2019/2022/2025 matrix.

## Owned fixture preparation and cleanup

The host entrypoint is `scripts/lab/security-descriptor-account.ps1`, using the reviewed functions in `security-descriptor-fixture.ps1`. Run it through the approved lab tool with PowerShell7 and the existing private lab profile:

```powershell
pwsh -NoProfile -File scripts/lab/security-descriptor-account.ps1 -Action Prepare -ServerVersion 2025 -RunId sdk06-owned-unique-run
# Independently retain source/binary proof; deliver the actor password only in protected process stdin.
pwsh -NoProfile -File scripts/lab/security-descriptor-account.ps1 -Action Cleanup -ServerVersion 2025 -RunId sdk06-owned-unique-run
```

Prepare pins the owned profile, private switch and running DC identity, captures both executed sources and digests before mutation, creates a fresh marked OU, one enabled AES24 actor and two disabled gMSAs with interval30. Initial retrieval descriptors have SYSTEM owner/group and unrelated basic Control Access/Write Property ACEs without an RP reader grant. The actor receives exactly one explicit object ACE per gMSA: Read/Write Property for the schema-resolved `msDS-GroupMSAMembership` attribute, in an object-capable ACL revision4. This exclusive creation-time provisioning is reference tooling, not a production atomic DACL mutation route.

The public `fixture.json` and stage journals contain names, GUIDs, SID/KVNO and descriptor/delegation proof. The fresh actor password is generated only for that new user and stored in an ACL-protected, DPAPI-encrypted host `secrets/actor.clixml`; no existing account password is reset. The host emits only its path. The prepared actor's own DN/GUID may be the pinned reader identity. There are no KDS root, managed-password retrieval, DC policy, TLS, VM-power or network mutations.

Cleanup verifies every class, DN, marker and recorded GUID, rejects unexpected/moved descendants before its first deletion, removes children and parent nonrecursively, then independently checks both DCs by exact GUIDs, markers and deterministic SAM names. It retires only the unchanged digest-matched private credential file after replicated absence is proven. Public journals and tombstones remain. An incomplete creation is reconciled only within its recorded intent; unjournaled live identities require explicit investigation. Offline PS5.1 and PS7 guard tests cover these refusal boundaries without contacting AD or Hyper-V.
