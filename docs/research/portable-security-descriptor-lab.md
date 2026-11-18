# Portable descriptor live collector

`TestPortableServiceAccountDescriptorLab` in the acceptance package is opt-in. It requires an independently prepared isolated `AD.SDK.TEST` fixture and explicit JSON stdin. Normal unit tests skip it. This collector is not evidence of a successful live run until its actual source, binaries, results and independent cleanup have been retained.

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
