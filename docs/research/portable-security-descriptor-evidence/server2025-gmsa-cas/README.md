# Native gMSA descriptor compare-and-write references

These are isolated native .NET LDAP references against Server 2025, using explicit Kerberos with signing and sealing. They do not execute the SDK. Every run uses disabled, marker/GUID-owned objects, retains exact executed sources and public journals, and records independent replicated cleanup on both DCs. No managed password is requested, no KDS root key is created or changed, and no effective-access result is claimed. The ordinary `msDS-GroupMSAMembership` attribute is written without the `nTSecurityDescriptor` SD-flags control or permissive modification.

Each directory's `index.json` records SHA-256 hashes of its raw capture files. Original source comments and failed attempts are preserved rather than edited to fit later findings.

| Run | Observed result |
| --- | --- |
| [190706846z](sdk06-gmsa-cas-20261118t190706846z/result.json) | Setup failed before a native CAS request. Cleanup verified. |
| [190953826z](sdk06-gmsa-cas-20261118t190953826z/result.json) | Corrected setup still failed; the source/result retain the original missing required interval context. No successful CAS is claimed. Cleanup verified. |
| [191110236z](sdk06-gmsa-cas-20261118t191110236z/result.json) | Matching request containing an invalid ObjectAce fixture was rejected LDAP19; after-read was unchanged. Its DACL revision2 contains ACE type5, which requires the object-ACE ACL revision. This does not establish a general attribute rejection of object ACEs or mask0x10. Cleanup verified. |
| [191234241z](sdk06-gmsa-cas-20261118t191234241z/result.json) | CommonAce Control Access `0x100`: matching old accepted LDAP0; stale old rejected LDAP16 (`00002085`); concurrent ACE retained. Cleanup verified. |
| [191358141z](sdk06-gmsa-cas-20261118t191358141z/result.json) | CommonAce Read Property `0x10`: matching old accepted LDAP0; stale old rejected LDAP16; concurrent ACE retained. Cleanup verified. |

The `191234241z` executed source historically calls its `0x100` fixture an SDK grant. That wording is inaccurate and remains unchanged as evidence. The SDK's ordinary explicit reader grant uses Read Property `0x10`; the independent `191358141z` run records that mask explicitly in `fixture_ace`. Neither experiment establishes permission to retrieve a managed password.

In both successful reference runs, the accepted readback equals the proposed descriptor bytes. For stale requests, the readback equals the independent concurrent value, the concurrent ACE remains, and the proposed ACE is absent. These results establish the server mechanics for those exact reference inputs; the portable public SDK still requires its own applicable live qualification on every required server/client combination.
