# Optional-feature protocol contract

Checked against issue [#29](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/29).

Optional-feature objects live below the configuration NC's Directory Service /
Optional Features container. Feature GUID and object GUID are distinct binary
identities. The feature's backlink lists scope objects; its omission does not
establish an empty set. AD DS has forest, domain and server scopes. AD LDS has
configuration-set and server scopes, with no domain scope. Forest/configuration
scope is the Partitions crossRefContainer, domain scope is the domain NC root,
and server scope is an nTDSDSA object. [MS-ADTS 3.1.1.9](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9ae2a9ad-970c-4938-a6bf-9c1fdc0b8b3e)

The scope/disablability bits are forest 1, domain 2, disablable 4 and server 8.
Unknown bits must survive decoding. [MS-ADTS 2.2.17](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5170a98c-091c-4d34-8ca5-fe77630f112a)

Both operations use LDAP ADD on the empty rootDSE DN. The attribute is
`enableOptionalFeature` or `disableOptionalFeature`; the UTF-8 value is the
scope object's DN, a colon, then the feature GUID string. Forest/configuration
operations require the Domain Naming Master, including AD LDS. The caller
needs Manage-Optional-Features on the scope; the server enforces permission.
An already-enabled feature and a missing feature-to-remove produce different
native failures. Neither is automatic permission to retry. A feature without
the disablable bit must reject Disable. [Enable contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3177e885-8912-471b-8fa5-761cabd6b3ff),
[Disable contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8106371b-9d69-413a-8e01-7fd97eca81b1),
[AD LDS role example](https://learn.microsoft.com/en-us/powershell/module/activedirectory/enable-adoptionalfeature?view=windowsserver2025-ps)

Recycle Bin is irreversible and requires functional level 4; PAM is irreversible
and requires level 7. Both are forest-wide and can add a server-wide enabled
link as an additional effect. [Recycle Bin](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9482178-ee53-4b6c-841d-5259d6261985),
[PAM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d079eee8-1bac-4b03-86e4-506a21450905)

Database 32K Pages is irreversible, requires functional level 10, and requires
every DSA to advertise `msDS-JetDBPageSize=32768`. The implementation checks the
complete DSA enumeration before submitting this feature, retaining server-side
validation as the authority. [Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f153eaeb-add8-457c-8a67-21402867fa09),
[Microsoft deployment guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/enable-32k-pages-optional-feature)

Implementation choices: stay on the caller's authenticated endpoint; reject a
wrong owner rather than forward credentials or transfer roles. Require explicit
acknowledgement for irreversible enables. Preserve accepted responses separately
from readback verification, and unknown responses separately from rejection.
An omitted enabled-link attribute cannot verify a disable; the accepted write
remains recorded while readback remains unverified. Backlink ranges continue on
one connection, validating indices/counts and preserving every raw response.
An empty bare attribute can accompany the first range; it is not completion.
Only the terminal star or a complete bare response ends the sequence. Gaps,
resets, duplicates, identity changes and missing continuations remain partial.
Ordering is only guaranteed while the attribute does not change; this is not
an atomic snapshot. [MS-ADTS range retrieval](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e27b48db-6f82-44cd-9038-2e54f790cc1f)
These choices are stricter observations/guards, not claims of live parity.
