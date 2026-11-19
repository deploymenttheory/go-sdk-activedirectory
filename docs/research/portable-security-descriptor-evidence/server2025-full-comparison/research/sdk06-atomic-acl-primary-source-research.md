# SDK-06 atomic ACL: fresh primary-source research

Reviewed 2026-11-19. Scope: public Microsoft protocol documentation and
Microsoft-owned public protocol-test source; no directory, lab, VM, guest, SSH,
or other live service was contacted. The prior
`sdk06-atomic-acl-protocol-notes.md` was read as supplied context. This note does
not qualify an implementation or close the atomic-write requirement.

The reviewed sources do not yet establish a supported `nTSecurityDescriptor`
compare-and-swap route for the retained target. They also do not establish that
every such route is impossible. Two distinct request shapes remain unresolved:
`DELETE(expectedOld) + REPLACE(new)` and permissive
`ADD(expectedOld) + REPLACE(new)`. The unresolved questions are identified below;
neither candidate may be relabelled a working CAS from the present evidence.

Microsoft's current landing page publishes MS-ADTS revision 70.0 dated
2026-10-26. The relevant permissive-modify, schema, expected-entry-count, and
batch passages were cross-checked in that dated DOCX, read in memory. [S1]

## Normative protocol facts

### Atomicity and ordinary attribute guards

An LDAP Modify applies its changes in order as one atomic operation. An error
response means that none of its changes were applied. `delete` with values
removes those values; `replace` supplies the replacement values without any
old-value precondition. RFC 4511 permits some intermediate schema violations
and requires the final entry to conform. It does not say that every intermediate
schema violation is permitted. [S2]

MS-ADTS describes ACID transactions with at least degree-2 isolation and commits
an originating LDAP Modify before returning the protocol response. Each Search
or Update request is a transaction; separate client requests do not become one
transaction simply because the client sends them consecutively. [S3]

For DC functional level Windows Server 2003 or later, without permissive modify,
inserting duplicate values fails with
`attributeOrValueExists / ERROR_DS_ATT_VAL_ALREADY_EXISTS`; removing a missing
value fails with
`noSuchAttribute / ERROR_DS_CANT_REM_MISSING_ATT_VAL`; removing an absent
attribute fails with `noSuchAttribute / ERROR_DS_ATT_IS_NOT_ON_OBJ`.
The final modified object must satisfy its schema, and NTSD modifications have
additional security-descriptor constraints. [S4]

### NTSD syntax and comparison

`nTSecurityDescriptor` is single-valued, has `attributeSyntax: 2.5.5.15` and
`oMSyntax: 66`, and is not `systemOnly`. Those schema facts do not describe the
processing of each possible LDAP Modify change type. [S5]

MS-ADTS's SecDesc comparison rule delegates to the octet-string rule. The latter
defines equality by equal length and identical contents. This is a byte
comparison, rather than semantic equivalence of ACL permissions. [S6] [S7]

The supported-comparisons table is expressly about LDAP **search filters**. It
allows only presence testing for SecDesc; it does not offer SecDesc equality,
ordering, substring, or bitwise filter matches. Consequently that table cannot
be cited as a prohibition on all internal duplicate-value or delete-value
comparison during Modify. [S8]

RFC 4512 separately says that values of an attribute without an equality
matching rule are equivalent when identical. Its restriction on independently
adding/deleting values without such a rule refers to a **multi-valued**
attribute. Neither statement proves how Windows handles an NTSD ADD on an
already-present single-valued attribute. [S9]

### SD-flags and descriptor processing

`LDAP_SERVER_SD_FLAGS_OID` (`1.2.840.113556.1.4.801`) encodes a sequence containing
an integer. Flags `1`, `2`, `4`, and `8` select owner, group, DACL, and SACL.
No flags, or an omitted control, selects all four. [S10]

The security-descriptor section says that search returns selected sections;
for update, only selected fields are updated and other supplied fields are
ignored. The specification does **not** define an expected-value operand or
explain whether a value-specific DELETE or duplicate ADD compares a projected,
merged, or complete stored descriptor. [S11]

When a DACL is written, the documented authorization requires explicit
`RIGHT_WRITE_DAC` or the qualifying owner rights. Owner/group writes use
different rights, SACL writes require `SE_SECURITY_PRIVILEGE`, and invalid owner
choices can cause `unwillingToPerform / ERROR_INVALID_OWNER`. Thus a descriptor
write failure is not intrinsically a conflict result. [S12]

Stored SDs retain explicit ACEs, derive inherited ACEs from the parent, and may
have ACE ordering and other SD fields standardized. A NULL owner and a NULL
DACL are disallowed. These are descriptor-state requirements; they do not
identify which change in a failed two-change Modify was rejected. [S13]

For SD updates, only explicit ACEs supplied by the client are authoritative;
the DC computes inherited ACEs and ensures parent consistency at commit.
Descendant propagation can occur outside that transaction. A successful write
therefore does not promise byte-identical readback or simultaneous descendant
updates. [S14]

### Permissive modify has two different implications

`LDAP_SERVER_PERMISSIVE_MODIFY_OID` (`1.2.840.113556.1.4.1413`) changes ordinary
Modify behavior: adding an already-contained value can succeed without a
modification, and deleting a missing value can succeed. Its `controlValue` is
omitted. The text expressly describes the already-contained value case; it does
not specify NTSD-specific ADD processing or the timing of single-value
validation before a following REPLACE. [S15]

`dSHeuristics` character 5, `fLDAPUsePermMod`, can make all LDAP Modify operations
behave as though this control were present. Omitting the control alone does
not establish strict delete-old behavior when that heuristic is enabled. [S16]

**Inference:** permissive DELETE-old cannot supply a stale-value rejection
guard. However, that reasoning does not dispose of the opposite ADD-old shape:
duplicate ADD could be a no-op when equal, while a different second value could
fail single-valuedness. That remains conditional on NTSD operation semantics
and validation timing; it is not a documented success result. [S5] [S15]

### Assertions, bitwise filters, and transaction alternatives

RFC 4528 defines assertion control `1.3.6.1.1.12`: a filter must evaluate TRUE
as part of the same atomic update; FALSE or Undefined returns
`assertionFailed (122)`. A supporting server should advertise it in
`supportedControl`. This would supply an atomic precondition, for example on a
suitable version attribute, **if implemented and supported by the target**.
The RFC does not establish Active Directory support. [S17]

Microsoft's AD control catalog describes the controls implemented by applicable
Windows DCs and discovery through RootDSE `supportedControl`; it does not list
RFC 4528 assertion control. This catalog absence and the supplied actual
critical-control LDAP12 result support a target-specific unsupported finding,
not a fabricated assertion success or a universal future-support claim. [S18]

`LDAP_MATCHING_RULE_BIT_AND` (`1.2.840.113556.1.4.803`) and `BIT_OR`
(`1.2.840.113556.1.4.804`) are matching rules used in the filter of a SearchRequest.
They are not Modify controls. Their table supports Integer comparisons, not
SecDesc comparisons. They do not attach an atomic expected-DACL condition to
an NTSD update. [S19] [S8]

RFC 5805 describes a distinct experimental transaction mechanism using start,
transaction-specification control, and end OIDs under `1.3.6.1.1.21`.
Microsoft's documented AD extended-operation catalog does not list those OIDs;
its transaction-related operation is the AD-specific batch request. No reviewed
source establishes RFC 5805 support for the retained target. [S20] [S21]

AD's `LDAP_SERVER_BATCH_REQUEST_OID` (`1.2.840.113556.1.4.2212`) is documented for
Windows Server 2012 onward and discoverable through `supportedExtension`. [S21]
It processes encoded LDAP messages sequentially and rolls back prior changes
when an inner operation fails. Windows supports only Search, Modify, Add, and
Delete inside it; Compare is outside that set. The ten accepted inner controls
include permissive modify and SD-flags, but omit assertion and
expected-entry-count. The specification explicitly says applicable Windows
releases support no additional inner controls. An unsupported inner operation
or control causes `protocolError`. Inner failure may coexist with outer
`success`, so every returned inner result must be inspected. Batch rollback
is useful infrastructure, but it does not itself supply a version/DACL guard.
[S22]

`LDAP_SERVER_EXPECTED_ENTRY_COUNT_OID` (`1.2.840.113556.1.4.2211`) can change an
otherwise-successful Search to `constraintViolation` when the count is outside
the supplied minimum/maximum. It changes the search result code, not its data.
Combining that with batch would be attractive, but the documented batch-control
restriction above prevents claiming it as a supported Windows route. [S23]

## Assessment of the remaining concrete shapes

These are protocol assessments, not live test results or implementation
authorization.

| Shape | Assessment and unresolved evidence |
| --- | --- |
| One Modify: `DELETE(expectedOld)`, `ADD(new)`, strict modify | Ordinary-attribute guard rationale is sound. Retained NTSD LDAP53 is a failure of this whole shape; it does not identify the rejected inner change or prove all value-guard shapes unsupported. [S2] [S4] |
| One Modify: `DELETE(expectedOld)`, `REPLACE(new)`, strict modify | Distinct unresolved candidate. It retains the old-value check but uses the documented replacement semantics for the write. Need NTSD-specific evidence that DELETE is accepted, compares the intended value, and rejects stale state before replacement. The reviewed NTSD constraints do not explicitly prohibit every DELETE-plus-REPLACE request. [S2] [S4] [S13] |
| One Modify: `ADD(expectedOld)`, `REPLACE(new)`, critical permissive modify | Distinct unresolved candidate. It needs equal ADD to be harmless and different ADD to fail before REPLACE. A final single-valued result alone does not demonstrate that earlier rejection. The sources found do not establish whether Windows treats NTSD ADD as ordinary ADD, rejects it, merges/replaces it, or bypasses it in this situation. [S5] [S15] |
| Batch containing a standalone permissive ADD-old Modify and a replacement Modify | Separating the first Modify would force its final schema validation, but the NTSD ADD semantics are still unresolved. Batch rollback plus the minimum documented isolation is insufficient by itself to establish a successful no-op guard remains protected against another writer until the second update. [S3] [S22] |
| Batch Search plus replacement | Search success does not imply the expected value matched. No supported inner Compare or expected-entry-count control is documented. This is not an established CAS route. [S22] [S23] |
| Read/check then ordinary REPLACE | The precondition occurs in a different request/transaction. It does not meet the server-side conditional-write requirement. [S3] |

The DACL-only snapshot is a material additional gap for both value-guard
candidates. SD-flags `4` can omit owner/group/SACL from a read, while the stored
NTSD includes fields outside the DACL. The documented byte comparator and
section-selection semantics do not establish that such a projected snapshot is
the expected complete value, or that the control applies a matching projection
before comparison. A comparison failure with projected bytes therefore cannot
prove value-DELETE itself unsupported; a success cannot be assumed either.
[S6] [S7] [S10] [S11]

Microsoft's inspected Win2012 Modify test source uses `DirectoryAttributeOperation.Replace`
for its NTSD owner-write case. That is evidence for that replacement scenario;
it provides no qualification of either old-value guard shape. The inspected
public tests are not exhaustive protocol coverage. [S24]

## Error interpretation

The LDAP result code and the diagnostic Win32/DS status are separate evidence.
MS-ERREF gives the following numerical LDAP codes. [S25]

| LDAP result | Decimal | Meaning relevant here |
| --- | ---: | --- |
| `unavailableCriticalExtension` | 12 | A critical extension is unavailable; it is not a stale-value comparison result. |
| `noSuchAttribute` | 16 | Ordinary strict missing-value deletion can use this result, with the more specific diagnostic status below. |
| `inappropriateMatching` | 18 | Matching cannot be applied as requested. |
| `constraintViolation` | 19 | A constraint failure; not automatically a concurrency conflict. |
| `attributeOrValueExists` | 20 | Existing attribute/value conflict; not automatically the stale outcome of a proposed NTSD guard. |
| `unwillingToPerform` | 53 | Broad operation refusal; the number alone does not locate a rejected change. |

For the documented strict ordinary-attribute cases, the diagnostic values are
`ERROR_DS_ATT_VAL_ALREADY_EXISTS = 0x2083`,
`ERROR_DS_CANT_REM_MISSING_ATT_VAL = 0x2085`, and
`ERROR_DS_ATT_IS_NOT_ON_OBJ = 0x2076`.
`ERROR_DS_SINGLE_VALUE_CONSTRAINT = 0x2081` and
`ERROR_DS_ILLEGAL_MOD_OPERATION = 0x2077` are distinct statuses.
MS-ADTS specifies LDAP20/0x2081 for the particular SAM `description` case;
that special case must not be generalized into the exact stale-NTSD result.
[S26] [S4]

RFC 4528's LDAP122 means an evaluated assertion failed. It is categorically
different from the retained LDAP12 unsupported-critical-control result. [S17]

## Supplied evidence and the precise outstanding requirement

The parent supplied these existing observations; this researcher did not rerun
or independently validate them:

- Optional gMSA descriptor delete/add CAS succeeded.
- Contact NTSD matching and stale delete/add attempts returned actual LDAP53.
- Those NTSD reads and writes used critical DACL-only SD-flags `4`.
- A concurrent NTSD replacement succeeded.
- Critical RFC 4528 assertion returned actual LDAP12.

The gMSA result does not establish NTSD's special write behavior. The NTSD53
result does not identify DELETE versus ADD as the rejected step, and does not
cover DELETE-plus-REPLACE or ADD-plus-REPLACE. These are limits of the supplied
evidence, not new claims about a server.

The exact remaining protocol evidence is: (1) which NTSD change types Windows
accepts on an already-present value; (2) whether SD-flags affects old-value
comparison or only SD section read/write processing; (3) whether permissive
ADD-old preserves a differing-value failure before a later REPLACE; and
(4) the exact LDAP and diagnostic results, unchanged state on rejection, and
concurrent-writer preservation for any route eventually selected. Until that
is established, the supported atomic route remains unqualified. An
unconditional write or an always-unsupported implementation does not satisfy
the original requirement.

## Primary sources

[S1]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a
[S2]: https://www.rfc-editor.org/rfc/rfc4511.html#section-4.6
[S3]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1b6bc13c-fd9e-4168-a721-f9d7a0150a8c
[S4]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/76df255d-dc67-4c1f-adc6-1e5b60021304
[S5]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/b4a3c9be-5388-4e0d-9f5e-96d21a801a3f
[S6]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5dcca0b6-169c-4f21-9392-8974ae5e4e1d
[S7]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b99c5ac7-7eec-4232-8048-3d39b761c055
[S8]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad58bcc9-1ce3-4b4c-98b2-a79b62a39259
[S9]: https://www.rfc-editor.org/rfc/rfc4512.html#section-2.2
[S10]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0
[S11]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499
[S12]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7afacb02-548b-4e74-bf96-04b0bf0c71b6
[S13]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a
[S14]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e42f988c-72a0-4f8d-a705-7235eac175d9
[S15]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/49cdb1e3-3baa-4c7c-8cde-7c26b13d3ba7
[S16]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5
[S17]: https://www.rfc-editor.org/rfc/rfc4528.html#section-3
[S18]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
[S19]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5
[S20]: https://www.rfc-editor.org/rfc/rfc5805.html#section-2
[S21]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/962a5f25-f541-48a6-b73c-da01f1b7fc69
[S22]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ee97400e-e551-4b4a-9a60-998e89493b3c
[S23]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6af5b6e1-2545-497a-a924-d82fbb6f5260
[S24]: https://github.com/microsoft/WindowsProtocolTestSuites/blob/main/TestSuites/ADFamily/src/TestSuite/MS-ADTS-LDAP/Win2012/TestScenarioModifyAD_DSWin2012.cs
[S25]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/a465ae57-5f89-4539-88b3-90cf37a5ae06
[S26]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
