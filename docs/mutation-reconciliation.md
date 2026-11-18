# Mutation results and reconciliation

Inspect the result even when an operation returns an error. A server can accept
the mutation and then refuse its readback, or a later independent stage can
fail. The result keeps those effects instead of describing the whole operation
as if nothing happened.

| State | Observation | Next step |
| --- | --- | --- |
| `ObjectWriteNotAttempted` | The operation did not submit a mutation | Fix the preflight condition or cancellation |
| `ObjectWriteRejected` | A valid server refusal was received | Inspect the original status and target |
| `ObjectWriteAccepted` | A valid server acknowledgment was received | Inspect verification and partial effects |
| `ObjectWriteUncertain` | Submission may have occurred without a trustworthy acknowledgment | Reconcile on a new explicitly authenticated connection |

`Verified` is an additional statement about the observed effect. `ReadbackComplete`
describes a read, not effective permissions. Missing or ranged attributes never
establish their absence. An accepted clear can therefore return
`ErrObjectUnverifiable`; a visible value that contradicts the request returns
`ErrObjectVerification`. An accepted mutation followed by a failed read retains
`ErrObjectReadback` and its original LDAP, decoder, transport or cancellation cause.

## Directory-normalized values

The shared verifier uses exact values first. For a byte-different DN spelling,
it reads the exact attribute's schema from the advertised schema naming context.
Only a complete, unique row with the Object(DS-DN) syntax triple permits
representational comparison. Attribute-name case, equivalent escapes and AVA
ordering can differ; decoded AVA values must still match exactly. The comparison
does not infer equality matching rules, arbitrary value-case equivalence or
attribute OID aliases. Normalized effects stay `Verified=false` and
`ClassUnverified`; raw requests and returned attributes remain available.

A still-present equivalent DS-DN contradicts a removal unless the same atomic
Modify deliberately re-adds it. DN-looking ordinary text receives no special
treatment. A missing, malformed, refused or partial schema observation cannot
prove equivalence and cannot erase an accepted write.

## Independent stages

`ReplicationSiteMutationResult.Mutation` and
`PrincipalGroupMembershipMutationResult.Mutation` summarize sequences that are
not atomic. Their precedence is uncertain, then accepted, then rejected, then
not attempted. `PartialEffectsPossible` preserves incomplete sequences that had
accepted or unknown effects. Each site's `Steps` and membership batch's
`Outcomes` retain actual identities, observations, errors and status codes.

A site aggregate anchors the resolved site-root GUID. Child settings GUIDs never
replace it. A multi-group batch has no single target GUID, DN, Before or After;
those belong to the individual group results. `Complete` and `Verified` are
separate: the existing membership readback observes group identity and does not
prove the complete linked membership edge.

A later LDAP50 denial after an accepted stage is still joined to the original
error, together with a stage-incomplete sentinel that classifies as
`ClassUncertain`. Cancellation before any write does not create partial effects.
Unknown outcomes and cancellation stop remaining group targets without replay.
Known per-group refusals remain recorded independently.

## Deletion and visibility

`AbsentAfter=true` means the ordinary post-delete GUID search found no visible
live object. ACL filtering can produce the same result while the object still
exists. This observation alone never sets `Verified`.

When advertised, the SDK selects one critical ShowRecycled control, otherwise
ShowDeleted, for a bounded search of the original naming context. It requires
the exact original GUID and explicit `isDeleted=TRUE`. `DeletionReadback` stores
the separate raw search result, including partial rows. A unique complete
same-GUID deleted observation can verify that object's deletion; it does not
prove restore eligibility or enumerate every effect of a tree delete.

A failed submitted recursive delete can have changed descendants while its root
request remains `ObjectWriteRejected`. `ErrObjectDeletionIncomplete` joins the
original server status/cause and classifies those possible partial effects as
`ClassUncertain`. Flat deletes and failures before submission retain their
ordinary refusal/cancellation contract. No synthetic LDAP status or retry is
introduced.

An empty controlled result or unavailable visibility control leaves the accepted
delete unverified. A refused, incomplete or invalid response retains its cause
and leaves verification false. The SDK never retries a refused control without
criticality, retries a mutation after an unknown response, or substitutes an
administrator's later read for the original actor's result.

## Reconcile without replay

Record the endpoint, partition, original GUID, write state, raw observations,
verification and all per-stage results before acting on the error. On a new
explicitly selected secure connection, resolve that GUID and read the properties
needed to decide the remaining work. A known LDAP acknowledgment must not be
turned into a second create, a second linked-value addition or a blind rollback.
Use a fresh observed version only when the target advertises the required
critical assertion control. A preflight read is not a concurrency guarantee.

Directory-type failures use `DirectoryCapabilityError`/`ErrUnsupportedDirectory`;
backend or authentication availability uses
`BackendUnavailableError`/`ErrBackendUnavailable`. The legacy `ErrUnsupported`
match remains broader. Neither permits an automatic backend or credential fallback.

## Validation scope

Default tests exercise the actual portable LDAP adapter over owned verified TLS
sockets: normalization/schema failures, deletion controls and raw partial proof,
accepted clears, multi-group outcomes, and multi-object site failures. Pure
directory-model tests separately exercise aggregate semantics. These fixtures
are protocol and public workflow evidence, not live AD qualification.

SDK09's Windows/Linux × Server2016/2019/2022/2025 matrix requires fresh owned lab
fixtures, actual source/binary provenance, narrow allow/deny ACLs, independent
read-only reconciliation and both-DC cleanup. Historical native-backend evidence
does not qualify this portable change. macOS has build/unit scope only. Live
qualification is pending until retained capture records identify its exact scope.

The opt-in `TestPortableMutationContractsLab` collector uses public APIs and
requires `ADSDK_MUTATION_LAB_INPUT=stdin`. Its strict 128 KiB JSON input uses the
existing policy collector shape: `credential_source` (`password` or `cache`),
`password_base64` or `cache_path`, `endpoint`, `username`, `realm`, `spn`,
`run_id`, `source_revision`, fresh `result`, and `targets` containing explicit
`role`, `dn`, `guid`. Password bytes travel only through protected process stdin;
unknown fields, mixed credential sources and reused result files are rejected.
The linker variable
`github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/acceptance.portableMutationLabBuildRevision`
must equal the actual immutable build revision supplied by the outer runner.

The ordinary input has exactly nine roles: parent, subject, manager, hidden,
group-allowed, group-denied, site, settings and delete-unverified. Six public
cases cover normalized manager values, an accepted clear, static denied
attribute readback, a partial group batch, a partial site/settings update, and
unverified deletion. A separate input and connection with exactly parent and
delete-verified performs the explicitly privileged positive deletion case.
Its observation never upgrades the ordinary actor's result. No fault wrapper,
timed permission change, ambient credential or backend fallback is installed.

[`mutation-contract-fixture.ps1`](../scripts/lab/mutation-contract-fixture.ps1)
provides functions only. Load the source-recorded descriptor fixture dependency
first. `New-MutationContractFixture(run, server, actorSID, protectedCredential)`
creates twelve owned objects and exact property grants. The actor is a separate
outer-owned enabled AES account; all fixture users remain disabled. The parent
marker, pinned GUIDs/DNs/classes and deterministic account names establish
ownership independently of descriptions that the SDK changes or clears. The
Servers and Licensing Site Settings children are recorded for cleanup but are
excluded from the collector's mutation target list.

`Remove-MutationContractFixture(run, server)` rejects unrecorded children,
replacement identities and unexpected member/management/site associations. It
uses separate GUID-targeted leaf deletions and checks both naming contexts on
both DCs. No global Deleted Objects ACL, account password, KDS key or directory
policy is changed. The outer runner owns account/credential retirement and
source/binary/controller provenance. Offline PowerShell5.1/7 guards validate
identity plans, changed-description ownership, foreign association refusal and
exact narrow ACL recipes; they perform no directory operation and do not prove
effective access. Successful setup/cleanup and every live contract case still
require independently retained results.

## Protocol sources

- [MS-ADTS LDAP representations](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa)
  defines the DS-DN syntax triple used by the schema check.
- [RFC4517 §4.2.15](https://www.rfc-editor.org/rfc/rfc4517.html#section-4.2.15)
  binds DN AVA value equality to the naming attribute's equality rule.
- [MS-ADTS ShowDeleted](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4b8f2a0e-9ea6-4be3-b639-4b019948c568)
  and [ShowRecycled](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b96e43b0-2783-4597-b7a0-f3f3f458cbf6)
  define explicit controlled deleted-object visibility.
- [Microsoft deleted-object access guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/non-administrators-view-deleted-object-container)
  explains the additional visibility rights; omission is not proof of deletion.
