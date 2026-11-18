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
