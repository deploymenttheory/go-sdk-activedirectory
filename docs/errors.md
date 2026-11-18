# Errors and classification

This package exports over 170 error sentinels. Each names one precise
condition, and that precision is deliberate: a caller reporting a failure
should be able to say exactly what the directory refused.

A caller *acting* on a failure needs far fewer answers than there are
sentinels. `Classify` supplies them.

```go
switch activedirectory.Classify(err) {
case activedirectory.ClassUncertain:
    // A write was attempted and its outcome is unknown. Do not record the
    // change as applied or as absent, and do not repeat it without re-reading.
case activedirectory.ClassNotFound:
    // No object matched. A tracked object is gone.
case activedirectory.ClassDenied:
    // The bound identity is not permitted. No retry succeeds.
...
}
```

Equivalently, one predicate per class: `IsUncertain`, `IsDenied`,
`IsConflict`, `IsAlreadyExists`, `IsNotFound`, `IsUnsupported`,
`IsInvalidRequest`, `IsTransport`, `IsIncomplete`, `IsUnverified`.

```powershell
go run ./examples/errorclassification
```

The example runs no directory operation. It classifies constructed errors,
including joined ones, so the precedence rules below can be read as output.

## The classes

A class answers "what may I do next", not "what went wrong". Two errors from
unrelated areas share a class when they permit the same next action.

| Class | Means | The caller's move |
| --- | --- | --- |
| `ClassUncertain` | A write was attempted; its outcome is unknown or only partly known | Re-read the target. Record neither applied nor absent |
| `ClassDenied` | The bound identity is not permitted | Stop. The remedy is outside the program |
| `ClassConflict` | The request was valid and permitted; observed state was not what it required | Re-read and retry. Nothing was written |
| `ClassAlreadyExists` | The object asked for already exists | Adopt it, or fail deliberately |
| `ClassNotFound` | No object matched | Treat the object as absent |
| `ClassUnsupported` | This platform, endpoint or directory type cannot do it at all | Stop. No credential changes this |
| `ClassInvalidRequest` | Malformed, inconsistent, out of range, or an object of the wrong class | Correct the call. Nothing was written |
| `ClassTransport` | The session or connection failed, or the client is closed | Retry a read on a new session |
| `ClassIncomplete` | A read returned less than was asked for | Use what came back; do not treat its gaps as absence |
| `ClassUnverified` | A write was accepted; no read could prove its effect | Record it as applied, but do not claim it was confirmed |
| `ClassUnclassified` | nil, or an error this package did not produce | Treat as a failure you do not understand |

`ClassUnclassified` never asserts that a condition is benign. It is the zero
value and the honest answer for a foreign error.

## Precedence

Errors here are joined freely, so one error commonly carries several classes.
`Classify` returns the most dominant present. The order is by the consequence
of acting on the wrong one, not by specificity:

```
Uncertain > Denied > Conflict > Unverified > AlreadyExists > NotFound >
Unsupported > InvalidRequest > Transport > Incomplete
```

Three of those orderings carry real weight and are pinned by their own tests.

**`ClassUncertain` dominates everything.** Every other class tells a caller
that the directory's state is known. Acting on that belief after a write whose
outcome is not known is the one mistake this package cannot help a caller
recover from, so no other class may mask it.

**`ClassDenied` outranks `ClassNotFound`.** An Active Directory search
silently omits objects the bound identity cannot read, so a permissions
failure can present as an absence. A caller that treats absence as deletion
would discard state over a permissions change. Being wrong in this direction
costs nothing: a genuinely absent object reports not-found with no denial
joined to it.

**`ClassDenied` outranks `ClassConflict`**, so a caller does not retry in a
loop something no retry will be permitted to do.

**`ClassUnverified` sits below those three and above the rest.** Each of
uncertain, denied and conflict says the directory may not hold the change,
while unverified says it does and only the proof is missing — so none of them
may be masked by it. Above the rest, because "a write landed" is the more
important fact to carry.

## Directory type versus backend support

Check `errors.Is(err, activedirectory.ErrUnsupportedDirectory)` to distinguish a
directory-type prerequisite failure from an unavailable backend operation.
Typed prerequisites return `DirectoryCapabilityError`, which carries the
operation, required directory type and actual advertised type. A required type
of `DirectoryUnknown` means either AD DS or AD LDS is acceptable; an unrecognized
server still fails closed.

For compatibility, these typed errors also match the older, broader
`ErrUnsupported` sentinel. Check the precise directory sentinel first:

```go
switch {
case errors.Is(err, activedirectory.ErrUnsupportedDirectory):
    // Select a directory type that provides the operation.
case errors.Is(err, activedirectory.ErrBackendUnavailable):
    // The explicitly selected backend or host mechanism is unavailable.
case errors.Is(err, activedirectory.ErrUnsupported):
    // Inspect backend/operation support. This alone does not identify the OS.
}
```

The user-property sentinel `users.ErrUserCapability` remains available for
property-specific refusals and is retained alongside a typed directory refusal
where both apply. `Classify` continues to return `ClassUnsupported`; use
`errors.Is` and `errors.As` when the distinction determines the caller's remedy.

`BackendUnavailableError` carries the selected backend, authentication method
and refused feature. It matches the precise `ErrBackendUnavailable` and legacy
`ErrUnsupported`, but not `ErrUnsupportedDirectory`. Choosing a backend does not
permit another backend or authentication mechanism to be tried silently.

## Multi-step writes

Some operations are several object writes: creating a site writes the site, its
NTDS Site Settings and its containers; creating a user may write the object,
then a password, then an enablement. Each stage's `ObjectMutationResult` is
retained, but a caller should not have to walk them to learn whether anything
landed.

So when such an operation stops after at least one stage was accepted, the
returned error joins a stage-incomplete sentinel — `ErrUserCreationIncomplete`,
`ErrComputerCreationIncomplete`, `ErrServiceAccountCreationIncomplete`,
`ErrServiceAccountMigrationPartial`, `ErrReplicationTopologyIncomplete`,
`memberships.ErrPrincipalMembershipIncomplete` — all of
which classify as `ClassUncertain`. One check covers the whole mutation
surface:

```go
if activedirectory.IsUncertain(err) {
    // Part of this may be in the directory. Re-read before recording state,
    // and before repeating the call.
}
```

The distinction that matters is against `ClassDenied` and `ClassInvalidRequest`,
which a caller may treat as "nothing happened". A third write refused with
status 50 is a denial, but if two writes were already accepted it is *also* a
partial change, and the uncertain class wins — which is what the precedence
order above is for. These sentinels are absent when nothing was accepted, so a
wholly refused call still classifies as the refusal it was.

## Server status codes

`Classify` also reads `LDAPError.Code`, so a refusal gets the same class
whether it arrived as a sentinel or as a bare server status — status 50
becomes `ClassDenied`, 32 becomes `ClassNotFound`, 68 becomes
`ClassAlreadyExists`.

Attribute-level codes are included — 16, 17 and 20 — because the first live
mutation run reported all three as unclassified. An undefined attribute and a
value that already exists are both failures whose remedy is in the request. 20
is also what AD DS returns for a single-value constraint violation, and it is
deliberately **not** `ClassAlreadyExists`: that class is about an object a
caller could adopt, not a duplicate attribute value.

The table is still deliberately partial. A code it does not name contributes no
class rather than a guessed one, and any sentinel joined alongside decides.
A status and a sentinel that disagree resolve through the same precedence as
two sentinels.

## A permission problem is not always `ClassDenied`

Active Directory does not always report an authorisation failure as access
denied. Measured on an isolated lab: an identity with no rights on a container
is refused with LDAP status 50 for every mutating operation except a computer
creation, which comes back as a constraint violation, status 19, and therefore
as `ClassInvalidRequest`.

So `IsDenied` is not a complete test for "the caller lacks permission". It is
correct for what it reports and it is the right control-flow signal, but a
caller diagnosing *why* a computer creation failed has to read the sentinel and
the LDAP status as well. This SDK deliberately does not relabel status 19:
it genuinely also means a real constraint violation, and guessing between the
two would make the classification less trustworthy, not more.

## The sentinels are unaffected

Classification is additive. Nothing about the sentinels changed, and
`errors.Is` against one remains the right tool for everything a class
deliberately discards:

```go
if errors.Is(err, activedirectory.ErrSearchReferences) {
    // Not merely incomplete: the server named a subordinate naming context
    // it did not search. A caller asking a narrower question may accept it.
}
```

`Classify` answers "what may I do next". `errors.Is` answers "what exactly
happened". Most callers want the first for control flow and the second for the
message they show.

## Exhaustiveness

Every sentinel this package exports is classified, and that is enforced rather
than asserted. `TestEverySentinelIsClassified` parses this package's own
source, collects every package-level `Err…` variable, and fails if one is not
in the classification table — and fails in the other direction too, if the
table names something that is no longer a sentinel.

That test is the point of the layer. Grouping by name alone would leave a
sentinel added later silently unclassified, and a caller that used to act
correctly on that condition would quietly stop. The suffix families
(`Err…Uncertain`, `Err…Permission`, `Err…Readback`) read like a contract and
are not one.

## Error types

Nine error types carry structure beyond a sentinel. All of them unwrap, so
`Classify` and `errors.Is` see through them.

| Type | Carries | Unwraps to |
| --- | --- | --- |
| `LDAPError` | `Operation`, `Code`, `Diagnostic`, `MatchedDN` | nothing; read by `Classify` directly |
| `DirectoryCapabilityError` | `Operation`, `Required`, `Actual` directory type | `ErrUnsupportedDirectory` |
| `SearchError` | `Returned` object count | `ErrIncompleteResult` and the cause |
| `DirectoryReadError` | `Operation` | `ErrIncompleteResult` and the cause |
| `ReplicationReadError` | per-server read context | `ErrIncompleteResult` and the cause |
| `ADFilterError` | filter position and property | the cause |
| `AccountCreationParentError` | the container that was unavailable | its joined causes |
| `ServiceAccountPrincipalError` | the principal that failed to resolve | the cause |
| `LocalServiceAccountNativeError` | `Operation`, NTSTATUS | classifies itself: two NTSTATUS values report as `ErrServiceAccountLocalPermission` |

`LDAPError.Error` deliberately omits `Diagnostic` and `MatchedDN`, so ordinary
error logging does not disclose server diagnostics. Read them explicitly
through `errors.As` when they are wanted.

`SearchError.Returned` is worth reading on an incomplete search: it is how
many objects did arrive, and a non-zero count with
[`ErrSearchReferences`](search.md) means the objects are real and one
subordinate partition went unsearched.

## Accepted writes and verification

The LDAP acknowledgment and subsequent verification are separate facts.
An accepted mutation keeps its state, GUID and observations when a readback
fails. Verification starts with exact bytes. The error distinguishes missing
proof from a contradicted or incomplete observation:

- `ErrObjectUnverifiable` classifies as `ClassUnverified`: the write was
  accepted but this observation cannot prove its effect. An omitted cleared
  attribute can mean either removal or denied visibility. A schema-proven DN
  representation change also cannot meet an exact-byte guarantee.
- `ErrObjectVerification` classifies as `ClassUncertain`: the readback
  contradicted the request, so the directory may not hold what was asked for.

For example, writing `cn=user,dc=example` into `manager` and observing
`CN=user,dc=example` reports `ClassUnverified` when a complete, unique schema
row proves that `manager` uses the Object(DS-DN) syntax. The request and returned
bytes remain unchanged. The same text difference in an ordinary string remains
`ClassUncertain`; the SDK never guesses an attribute's syntax from its contents.
DN value-case differences need the naming attribute's matching rule and are
not assumed equivalent. Failed schema reads preserve their causes and the
accepted mutation without manufacturing normalization evidence.

Removing a DN value while its schema-proven equivalent remains is a
contradiction. A strict remove/add pair in the same Modify may intentionally
re-add that value through another representation; that final presence remains
unverified rather than being mistaken for a failed removal.

Two consequences worth planning around:

- **Prefer a DN the directory gave you.** `TargetDN` on a creation result is
  the directory's own `distinguishedName` once the readback has been verified,
  so it can be stored and written back unchanged. A DN assembled by hand, or
  taken from somewhere that spells attribute types differently, may require a
  schema observation and remain unverified after an accepted write.
- **A base-scoped search echoes the name the request supplied** as the entry
  name. `Object.DistinguishedName` from such a read is therefore the requested
  spelling, not necessarily the directory's; the `distinguishedName` attribute
  is the authoritative one. Compare DNs through their parsed form rather than
  byte-wise wherever the comparison matters.

Measured in `coverage/lab/server2025/account-values/`.

`AbsentAfter` records an empty ordinary live-object search; it does not prove
deletion. Verification requires a separate critical ShowDeleted or ShowRecycled
search returning the original GUID with explicit `isDeleted=TRUE` in the original
naming context. `DeletionReadback` retains that raw result, including partial
rows and completion. Missing controls, permissions or visibility leave an
accepted deletion unverified; refused, malformed or interrupted reads retain
their errors. No write or refused visibility control is retried automatically.

See [mutation reconciliation](mutation-reconciliation.md) for aggregate results,
the evidence boundary and safe next steps.
