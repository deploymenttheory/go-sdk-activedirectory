# Write authentication and permissions qualification

Run `writeauth-20261116T205659Z` passed on 2026-11-16 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result.

Advances **15 scenario states**. This was the last of the four provider-facing
gaps: a denied *write* is something a caller meets constantly, and nothing had
observed one.

## The design

One ordinary identity and two containers:

| Container | The identity's rights |
| --- | --- |
| `OU=Delegated,OU=ADSDK-WriteAuth-…` | full control, granted by the collector |
| `OU=Denied,OU=ADSDK-WriteAuth-…` | none |

The endpoint, the session, the explicit Negotiate credentials and the request
are **identical** across both halves. The only difference is the access check,
so whatever the directory returns in the denied container is caused by it.

The identity's account name carries non-ASCII text and its password carries
non-ASCII and supplementary Unicode. No secret reaches a command line, an
environment variable or a file: the credential arrives on the test process's
standard input and is cleared after use.

The subjects in the denied container are placed there by the collector's own
identity, so the delegated identity can **read** them and must not be able to
change them — otherwise the observation would be about visibility rather than
about the write access check.

## What passed

**Success.** Every operation succeeded under those explicit credentials inside
the delegated container. That establishes the SDK carries an explicit identity
into a *write*, not only into a read.

**Failure.** The same operation, same session, same credentials, against a
subject in the denied container was refused and wrote nothing — proved by the
target's `uSNChanged` being unchanged with the object still present, and for a
create by the delegated create of the same relative name succeeding.

## One refusal is not a denial, and that is Active Directory's doing

```
denied           LDAP  50   x14
invalid-request  LDAP  19   x1     <- New-ADComputer
```

`New-ADComputer` in the denied container is refused with a **constraint
violation**, not access denied. That is Active Directory's own behaviour for an
under-privileged computer creation, not anything this SDK chooses, and
relabelling it would mean the SDK guessing at a status that genuinely also
means a real constraint violation.

**The consequence is worth stating plainly: a caller cannot rely on a `denied`
classification alone to detect a permission problem on computer creation.**

The qualification therefore accepts any classification the directory produced —
the design already makes the permission the only variable — but **requires the
refusal to carry an LDAP status**. A refusal with none would have been produced
by this SDK before reaching the access check, which would mean the check was
never exercised at all. That is the discriminator that keeps the looser rule
honest.

## What this is not

`full_ticket_complete` is `false` in both artifacts, and **no variant state
advances.**

**`Rename-ADObject` is not covered.** This harness sweeps create, update and
delete per class, so 15 of the 16 mutating operations are claimed.

The scenario's other documented cases are not covered here: invalid
credentials, and any documented Basic/TLS option. Those are qualified on the
read surface, where the bind is the subject; this run is about what an
authenticated-but-unauthorised identity can and cannot write.

The delegation is a single access rule on one organizational unit inside the
owned disposable lab domain, removed with the fixture root. Nothing outside the
fixture root is modified, and `collector-run.json` records the removal as
proved rather than assumed.
