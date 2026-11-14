# Authentication and permissions qualification

Run `authentication-20261114T054810Z` passed on 2026-11-14 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result. This is the
evidence behind `authentication-and-permissions` for all thirteen operations in
the sweep table.

| Property | Observed value |
| --- | --- |
| Endpoint | `ADSDK25DC1.ad.sdk.test` |
| Test host | `ADSDK25MEM`, windows/amd64 |
| AD module | 1.0.1.0 |
| Go toolchain | go1.26.5 |

## The fixture

`scripts/lab/reference-authentication.ps1` creates one organizational unit and
one ordinary user in the owned disposable domain, both carrying the run's
marker, and removes them again. It is the only collector in the reference batch
that mutates the directory, so the driver gates it behind
`-AllowAuthenticationFixture` and the script itself refuses without
`-AllowWrites`.

The account name carries non-ASCII text and the password carries non-ASCII and
supplementary Unicode, so the native identity path is exercised rather than
assumed. The secret reaches the test process through a private pipe only: no
command argument, environment variable, transcript, or credential file is
created, and the buffer is cleared afterwards. `collector-run.json` records the
creation and the **proved** removal — absence is confirmed by catching
`ADIdentityNotFoundException`, not inferred from the delete returning.

## What passed

All thirteen operations read under **both** identity modes, each on its own
session, each leaving every native allocation counter at zero.

| Half | Observation | Result |
| --- | --- | --- |
| success | current Windows identity | 13/13 read |
| success | explicit Negotiate, ordinary account | 13/13 read |
| **failure** | simple authentication over plaintext | refused **before any bind**: `simple authentication requires TLS` |
| **failure** | wrong password | refused at the bind, LDAP status **49**, server diagnostic retained |
| **failure** | ordinary identity creating an object | refused, LDAP status **50**, native status surviving as the error |
| both | signing and sealing | both still enabled on the explicit session |
| both | credential containment | absent from the credential's rendering, from every diagnostic, and from this artifact |

Simple authentication is this SDK's insecure-Basic equivalent. It is rejected by
configuration validation, so no endpoint is contacted at all — which is stronger
than refusing after a connection.

The denial had to come from a **write**. An LDAP search omits objects the bound
identity cannot read rather than failing, so no read can demonstrate that an
access-denied status survives. The probe therefore attempts to create a
container inside the fixture's own organizational unit; anything it managed to
create would be inside that unit, which the collector removes recursively. An
earlier run of this qualification used a deleted-objects read instead and
recorded `attribute is not present and complete` — a *capability* refusal,
because the recycle bin is not enabled here, not a permission one. That reading
is kept in the artifact as `deleted_objects_detail` and belongs to capability
errors rather than to this scenario.

Secret containment is asserted **before** the artifact is written: the encoded
artifact is searched for the password bytes and the write is abandoned if they
appear.

## What this is not

The artifact records `full_ticket_complete: false`. Thirteen
`authentication-and-permissions` scenarios advance; nothing else does. The
per-operation half shows each operation reading correctly under both identity
modes, and the session half shows the authentication contract. Not covered
here: a documented TLS or StartTLS option under explicit credentials, delegation,
and per-operation denial for operations whose own objects an ordinary identity
cannot read.
