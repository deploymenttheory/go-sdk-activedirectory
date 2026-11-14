# Identity form qualification — failed, and why

Run `identity-20261114T101654Z` on 2026-11-14 against the isolated Server 2025
two-DC/member profile. **This qualification did not pass, and no coverage state
advances.** It is retained because the failure is a finding about the SDK, not
about the harness.

## The fixtures

`scripts/lab/reference-identity.ps1` creates one organizational unit holding
three objects, and reads the controller's own computer account. Each records
only the identity forms it actually carries, so the qualification is never
handed a form the reference does not document for that object — an
organizational unit has no security identifier and no account name.

| Fixture | Forms | Distinguished name |
| --- | --- | --- |
| `unicode_user` | dn, guid, sid, account | `CN=sdk\xe9\U0001f511…` — non-ASCII plus a supplementary-plane character |
| `escaped_user` | dn, guid, sid, account | `CN=sdk\,esc\+…` — comma and plus escaped |
| `escaped_group` | dn, guid, sid, account | `CN=sdkgrp\,esc\+…` |
| `computer` | dn, guid, sid, account | the controller's own account, read not created |
| `ou` | dn, guid | the fixture container |

The collector is gated behind `-AllowWrites`, the driver behind
`-AllowFixtureCreation`, and `collector-run.json` records the fixtures' creation
and their proved removal.

## What passed

The **distinguished-name** form resolved the correct object for every operation:
`Get-ADUser`, `Get-ADGroup`, `Get-ADComputer`, `Get-ADOrganizationalUnit` and
`Get-ADObject`. Escaped commas and plus signs, non-ASCII text and a
supplementary-plane character all round-tripped. Both refusals held everywhere:
a wrong object class was rejected with a class-specific error, and a
syntactically valid identity naming nothing was refused without selecting an
arbitrary object. No operation leaked a native allocation.

## What failed, and the cause

**Every non-DN form failed, for every operation:**

```
LDAP search incomplete after 1 objects: LDAP result requires additional
retrieval: search references require explicit retrieval on another endpoint
```

Read that carefully: *after 1 objects*. The object **was found**. The search
then also returned a continuation reference, and the SDK treats any non-zero
reference count as making the whole result incomplete
(`native_search_windows.go:213-219`), so the resolved object is withheld.

A distinguished name is a direct read and needs no search, which is why it is
the only form that works. `ResolveIdentityOptions` documents the rest:

> Partition overrides Config.Partition. If both are empty, a DN selects its
> longest advertised NC; other forms use defaultNamingContext.

So a GUID, SID or account name is searched for across the **default naming
context** — whose subordinate naming contexts are, in this domain and in every
Active Directory domain, `cn=configuration`, `dc=domaindnszones` and
`dc=forestdnszones`. A subtree search of the domain root therefore always
returns continuation references, so non-DN identity resolution always reports
an incomplete result.

### There is no caller-side workaround

Narrowing `Partition` to the object's own container was tried and is refused
with `identity is outside the selected naming context`: `Partition` must name a
naming context, not an arbitrary container. The one case where the narrowed
value *was* a naming context — the organizational unit, whose parent is the
domain root — still failed on its GUID form with the same reference error.

No option in `SearchOptions`, `ResolveIdentityOptions` or `Config` tolerates
references. `LDAP_OPT_REFERRALS` is deliberately off so that WinLDAP never
silently contacts another endpoint, which is right; the defect is that the SDK
additionally refuses a result when the server merely *mentions* a subordinate
naming context it was never going to follow.

### The same cause affects collection reads

`coverage/lab/server2025/directory/query-sweep-result.json` shows the related
case: a subtree read of the domain root reported `incomplete after 3 objects`
and `after 51 objects` for `Get-ADUser` and `Get-ADGroup`. The query sweep works
around it by reading the Users container, which has no subordinate context
beneath it. Identity resolution cannot work around it, because the caller does
not choose the base.

## Separately observed

`Get-ADObject` reports `identity form is not supported for this` for the SID and
account-name forms. The generic object read accepts a DN or a GUID only, which
is consistent with the reference accepting a distinguished name or GUID for
`-Identity`. That is a documented narrowing, not part of the failure above.
