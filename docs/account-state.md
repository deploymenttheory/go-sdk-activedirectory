# Account expiration and state searches

`AccountExpiration`, `SetAccountExpiration` and `ClearAccountExpiration` reuse
the shared account identity/class checks and native writer. They support users,
computers and applicable service-account subclasses, plus AD LDS user,
inetOrgPerson and returned msDS-BindableObject classes. Groups and unrelated
objects fail before mutation. DN/GUID identities work on both directory types;
SID and literal unqualified SAM identities require AD DS. No runtime PowerShell
or RSAT is used.

```go
identity, err := ad.IdentityByAccountName("fixture-user")
// Check err before using identity.
at, err := time.Parse(time.RFC3339Nano, "2027-01-02T12:00:00.1234567+01:00")
result, err := client.SetAccountExpiration(ctx, ad.SetAccountExpirationRequest{
    Identity: identity, At: at,
})
// Inspect err and result.Mutation.State, including on failure.
```

`At` is an absolute instant, converted to UTC FILETIME at exact 100ns precision.
Sub-100ns values, times outside the finite FILETIME range and the 1601 epoch
(the zero sentinel) are rejected. There is no date-string parsing, local-time
guessing or implicit end-of-day adjustment. Relative expiration is an explicit
caller calculation such as `At: reference.Add(24*time.Hour)`.

Reads preserve the original `FileTime` and recognize both zero and MaxInt64 as
never-expire. `ExpiresAt` is populated only for a finite timestamp. Missing or
hidden `accountExpires` leaves typed fields nil; it does not mean never-expire.
The raw object's attribute state remains available.

Clearing writes `9223372036854775807`, matching the installed ActiveDirectory
module's AccountExpirationDate clear converter. It does not delete the attribute
or write -1. Both never-expire representations remain valid on reads. The focused
offline comparison records module 1.0.1.0, assembly file 10.0.26100.7920, its hash,
host/PowerShell versions and four conversion cases in
`testdata/account-expiration-reference.json`. It invokes only an in-memory
converter, never a directory command. Generic schema documentation also describes
zero as a reset-to-never representation; the SDK preserves this distinction.

Set and clear issue one Modify against the resolved GUID and support the shared
`Options.ExpectedVersion` assertion control. Native errors, accepted/rejected/
uncertain states and failed readback remain distinct. Exact returned values must
verify the write. No failed or uncertain operation is retried or rolled back.

`SearchAccountState` selects one condition and an explicit LDAP scope. Its
`Search` field reuses raw/typed filters, properties and paging. The class filter
is always combined with the caller filter. Zero scope means Base, as with
`Search`; set `ScopeSubtree` for a domain/OU subtree. Empty Base chooses the
configured partition or server default naming context. AD DS global catalog
ports are rejected because account-state attributes may be unavailable there.

```go
observed, err := client.SearchAccountState(ctx, ad.AccountStateQuery{
    Condition: ad.AccountLockedOut,
    Kind: ad.AccountStateUsers,
    Search: ad.SearchOptions{
        Base: "OU=People,DC=example,DC=test", Scope: ad.ScopeSubtree,
        PageSize: 256, ResultLimit: 100,
    },
    ScanLimit: 20000,
})
// Inspect err, observed.Complete, both limit flags, and observed.Unknown.
```

| Condition | Evaluation | Required time fields |
| --- | --- | --- |
| AccountDisabled | stored UAC disable bit, or LDS disabled boolean | none |
| AccountPasswordNeverExpires | stored UAC bit, or LDS never-expire boolean | none |
| AccountLockedOut | DS computed lockout bit / LDS ms-DS-UserAccountAutoLocked | none |
| AccountPasswordExpired | DS computed password-expiry bit / LDS msDS-UserPasswordExpired | none |
| AccountExpired | finite accountExpires < AsOf | AsOf |
| AccountExpiring | AsOf <= finite accountExpires < Boundary | AsOf, Boundary |
| AccountInactive | directory NOT(lastLogonTimestamp >= effective cutoff) | Boundary |

Unused time fields, an inverted expiring window and invalid condition/kind values
are errors. Time-based comparisons use the explicit instants, including equal
boundaries as shown. Current computed state is observed on the chosen server;
the API does not reconstruct historical lockout or password policy state.

`AccountStateAll` includes supported account classes. `AccountStateUsers` excludes
computer subclasses; `AccountStateComputers` includes computers and their account
subclasses, including applicable managed service accounts. The result retains
raw `Object` values instead of inventing a competing user/computer model.

Computed conditions are evaluated locally after a class/caller-filter candidate
search. Constructed `msDS-User-Account-Control-Computed` and the LDS booleans are never
submitted as an LDAP predicate, and stale `lockoutTime` or stored UAC expiry bits
cannot stand in for computed state. A broad candidate scan also makes hidden or
malformed state observable rather than silently excluding it. Narrow the search
with an explicit Base, scope and additional caller filter when appropriate.

`ScanLimit` defaults to 10,000 evaluated candidates. `Search.ResultLimit` limits
confirmed matches independently; zero has no match limit. The page size is
narrowed to the remaining scan budget. `Scanned` counts evaluated candidates;
`Observation.Objects` preserves every received row, including an unevaluated
tail of the final page after a match limit. The cursor releases its page cookie
when stopping early. A limit flag means retrieval stopped at the requested bound,
not that more matches are known to exist. No incomplete collection is marked
complete. Native errors retain partial matches and raw observations.

`Unknown` identifies candidates whose class/state could not be evaluated. The
scan continues so other matches survive, then returns `ErrAccountStateUnreadable`
and `Complete=false`. `Observation.Complete` may still indicate that the LDAP
candidate search finished. Inactivity is a deliberate exception: the server's
negative comparison includes absent and zero timestamps. An absent projected
timestamp preserves the server predicate's selection, without claiming the
account never logged on. Complete results are limited to objects
visible to the caller and are not a transaction across multiple pages.

Inactivity follows the inspected module criterion: subtract the default domain's
`msDS-LogonTimeSyncInterval` from `Boundary`, then search with
`(!(lastLogonTimestamp>=cutoff))`. An omitted interval uses the module's 15-day
default; AD LDS also uses 15 days. `Inactivity` retains the effective cutoff,
interval, default indicator and raw domain read. Omission can mean hidden rather
than unset, so `Defaulted` makes that assumption explicit. Malformed or rejected
interval reads stop before the account scan, retaining partial observations.
The calculation uses UTC days to avoid implicit local timezone/DST changes.
`Boundary` corresponds to the module's explicit `DateTime`, not the already
adjusted LDAP cutoff. Supply a caller-computed boundary for relative windows;
the SDK does not silently choose the current time or default expiring window.

`lastLogonTimestamp` remains an approximate replicated activity signal. The SDK
does not query each DC's nonreplicated lastLogon or infer activity from pwdLastSet
or creation time. Offline inspection verified the module's comparison operators,
default/adjustment logic, null selection and LDS attribute mappings; it does not
replace live differential qualification across directory versions and ACLs.
AD DS inactivity requires domain functional level 2003 or later; an explicitly
returned older level is rejected before scanning. If the server omits the level,
that prerequisite still applies and cannot be verified from the response.

The reference JSON also records actual AD/ADAM factory mappings and hashes of
the inspected `SearchADAccount` method bodies. In the pinned assembly,
`SearchADAccountBeginCSRoutine` constructs the expiring upper/lower comparisons
at IL offsets 748/809, the expired comparison at 888, and the negated inactivity
comparison at 1131–1155 (`Ge=2`). `GetInactiveTimeSpanDays` reads
`msDS-LogonTimeSyncInterval` with a 15-day fallback. These are offline inspection
findings, not executed directory searches or claims about every module version.

Local tests cover sentinel/timezone/precision boundaries, class guards, conflicts,
unknown state, independent limits, raw partial results and uncertain writes.
Actual WinLDAP loopback tests verify expiration Modify bytes, candidate paging,
computed-state postfiltering, cookie release, permission failures and all seven
native ownership counters returning to zero. The offline converter fixture
compares expiration values only. Server 2016/2019/2022/2025 and applicable AD LDS
search/mutation differential qualification remains open; no live results are
claimed. `examples/accountstate` defaults to read-only observation and requires
`-apply` for an explicit set or clear.

References: [Set-ADAccountExpiration](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountexpiration?view=windowsserver2025-ps),
[Clear-ADAccountExpiration](https://learn.microsoft.com/en-us/powershell/module/activedirectory/clear-adaccountexpiration?view=windowsserver2025-ps),
[Search-ADAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/search-adaccount?view=windowsserver2025-ps),
[accountExpires syntax and sentinels](https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires),
[computed state](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b80798ae-1f8c-4d30-9d80-a1f3281e96e2),
[lastLogonTimestamp update behavior](https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp),
[replication interval syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/1516361f-e412-46af-bcdb-caacf27158bd),
[LDS lockout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3eb9110a-bd0f-4510-9689-92b03c5e44e0),
[LDS password expiry](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ccec6986-5af3-4d0b-b3cd-e6d4d7c485b5).
