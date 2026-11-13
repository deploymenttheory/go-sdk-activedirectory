# Domain and forest settings

`Client.UpdateDomain` changes the connected DC's domain NC root. Typed fields
cover allowed DNS suffixes, the integer last-logon replication interval in days,
`managedBy`, and smart-card-only account password rolling. The existing
`Directory().Domain` read includes these fields, including the new optional
`PublicKeyRequiredPasswordRolling` boolean. `Directory().Forest` reads UPN/SPN
suffixes and functional levels.

`Client.UpdateForest` changes `uPNSuffixes` and `msDS-SPNSuffixes` on
`CN=Partitions,<configuration NC>`. These are forest suffix settings; this call
does not change SPNs on account objects, trusts, DNS records, or routing.

Both requests use the shared `Identity` and `ObjectMutationOptions` types. Domain
identities are the domain NC root's DN or GUID. Forest mutation identities are
the Partitions container's DN or GUID; a GUID needs the configuration NC in
`Options.Partition`. No DNS/NetBIOS alias discovery, referral chasing, credential
forwarding, or alternative-server selection occurs. AD LDS, RODCs, conventional
GC endpoints, cross-domain roots, and non-root objects are rejected.

## Explicit changes

Nil fields are omitted. A non-nil suffix slice replaces the complete attribute;
an empty slice clears it. `Changes` reuses `AttributeChange` for exact add/remove,
clear, and domain raw binary/multivalue changes. One disjoint remove/add pair is
submitted remove-first in one Modify. A repeated operation, overlapping values,
or a typed/raw conflict is rejected before I/O. No permissive-modify control is
used. Omitted attributes are never reconstructed or replaced.

`LastLogonReplicationIntervalDays` preserves explicit zero, the LDAP schema's
`rangeLower=0`, and rejects values above the signed 32-bit attribute range. It
does not round a Go duration. This is the native attribute representation, not a
claim of identical PowerShell TimeSpan parameter validation. Empty `ManagedByDN`
is invalid; use an explicit `AttributeClear`. Enabling password rolling requires
an observed domain level of at least Windows Server 2016. Non-level settings
reject raw changes to functional levels, mixed mode, role ownership, optional
feature enablement, and object identity; these require dedicated operations.

## Functional-level changes

`Client.SetDomainMode` and `Client.SetForestMode` accept a
`FunctionalLevelTransitionRequest`. Levels are 0 (2000), 1 (2003 interim),
2 (2003), 3 (2008), 4 (2008 R2), 5 (2012), 6 (2012 R2), 7 (2016), and 10 (2025).
2019/2022 have no separate functional level. Unknown values are rejected.

Domain changes require the connected PDC; forest changes require the connected
Schema Master. The owner comes from the corresponding `fSMORoleOwner` attribute,
compared to this session's DSA identity. The SDK does not transfer roles or retry
against an owner. MS-ADTS 6.1.4.4 describes a Domain Naming Master requirement,
which conflicts with the write constraints in 3.1.1.5.3.4 and the current
Set-ADForestMode example. This implementation follows the latter two sources;
separate-role live qualification remains open.

The preflight retains raw observations and checks the schema's `objectVersion`,
DC behavior versions (including RODCs and domain replica declarations), domain
cross-reference levels for a forest change, mixed-mode restrictions, and visible
enabled optional-feature requirements. The connected role owner must appear in
the controller enumeration, and the forest root domain must appear in the
cross-reference enumeration. Each search is capped at 4096 rows and must finish;
partial retrieval, unreadable required values, and unknown versions stop the
write. Absent behavior versions mean level 0 under MS-ADTS; the target must also
agree with computed RootDSE functionality.
Enabled-feature backlinks use the shared optional-feature range reader, with
GUID checks across continuations, a 4096-read/1,048,576-value bound, and retained
raw responses. Metadata search does not request the ranged attribute itself.

Lowering requires `AllowLowering: true`. It does not bypass constraints. The
target cannot be below Windows Server 2008; with a 2025 DC in the affected scope
it cannot be below 2016. A domain target cannot be below the forest level.
Enabled features with higher requirements and domain smart-card password rolling
also block incompatible lowering. Lowering to the current forest level is
allowed by current rollback guidance; an older server's stricter rejection is
returned unchanged. A same-level request returns `Unchanged`, makes no write,
and preserves requested extra properties.

These are local, replicated LDAP observations, not a forest-wide health or
visibility proof. Optional requirements can be absent or hidden, permissions
remain server-authoritative, and prerequisites can change between reads and the
write. ADPrep, DC upgrades, SYSVOL/DFSR migration or health checks, replication
synchronization, mixed-to-native mode conversion, and feature disabling are not
performed. No atomicity across prerequisite objects is claimed. An optional
`ExpectedVersion` requires advertised critical RFC4528 assertion support; an
unsupported server returns `ErrObjectControlUnsupported` rather than silently
substituting a read check.
An unchanged request with `ExpectedVersion` also returns this error: no write
means no assertion was evaluated by the server.

## Results and verification

Settings return `ObjectMutationResult`. Transitions return it in `Mutation`,
alongside the current/requested levels, role owner, schema version, and raw
preflight observations. `PreflightComplete` means the documented local checks
finished. It is independent of whether the write was accepted.

Each change is one native LDAP Modify. A rejected reply, accepted reply with
cleanup failure, and uncertain dispatch remain distinct. Native LDAP status,
diagnostic, and matched DN are retained. No error triggers replay or rollback.
An accepted write is read back by GUID; `Verified` compares the requested effects
with returned values. Missing/hidden/ranged values cannot prove a clear. A
readback error retains raw candidates without promoting them to verified data.
Acceptance and a later observation are not atomic and do not prove convergence.

## Example and qualification

`go run ./examples/directorysettings -server dc.example.test` is read-only.
The example accepts an explicit operation plus `-apply` for a write and a
separate `-allow-lowering` intent. Use the appropriate role owner for a mode
change. No live directory operations were run during implementation.

Portable tests cover settings conflicts, zero/omitted values, raw binary values,
target guards, raising/lowering, mixed mode, schema/DC/domain and feature
rejections, no-op projections, partial readback, and uncertain outcomes. Windows
tests execute all four public workflows through real WinLDAP against a loopback
peer, checking the exact Modify bytes, GUID target, permission/referral replies,
single submission, and native ownership. Live AD parity, older-version rollback
boundaries, access-controlled observations, and separate-role behavior remain
unqualified; issue #28 is not accepted or complete on the strength of these tests.

## Primary references

- [Set-ADDomain](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addomain?view=windowsserver2025-ps)
  and [Set-ADForest](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adforest?view=windowsserver2025-ps).
- [BehaviorVersion update constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/feb24e8c-310c-4ff9-9303-629c7bbebbbb)
  and [current Set-ADForestMode](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adforestmode?view=windowsserver2025-ps).
- [Supported rollback prerequisites](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/lower-domain-forest-functional-levels)
  and [current functional-level compatibility](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels).
- [Schema versions](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/find-active-directory-schema),
  [DC NC declarations](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ebf2419-1169-4413-88e2-12a5ad499cf5),
  and [optional-feature requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9ae2a9ad-970c-4938-a6bf-9c1fdc0b8b3e).
- [Logon replication interval schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/1516361f-e412-46af-bcdb-caacf27158bd).
