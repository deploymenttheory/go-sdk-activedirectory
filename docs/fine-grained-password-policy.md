# Fine-grained password policies

The client reads, searches, creates, updates and deletes password settings objects
(PSOs), changes their explicit subjects, and reads a user's server-selected
resultant PSO. These operations require an AD DS domain with functional level
Windows Server 2008 or later, using its domain LDAP endpoint. AD LDS and GC
endpoints are rejected. The client does not route writes to another DC or forward
credentials. Server permissions, schema constraints and native errors still apply.

`FineGrainedPasswordPolicy` accepts an explicit DN or GUID. Search by name with
`FineGrainedPasswordPolicies` and the existing typed filter; raw and typed filters
are mutually exclusive. Searches stay one level beneath the connected domain's
Password Settings Container. A supplied partition must be that domain. Reads
include raw attributes and caller-selected extra properties. Missing typed fields
stay nil; missing/hidden values are not substituted with defaults.

`CreateFineGrainedPasswordPolicy` requires a name and all ten settings explicitly.
It uses one native LDAP Add. `UpdateFineGrainedPasswordPolicy` takes pointer fields:
nil preserves a setting. Selected settings, description/display name, and supported
raw attribute changes are one atomic Modify. Raw changes cannot override typed
settings or subject links. `DeleteFineGrainedPasswordPolicy` is a leaf delete;
subject accounts/groups are never deleted. Protection is not removed automatically.

`PolicyInterval` is the shared domain-policy type: a nonnegative count of 100ns
ticks, including values beyond Go's `time.Duration`. `PolicyNever` represents the
LDAP minimum signed 64-bit value. It means no expiry for maximum password age and
manual unlock for lockout duration. Setting maximum age to zero also requests no
expiry; other fields preserve zero. Duration conversion rejects overflow and
sub-100ns precision. Creation requires maximum age greater than minimum age and
lockout duration at least the observation window. An update touching one of those
pairs requires the corresponding existing value to be readable; the server checks
the final state. Precedence is positive; history is bounded at 1024 and minimum
length at 256, with any stricter server schema limit preserved as a native error.
These rules follow the [PSO add constraints](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7dfeb38c-3cb9-4215-ae1c-ef209fd251ae)
and [precedence schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/a67d542c-0069-48a4-869b-ce706cbcbb8b).

`AddFineGrainedPasswordPolicySubjects` and `RemoveFineGrainedPasswordPolicySubjects`
resolve every supplied DN/GUID/SID/account-name identity in the PSO's domain before
one strict multivalue Modify. Only normal user accounts and global security groups
are accepted. Duplicate identities are rejected; already-present additions and
missing removals retain the server's error. GUID references bind writes to the
resolved objects. No permissive-modify control, guessed name resolution, retries,
group membership expansion or subject-creation step is added. These are explicit
assignments, matching the [subject operation's scope](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adfinegrainedpasswordpolicysubject?view=windowsserver2025-ps).

`FineGrainedPasswordPolicySubjects` continues `msDS-PSOAppliesTo` ranges with a
GUID-stable target and checks the PSO's GUID/USN on every batch. Defaults bound the
read to 100,000 subjects, 1,000 ranges and 64 MiB; the context also bounds work.
Gaps, repeated ranges, changed versions, permission errors and exhausted bounds
return incomplete results with retained raw batches and resolved subjects.
`AttributeReturned` distinguishes omission from a returned empty list. `Complete`
means the requested reads and identity resolutions finished, not that ACLs exposed
every link or that the observations form a transaction. A policy's ordinary
`AppliesTo` field can be partial; use this method for continuation.

`UserResultantPasswordPolicy` reads `msDS-ResultantPSO` from the user and resolves
that PSO. It never calculates a winner using local precedence or group expansion.
`NotReturned` explicitly reports no constructed value returned; it does not prove
that the default domain policy applies when access controls hide data. A returned
PSO DN survives a failed PSO read. The server owns direct-versus-group priority,
tie-breaking and version-specific exclusions under [MS-ADTS resultant processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ad735d45-ba6a-42fc-a41c-e91ced8e72d9).
This method's `Properties` select extra PSO attributes; `User` retains the raw
account and constructed attribute observation.

Every mutation retains `ObjectMutationResult`: inspect `State`, raw preflight and
readback rows, `ReadbackComplete`, `Verified`, and the returned error. Accepted
writes remain accepted if readback or subject resolution fails. Unknown response
outcomes retire the connection and are never replayed. Subject verification needs
a complete visible link read; omission does not prove a successful last removal.
LDAP normally omits a multivalue attribute after its last value is deleted. In
that case removal returns `State=ObjectWriteAccepted`, `Verified=false` and
`ErrObjectVerification`, retaining the completed but omitted readback. This is
not a rejected write and must not trigger a retry; no reliable empty-attribute
response is assumed.
`ExpectedVersion` uses the existing critical assertion-control contract and fails
when unsupported; creation cannot assert a version of an object that does not yet
exist. Without that control, preflight/readback are observations and concurrent
edits remain possible.
Creation shares one `Config.Timeout` budget across discovery and the Add workflow.

The SDK deliberately requires explicit creation settings instead of importing
PowerShell defaults or a domain policy template. It also does not add a racy
client-side uniqueness check for precedence. The [PowerShell creation reference](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adfinegrainedpasswordpolicy?view=windowsserver2025-ps)
describes cmdlet behavior; the native server remains authoritative for SDK writes.

Run the example in read mode:

```powershell
go run ./examples/fine-grained-policy -server dc.example.test -operation list
go run ./examples/fine-grained-policy -server dc.example.test -dn 'CN=alice,OU=People,DC=example,DC=test' -operation resultant
```

For creation, provide all fields in a JSON file (intervals below are exact ticks):

```json
{"Precedence":100,"ComplexityEnabled":true,"ReversibleEncryptionEnabled":false,
 "PasswordHistoryCount":24,"MinPasswordLength":14,"LockoutThreshold":5,
 "MinPasswordAge":864000000000,"MaxPasswordAge":36288000000000,
 "LockoutDuration":18000000000,"LockoutObservationWindow":18000000000}
```

The example accepts `-operation create -name Example -settings policy.json -apply`,
`update` with a partial settings file and `-dn`, `delete -dn ... -apply`, and
`add-subjects`/`remove-subjects` with repeated explicit `-subject` DNs and `-apply`.
It prints returned observations before reporting an error. The SDK itself has no
PowerShell runtime dependency. `scripts/reference-fine-grained-policy.ps1` is an
explicit-server, read-only reference collector for separately owned fixtures.

Portable tests cover lifecycle, interval boundaries, strict/atomic subjects,
invalid subjects, server-selected resultant policies, omission, permission and
partial failures, range continuity and cancellation. Windows loopback tests drive
actual WinLDAP policy/subject Modify bytes, native errors and allocation cleanup.
Live direct/group/competing/no-PSO results, permissions, server schema differences
and mutation/readback comparison with the reference module remain unqualified;
these tests do not close issue #26.
