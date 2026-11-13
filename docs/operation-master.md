# Operation master transfers and seizure (draft)

`Client.MoveOperationMasterRoles` moves selected FSMO roles to the server named
by the client's LDAP endpoint. The implementation uses the pinned WinLDAP
bindings directly. Execution requires Windows amd64 or arm64; configuration,
request types, and workflow tests remain portable. No runtime PowerShell, RSAT,
ADWS, or agent is required.

This is an implementation slice for [issue #32](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/32),
not a completed parity claim. Disposable-forest live qualification and
PowerShell differential tests remain outstanding. Do not use it for production
role changes until those checks are complete.

## Run the example

From a Windows account with the required directory permissions, against a
disposable forest:

```powershell
go run ./examples/operationmaster -server dc2.example.test -roles PDCEmulator,InfrastructureMaster
```

The call uses the current Windows identity with signed/sealed Negotiate.
Applications can use the existing `Config.Credentials` and TLS options.
The example prints every role outcome even when an earlier role fails.

Seizure requires the explicit `-force` switch. It still attempts transfer first:

```powershell
go run ./examples/operationmaster -server dc2.example.test -roles SchemaMaster -force
```

Force does not bypass directory permissions. As with Microsoft's seizure
procedure, the former holder must be handled according to the forest recovery
plan; do not bring it back assuming the SDK repaired its state.

For AD LDS, use the instance's LDAP port and select only `SchemaMaster` or
`DomainNamingMaster`. Domain roles always apply to the connected AD DS server's
default domain; `Config.Partition` does not redirect them. The target DSA is
resolved from RootDSE `dsServiceName`, including AD LDS GUID references.

## Observable behavior

All requested roles and their ownership objects are validated before any write.
The client rejects unknown directory types, RODCs, unsynchronized servers,
unsupported AD LDS roles, malformed domain SIDs, and missing ownership data.
Requests reject empty, duplicate, or unrecognized roles. Valid roles execute in
request order and stop at the first error; earlier changes are not rolled back.

| Role | Transfer attribute on RootDSE | Ownership object |
| --- | --- | --- |
| PDCEmulator | `becomePdc` with the binary domain `objectSID` | Default domain NC root (`domainDNS`) |
| RIDMaster | `becomeRidMaster` with `1` | Object referenced by domain `rIDManagerReference` (`rIDManager`) |
| InfrastructureMaster | `becomeInfrastructureMaster` with `1` | `CN=Infrastructure,<default domain NC>` (`infrastructureUpdate`) |
| SchemaMaster | `becomeSchemaMaster` with `1` | Schema NC root (`dMD`) |
| DomainNamingMaster | `becomeDomainMaster` with `1` | `CN=Partitions,<configuration NC>` (`crossRefContainer`) |

Transfer succeeds only after the server acknowledges it. The SDK then reads
`fSMORoleOwner` back from the role object. A successful readback reflects this
server's replica; it does not prove forest convergence or effective role
activation. Native permission failures retain `LDAPError` and are also
identifiable through `errors.Is(err, ad.ErrOperationMasterPermission)`.

With `Force`, a clean server rejection with LDAP `operationsError`,
`unavailable`, or `unwillingToPerform` permits a fresh ownership read followed
by seizure. Other rejection statuses, failed readback, changed ownership,
permission failure, cancellation, or uncertain responses stop the request.
Seizure uses one LDAP Modify containing deletion of the exact observed
`fSMORoleOwner` and addition of the target DSA DN. No permissive-modify control
is supplied: a concurrent ownership change must fail instead of being
overwritten. There is no unconditional replacement fallback.

RID seizure includes a conditional `rIDAvailablePool` change in that same
Modify: the next available RID advances by 30,000 while preserving the upper
32-bit pool limit. Exhaustion and overflow fail before seizure. Readback must
show ownership by the target and a pool at least as advanced as the requested
value, with the same limit. The server may allocate further pools between the
write and readback. The atomic guarded change and its role-specific server
behavior still require live qualification; a rejected guarded write is never
replaced with an unguarded attempt.

`Outcomes` contains one item per requested role. `Transfer` and `Seizure`
separately report not-attempted, accepted, rejected, or uncertain writes. A
seizure that succeeds retains the failed transfer's diagnostic in
`Transfer.Err`, while the role's `Err` describes the final result. Check both
the returned error and each outcome's `Verified` field. An accepted write
followed by failed readback remains marked transferred/seized with a non-nil
error; it must not be retried automatically.

Loss of a write response, submission ambiguity, or cancellation after
submission returns `ErrOperationMasterUncertain` and retires the LDAP
connection. Abandon and Close do not roll back a write. There is no write replay,
automatic reconnect, seizure after uncertainty, or referral following. Reconcile
the role object and RID pool through a new read-only connection before deciding
on any further write. Error strings omit LDAP diagnostic text; explicit
`LDAPError.Diagnostic` access can expose directory details.

## Validation and remaining qualification

`go test . -run OperationMaster` exercises all role payloads, role objects,
AD LDS restrictions, permission failures, partial completion, RID bounds,
readback mismatch, and refusal to replay uncertain writes. On supported Windows
platforms it also tests native ABI argument construction, GC lifetimes, response
parsing, cancellation, session retirement, and ownership of returned messages
and diagnostic allocations through injected WinLDAP boundaries.

Remaining disposable-forest checks: real transfer and already-owned behavior
for all five roles; unreachable holders; each role's seizure; concurrent
ownership/pool changes; denied change-role and RID-pool permissions; interrupted
responses; cleanup; and readback against Windows Server 2016/2019/2022/2025 plus
the two AD LDS roles. Compare applicable outcomes with
`Move-ADDirectoryServerOperationMasterRole`, recording server and module
versions and the complete RID-pool values. The local tests are not substitutes
for these live checks, and issue #32 must remain open.

## Primary references

- [MS-ADCAP transfer mechanisms and binary PDC SID](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adcap/cd0e446b-ff97-4b53-8d93-a61c17cd2095)
- [MS-ADCAP seizure role classes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adcap/9061da1b-fa23-480c-98af-d4f7b641addb)
- [Microsoft ownership-object paths](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/fsmo-transfer-seizure-process)
- [MS-ADTS modify constraints, including exact-value deletion failures](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/76df255d-dc67-4c1f-adc6-1e5b60021304)
- [Required change-role access rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dc21d519-c3e1-4ce0-b061-cc2beb95db5a)
- [PowerShell transfer-before-seizure semantics](https://learn.microsoft.com/en-us/powershell/module/activedirectory/move-addirectoryserveroperationmasterrole?view=windowsserver2025-ps)
- [PowerShell's 30,000 RID seizure advance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/transfer-or-seize-operation-master-roles-in-ad-ds)
- [RID pool high/low word interpretation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-raise-rid-pool)
- [WinLDAP asynchronous Modify API](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_modify_extw)
