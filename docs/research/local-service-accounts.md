# Local managed service account operations

What `Install`, `Uninstall`, `Test` and `Reset-ADServiceAccount` actually do on
a domain member. **Observed, not inferred.** Issues
[#47](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/47),
[#48](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/48) and
[#49](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/49) are
framed as prove-then-implement; this is the proof half.

Evidence:
[`local-service-account-evidence/server2025-local-operations.json`](local-service-account-evidence/server2025-local-operations.json),
captured by `scripts/lab/reference-local-service-accounts.ps1` on the isolated
`ad.sdk.test` member. Module 1.0.1.0, OS build 26100.32230.

No secret material is recorded: password parameters are redacted and managed
password blobs appear as length and SHA-256 only.

## Test does not report local installation state

This is the finding most likely to be implemented wrongly from the name alone.

| Step | `Test-ADServiceAccount` |
| --- | ---: |
| gMSA created, **not installed** | **True** |
| after `Install-ADServiceAccount` | True |
| after `Uninstall-ADServiceAccount` | **True** |
| standalone account, associated but not installed | False |
| account does not exist | **throws** |

A gMSA tested `True` **before** it was ever installed and **still** `True`
after it was uninstalled. So `Test` reports whether this host can retrieve and
use the managed password — an eligibility check — not whether the account is
installed locally. Treating it as an install probe would be wrong.

For a non-existent account it raises an identity-resolution error rather than
returning `False`, so absence and ineligibility are distinguishable.

## Reset requires local installation

`Reset-ADServiceAccountPassword` failed on an account that was not installed on
the host, both before install and after uninstall, with:

```text
Referenced service account is not installed on this computer.
```

It succeeded on an **installed** gMSA. So Reset is a **local** operation
against installed host credential state, not a directory password reset. That
is why the nullable-credential binding was the prerequisite for this work:
deploymenttheory/go-bindings-win32#76 added `NetAddServiceAccountUTF16` so a
NULL password can be passed without a hidden string copy.

## Uninstall is idempotent

Uninstalling an already-uninstalled gMSA **succeeded**. A repeat uninstall is
therefore not an error condition and must not be reported as one.

## Standalone accounts need a host association

A standalone account (`-RestrictToSingleComputer`) could not be installed or
uninstalled until it was associated with the host computer via
`Add-ADComputerServiceAccount`. The failures were distinguishable and
informative:

| State | Install error | Uninstall |
| --- | --- | --- |
| no host association | `Indicates a particular Security ID may not be assigned as the owner of an object` | same error |
| host associated | `{Access Denied} A process has requested access to an object but has not been granted those access rights` | **succeeds** |

The association changes both operations, so the host link is a genuine
precondition rather than an optimisation.

## Replication is a precondition for the local cmdlets

The local cmdlets take no `-Server`: they resolve the account through the
member's own DC locator. An account created against one DC was **not found**
until it had replicated and become visible through that locator. The collector
now replicates each fixture to every other DC and waits for the member to see
it before any local step, recording whether that ever happened.

Any SDK equivalent must not assume an account written against an explicit
endpoint is immediately usable locally.

## Native differential: what the APIs actually report

A second run paired every cmdlet result with a native reading from
`scripts/lab/msaprobe` (`NetIsServiceAccount` plus `NetQueryServiceAccount`
level 1). Evidence:
[`local-service-account-evidence/server2025-native-differential.json`](local-service-account-evidence/server2025-native-differential.json).

| Fixture state | `Test` | `MSA_INFO_STATE` | `NetIsServiceAccount` |
| --- | --- | --- | --- |
| gMSA created, not installed | True | `MsaInfoInstalled` | **true** |
| gMSA installed | True | `MsaInfoInstalled` | true |
| gMSA after uninstall | True | `MsaInfoInstalled` | **true** |
| sMSA associated, not installed | False | `MsaInfoCanInstall` | false |
| account absent | throws | `MsaInfoNotService` | false |

Two conclusions, one of which overturned the earlier guess in this document:

1. **`Test` matches `NetIsServiceAccount` exactly** — all eleven observed rows
   agree. `ServiceAccountReadiness` therefore mirrors that boolean. The earlier
   inference that `Test` could not be `NetIsServiceAccount` came from MSDN's
   "exists in the Netlogon store" wording; the native reading does not behave
   that way for a gMSA.

2. **`MSA_INFO_STATE` does not track installation either.** A gMSA reported
   `MsaInfoInstalled` before it was ever installed and still after uninstall,
   while an sMSA that could not be installed reported `MsaInfoCanInstall`. So
   neither reading distinguishes installed from eligible for a gMSA, and the
   state enum's names are misleading for that case.

### Consequence for this SDK

`UninstallLocalServiceAccount` originally required the presence reading to flip
to false and returned `ErrServiceAccountLocalObservation` otherwise. For a group
managed account the reading never flips, so **every successful gMSA uninstall
reported a failure**. That verification is now scoped to standalone accounts;
a gMSA uninstall completes unverified and reports the presence it actually read.
`TestUninstallGroupManagedSucceedsWhenPresenceDoesNotFlip` reproduces the
original failure if the carve-out is removed.

A reading that does distinguish a gMSA's local installation has **not** been
found. Until one is, no API here claims to report it.

## Still unobserved

- **Installing a standalone account with an explicit password.** It returned
  access-denied even with the host association. Supplying a password for an
  account whose password the directory manages may simply be the wrong call;
  the correct standalone install path is **not established**.
- **Service logon.** Nothing here starts a service under an installed account,
  so readiness in the operational sense is not proven by `Test` alone.
- **Permission-denied and partial-failure paths** beyond those above.
- The native status codes behind each failure were not surfaced by the module;
  only its messages were captured.
