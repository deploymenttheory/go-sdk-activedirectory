# Capability error and resource lifetime qualification

Run `capability-20261114T144507Z` passed on 2026-11-14 against the isolated
Server 2025 two-DC/member profile. Local execution, not a CI result. This is the
evidence behind `capability-errors-and-resource-lifetime` for twelve operations.

## No second directory was provisioned

The scenario needs an *unsupported* directory as well as a supported one. AD LDS
was the obvious candidate and the lab no longer has it — the instances went with
a previous build — but re-provisioning proved unnecessary. The unsupported
directory is a **loopback LDAP fixture the test starts in its own process**,
advertising no `supportedCapabilities` at all, and read by the same real
WinLDAP over a real socket. The refusal therefore comes from the SDK's own
prerequisite rather than from a transport failure, and nothing is installed.

## What passed

| Observation | Result |
| --- | --- |
| supported capability | 12/12 read against AD DS |
| repeated calls | 3 per operation, on one session |
| unsupported capability | 12/12 refused **before any search** |
| native error after resources taken | 12/12, by requesting a naming context the server does not hold |
| allocations after the satisfied path | all seven counters zero |
| allocations after the failed path | all seven counters zero |
| `Close` idempotent | 12/12 |

Three repeats is the minimum that distinguishes a reusable session from one that
merely survived a second call.

## The refusal is not uniform, and the artifact says so

"Wrong directory type" is reported three different ways across the SDK. The
artifact records which each operation produced rather than flattening them all
into "refused":

| Refusal | Operations |
| --- | --- |
| `ErrUnsupported` | `Get-ADGroup`, `Get-ADOrganizationalUnit`, `Get-ADClaimType`, `Get-ADClaimTransformPolicy`, and the three resource-property reads |
| `DirectoryCapabilityError` (wrapping `ErrUnsupportedDirectory`) | `Get-ADComputer`, `Get-ADServiceAccount`, `Get-ADAuthenticationPolicy` |
| `ErrUnsupportedDirectory` | `Get-ADReplicationConnection` |
| `ErrUserCapability` | `Get-ADUser` |

All four are legitimate: `central_access_test.go` and `replication_links_test.go`
pin `ErrUnsupported` as the directory-type contract for those paths, so it is a
deliberate choice rather than an oversight. An earlier run of this
qualification failed seven operations because the test assumed a single
refusal shape; the test was wrong, not the SDK.

What *was* wrong is that `ErrUnsupported` read `"Active Directory native API
unavailable; execution requires Windows amd64 or arm64"`. On Windows, against a
server of the wrong type, that told the caller to change operating system. The
message now names both causes. No sentinel changed, so nothing that matches on
`ErrUnsupported` is affected. Splitting the sentinel per cause would be the
fuller fix and is a deliberate API decision with pinned tests behind it; see the
tracking issue.

## What this is not

The artifact records `full_ticket_complete: false`. Twelve scenarios advance.

`Get-ADObject` is recorded and **excluded**: `Client.Search` carries no
directory-type prerequisite by design — it submits what the caller asked for —
so there is no capability refusal to observe. Claiming it would mean claiming an
observation that cannot be made.

Not covered: a missing native export, which would need a build with the export
absent rather than a directory that lacks a capability.
