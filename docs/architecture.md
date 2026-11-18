# Repository architecture

The SDK uses a composed client and resource packages, following the organization
of [Go SDK Jamf Pro v2](https://github.com/deploymenttheory/go-sdk-jamfpro-v2).
The package split is an intentional breaking change before v0.1.0; the future
[v1 compatibility baseline](sdk-readiness.md) remains a separate release gate.

## Package ownership

```text
activedirectory/             Public client composition and connection entry point
  client/                   Generic directory session for advanced callers
  config/                   Connection configuration
  shared/                   Common directory identities, values and outcomes
  services/<family>/        Resource operations and family-owned public types
  internal/engine/          Backend sessions, generic LDAP operations and lifetime
  internal/model/           Shared models, codecs and directory helpers
  acceptance/               Cross-package and opt-in live qualification tests
conditions/                 Independent conditional-expression module
dccloning/                  Independent domain-controller cloning module
cmd/                        Offline coverage and reference tools
coverage/                   Approved inventory and retained lab evidence
examples/                   Runnable caller examples
scripts/lab/                Provisioning, source snapshots and collectors
3rd_party/                  Owned protocol sources, licenses and patch ledgers
```

The public entry point composes the resource modules around one connection.
Resource workflows own their typed operations; shared models break dependencies
between account, computer, discovery, and replication projections. Internal
helpers support those workflows without duplicating protocol calls or creating
separate sessions for each resource family.

The engine retains connection serialization, cancellation, timeout bounds,
native memory ownership, generic identity/search/mutation algorithms, and
explicit write outcomes. The package split introduces no automatic retry,
rollback, credential retention, or PowerShell runtime dependency. Resource
modules share the same session lifetime; closing the composed client closes it
for every module.

The engine selects exactly one configured backend. Portable LDAP uses owned
sources under `3rd_party/ldap` and `3rd_party/gokrb5`; their original revisions,
licenses and local changes are retained beside the source. These packages ship
inside the SDK module with SDK-owned imports. They contain no nested Go module,
Git checkout or local `replace` directive. The engine owns the context-bound
socket, verifies TLS before simple bind, and retires a connection after protocol
or transport failure. Native Windows authentication keeps its existing WinLDAP
and SSPI boundary. See [portable LDAP](portable-ldap.md) for execution scope.

## Migrating callers

Import the SDK entry point below the module root:

```go
import ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
```

Use the composed resource module for typed operations, such as
`client.Users.CreateUser(...)`. Resource methods retain their operation names
while moving off the single generic client. Family request and result types
are available from their resource package; common identities, values and
configuration have shared public packages. The runnable examples show complete
imports and calls for each family.

| Previous caller shape | New caller shape |
| --- | --- |
| Module-root import | `.../go-sdk-activedirectory/activedirectory` |
| `client.CreateUser(...)` | `client.Users.CreateUser(...)` |
| `ad.CreateUserRequest` | `users.CreateUserRequest` from `services/users` |
| `client.Search(...)` | `client.Directory.Search(...)` |
| `client.Directory().Domain(...)` | `client.Discovery.Domain(...)` |
| A client passed as `Destination` or `GlobalCatalog` | Its generic `Directory` session, or a separately dialed `client.Client` |

There is no compatibility package at the old module-root import. The independent
`conditions` and `dccloning` imports retain their existing paths. Internal
packages are implementation details, including any symbols exported solely to
cross an internal package seam or exercise native behavior in tests.

## Tests, tooling and evidence

Run `go test ./...` and `go vet ./...` from the repository root. The compiled
cross-package qualification suite lives at `./activedirectory/acceptance`;
its live tests retain their environment-variable and explicit-write gates.
Ordinary test runs do not provision a lab or contact a directory.

Lab source snapshots preserve package directories, dependency pins and fixtures.
Collectors still verify the compiled binary hash, enforce write authorization,
and verify fixture cleanup independently. Scripts must compile the acceptance
package rather than assuming a testable Go package at the repository root.

Coverage implementation references follow their current source files. Captured
lab artifacts, source hashes, test IDs and observations remain historical
records: this restructure does not rewrite those bytes or advance any coverage
state. Existing evidence does not establish a fresh live qualification of the
new package graph. Subsequent qualification runs record their actual source and
binary provenance.

SDK errors retain their existing propagation across resource and engine packages.
The wrapping linter treats calls within this SDK module as internal; calls into
other modules and the standard library retain their existing checks.
