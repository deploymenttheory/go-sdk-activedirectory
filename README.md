# Go SDK for Active Directory

A Go SDK under development for Active Directory Domain Services and applicable
Active Directory Lightweight Directory Services operations. The delivery plan
covers all 151 cmdlets in the approved Windows Server 2025 ActiveDirectory
PowerShell reference.

The SDK uses native Windows APIs through
[go-bindings-win32](https://github.com/deploymenttheory/go-bindings-win32).
Runtime support targets Windows amd64 and arm64, with no PowerShell or RSAT
runtime dependency. PowerShell is used for lab provisioning and reference tests.
Portable tooling and expression builders can be developed on Linux and macOS.

Public [backend and authentication contracts](docs/authentication.md) also
describe explicit portable selection, password/keytab/file-cache Kerberos inputs,
and measured protection. They validate on every supported build platform;
portable execution currently fails with `ErrBackendUnavailable` before network
or credential submission while implementation and qualification remain pending.

The public entry point is
`github.com/deploymenttheory/go-sdk-activedirectory/activedirectory`. It composes
resource modules around one native connection.

## Current state

Public interfaces remain provisional. The SDK groups typed workflows
into 18 resource modules, including users, groups, computers, organizational units,
accounts, memberships, service accounts, policies, claims, and replication.

Implementation and qualification are tracked separately. The generated
[coverage report](docs/coverage.md) records the operation contract; a command's
state includes both its behavioral scenarios and parameter-set variants. Planned
test identifiers are not passing evidence.

The [SDK v1 readiness gate](docs/sdk-readiness.md) requires evidence for every
applicable operation, scenario, variant, and parameter claim across AD DS Server
2016, 2019, 2022, and 2025, plus repeatable lifecycle and reconciliation behavior.
That gate has not been met. AD LDS and arm64 runtime qualification remain outside
the initial readiness guarantee. See the [coverage handoff](docs/coverage-handoff.md)
and [delivery issues](https://github.com/deploymenttheory/go-sdk-activedirectory/issues)
for measured behavior and remaining work.

## Usage

`Dial` creates one authenticated session shared by the resource modules. Use
`client.Users`, `client.Groups`, and the other module fields for typed operations;
use `client.Directory` for generic search, identity, and object operations.
Closing the client closes that session for every module.

This read-only helper uses the current Windows identity with Negotiate. It
returns any available user observation along with read or cleanup errors:

```go
package example

import (
    "context"
    "errors"

    ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
    "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

func readUser(ctx context.Context, server, dn string) (user *users.User, err error) {
    client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
    if err != nil {
        return nil, err
    }
    defer func() { err = errors.Join(err, client.Close()) }()

    identity, err := ad.IdentityByDN(dn)
    if err != nil {
        return nil, err
    }
    result, err := client.Users.User(ctx, identity, ad.ResolveIdentityOptions{})
    return result.User, err
}
```

Check the error before treating the observation as complete. Mutations likewise
retain accepted, rejected, uncertain, and readback outcomes; see
[error classification](docs/errors.md) and [object mutations](docs/directory-objects.md).

Resource request and result types live in `activedirectory/services/<family>`.
Configuration and common identities/values have public `config` and `shared`
packages, with convenience aliases at the entry point. The standalone
[`conditions`](docs/conditions.md) and [`dccloning`](docs/dc-cloning.md) import paths
remain available. The [connection guide](docs/connection.md) covers explicit
credentials, TLS, and applicable AD LDS authentication.
The [authentication contract example](examples/authcontracts/main.go) runs
offline with `go run ./examples/authcontracts`.

Run the user example on Windows against your own directory:

```sh
go run ./examples/users -server dc1.example.test -dn "CN=Example User,OU=People,DC=example,DC=test"
```

## Repository layout

```text
activedirectory/
  activedirectory.go    Composed client and Dial entry point
  client/              Generic directory session
  config/              Connection configuration
  shared/              Common directory types and values
  services/<family>/   Typed resource operations
  internal/engine/     Native session, search, mutations, and lifetime
  internal/model/      Shared models, codecs, and directory helpers
  acceptance/          Cross-package tests and opt-in lab harnesses
conditions/            Conditional expressions and SDDL
dccloning/             Domain-controller cloning
coverage/              Operation inventory and retained evidence
cmd/                   Offline contract and reference tools
examples/              Runnable callers
scripts/lab/           Lab preparation, snapshots, and collectors
```

The [architecture guide](docs/architecture.md) includes caller migration examples
and package ownership. The [glossary](GLOSSARY.md) defines the qualification terms.

## Development

Use the latest stable Go release, currently Go 1.27.4. From the repository root:

```sh
go test ./...
go vet ./...
go run ./cmd/adcoverage
golangci-lint run --fix=false ./...
```

The maximum Go line length is **180 characters**: `lll` enforces the limit and
`golines` formats toward the same limit. Apply the configured formatters with:

```sh
golangci-lint fmt
```

Native condition and client tests execute on Windows amd64/arm64. Other platforms
exercise portable construction, client synchronization, and unsupported-platform
behavior. Directory integration tests require an explicitly configured isolated
lab and skip ordinary test runs. The compiled SDK qualification suite now lives
at `./activedirectory/acceptance`; its collectors preserve nested source snapshots
and independently verify fixture cleanup. See the [lab guide](docs/lab.md).

Run the condition example on Windows:

```sh
go run ./examples/conditions
```

See the [documentation](docs/README.md), [coverage maintenance guide](docs/coverage-guide.md),
and [contribution guidelines](CONTRIBUTING.md).
