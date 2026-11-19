# Go SDK for Active Directory

A Go SDK under development for Active Directory Domain Services and applicable
Active Directory Lightweight Directory Services operations. The delivery plan
covers all 151 cmdlets in the approved Windows Server 2025 ActiveDirectory
PowerShell reference.

The SDK provides native Windows APIs through
[go-bindings-win32](https://github.com/deploymenttheory/go-bindings-win32) and an
explicit portable LDAP backend. Portable sessions support simple authentication
over verified LDAPS or StartTLS, plus explicit Kerberos credential sources and
required SASL protection on Go platforms, including Linux and Windows.
Neither backend requires PowerShell or RSAT at runtime. PowerShell is used for
lab provisioning and reference tests.

Public [backend and authentication contracts](docs/authentication.md) also
describe explicit portable selection, password/keytab/file-cache Kerberos inputs,
and measured protection. Kerberos implementation and live qualification are
tracked separately; consult the ticket evidence before claiming a platform or
server version is qualified. See the [portable LDAP guide](docs/portable-ldap.md)
for supported sessions, connection ownership and qualification limits. The
[verified TLS guide](docs/portable-tls.md) covers private CA trust, observed
protection and the fresh Windows/Linux acceptance matrix.

The public entry point is
`github.com/deploymenttheory/go-sdk-activedirectory/activedirectory`. It composes
resource modules around one authenticated connection.

## Current state

Public interfaces remain provisional. The SDK groups typed workflows
into 18 resource modules, including users, groups, computers, organizational units,
accounts, memberships, service accounts, policies, claims, and replication.

Implementation and qualification are tracked separately. The generated
[coverage report](docs/coverage.md) records the operation contract; a command's
state includes both its behavioral scenarios and parameter-set variants. Planned
test identifiers are not passing evidence.

Portable [discovery](docs/discovery.md) separates untrusted DNS candidates from
authenticated domain/controller identity. Select a DC explicitly, then use
`DialDomainController` and the same client's topology modules. The
[private-stdin example](examples/portablediscovery/README.md) supports verified
TLS and explicit Kerberos protection; no Windows join state is inferred.
Owned wire tests are development evidence, with live qualification tracked in #175.

Portable [replication diagnostics](docs/replication.md) use direct authenticated
endpoint mapping and DRS/RPC with explicit identities for each selected server.
The [private-stdin example](examples/portablereplication/README.md) uses the normal
public API. This draft has a canonical Windows/Server 2025 password read and
native comparison; the [remaining qualification matrix](docs/research/portable-replication-validation.md)
is still required before release.

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

This read-only helper uses an explicit portable Kerberos keytab over verified LDAPS. It
returns any available user observation along with read or cleanup errors:

```go
package example

import (
    "context"
    "errors"

    ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
    "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

func readUser(ctx context.Context, server, dn, username, realm, keytab string) (user *users.User, err error) {
    client, err := ad.Dial(ctx, ad.Config{
        Backend: ad.BackendPortable,
        Endpoint: ad.Endpoint{Host: server},
        Transport: ad.TransportLDAPS,
        Authentication: ad.AuthenticationKerberos,
        Kerberos: &ad.KerberosCredentials{
            Source: ad.KerberosKeytabFile, Username: username,
            Realm: realm, SPN: "ldap/" + server, KeytabPath: keytab,
        },
    })
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
The [portable LDAP example](examples/portableldap/main.go) connects with explicit
TLS roots and reads its exact password bytes from redirected standard input.
The portable [descriptor codec](docs/conditions.md) parses binary descriptors and
SDDL, preserving opaque ACEs and unrelated descriptor components during edits.
Run the [offline descriptor example](examples/securitydescriptors/main.go) with
`go run ./examples/securitydescriptors`; it performs no directory operation.

Runnable directory examples use shared secure authentication options. Supply an
explicit Kerberos identity and keytab/cache; verified LDAPS is the default:

```sh
go run ./examples/users -server dc1.example.test \
  -auth-user automation -auth-realm EXAMPLE.TEST \
  -auth-keytab /run/secrets/automation.keytab \
  -dn "CN=Example User,OU=People,DC=example,DC=test"
```

The [examples guide](examples/README.md) covers verified StartTLS, required
Kerberos signing/sealing, private CA trust, secure global catalog ports and
explicit native Windows selection for operations that require that backend.
Password demonstrations read secrets from redirected stdin. See the
[Kerberos example](examples/portablekerberos/main.go) and
[SASL guide](docs/portable-sasl.md) for the authentication and protection flows.

## Repository layout

```text
activedirectory/
  activedirectory.go    Composed client and Dial entry point
  client/              Generic directory session
  config/              Connection configuration
  shared/              Common directory types and values
  services/<family>/   Typed resource operations
  internal/engine/     Backend sessions, search, mutations, and lifetime
  internal/model/      Shared models, codecs, and directory helpers
  acceptance/          Cross-package tests and opt-in lab harnesses
conditions/            Conditional expressions and SDDL
dccloning/             Domain-controller cloning
coverage/              Operation inventory and retained evidence
cmd/                   Offline contract and reference tools
examples/              Runnable callers
scripts/lab/           Lab preparation, snapshots, and collectors
3rd_party/             SDK-owned, pinned protocol sources and patch ledgers
```

The [architecture guide](docs/architecture.md) includes caller migration examples
and package ownership. The [glossary](GLOSSARY.md) defines the qualification terms.
The [mutation reconciliation guide](docs/mutation-reconciliation.md) explains
accepted, rejected and unknown writes, per-stage summaries, normalized values
and the positive deleted-object evidence required for verification.

## Development

Use the latest stable Go release, currently **Go 1.27.4**. The module requires
Go 1.27.4 and CI installs the current stable toolchain. From the repository root:

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

Native condition and client tests execute on Windows amd64/arm64. Portable TLS,
LDAP socket fixtures, cryptographic vectors and client synchronization execute
on supported Go platforms. Directory integration tests require an explicitly configured isolated
lab and skip ordinary test runs. The compiled SDK qualification suite now lives
at `./activedirectory/acceptance`; its collectors preserve nested source snapshots
and independently verify fixture cleanup. See the [lab guide](docs/lab.md).

Run the condition example on Windows:

```sh
go run ./examples/conditions
```

See the [documentation](docs/README.md), [coverage maintenance guide](docs/coverage-guide.md),
and [contribution guidelines](CONTRIBUTING.md).
