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

## Current state

This is an initial implementation, with no stable API or complete AD client yet.
The repository contains:

- A pinned operation and parameter inventory, its validator, and a generated
  [coverage report](docs/coverage.md).
- A [headless conditional-expression API](docs/conditions.md) that compiles SDDL
  using Windows APIs.
- An offline importer for updating the pinned Microsoft documentation snapshot.

Inventory entries describe planned work. They do not imply implemented or
validated behavior. The [delivery issues](https://github.com/deploymenttheory/go-sdk-activedirectory/issues)
track the remaining work, including LDAP services, authentication, replication,
managed service accounts, and versioned lab evidence.

## Development

Use Go 1.25 or later. From the repository root:

```sh
go test ./...
go vet ./...
go run ./cmd/adcoverage
```

Native condition tests execute on Windows amd64/arm64. Other platforms exercise
the portable builders and unsupported-platform behavior.

Run the condition example on Windows:

```sh
go run ./examples/conditions
```

See the [documentation](docs/README.md), [coverage maintenance guide](docs/coverage-guide.md),
and [contribution guidelines](CONTRIBUTING.md).
