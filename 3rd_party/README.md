# Maintained third-party source

Dependencies that need local fixes are kept as source under this directory.
Patch the owned copy when required and add regression tests for the behavior.
The SDK imports these packages through its own module path, so published SDK
consumers receive the same reviewed code.

Each component retains its upstream licence, exact repository revision, original
module metadata and a `PATCHES.md` ledger. Preserve upstream files and provenance
when updating a component; review the resulting delta and rerun its protocol,
cryptographic and malformed-input tests. Keep any upstream-only module files as
provenance text rather than nested `go.mod` files or consumer-local replacements.

Unit tests run with the SDK. Tests needing a real LDAP/KDC fixture require explicit
configuration and use owned disposable services. Synthetic tests and successful
compilation do not establish live Active Directory qualification.

Vendored code remains subject to security and correctness checks. Limited style
exceptions preserve upstream conventions; they do not waive the 180-character
line limit or authorize weaker authentication. Use the latest stable Go toolchain
for project builds and validation.
