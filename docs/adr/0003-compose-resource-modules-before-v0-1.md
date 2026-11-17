# Compose resource modules before v0.1.0

Accepted on 2026-11-17. Move the SDK out of the repository root into a composed
`activedirectory` entry point, resource modules, and shared internal engine and
model packages, following the organization of Go SDK Jamf Pro v2. The owner
authorized breaking imports and calls before v0.1.0, so this migration keeps no
module-root compatibility facade; the split gives resource workflows their own
home while retaining one shared native session and its existing outcome and
lifetime guarantees. Public v1 compatibility still begins only when the
[readiness gate](../sdk-readiness.md) passes.

See [repository architecture](../architecture.md) for ownership, migration, and
the distinction between current implementation paths and historical evidence.
