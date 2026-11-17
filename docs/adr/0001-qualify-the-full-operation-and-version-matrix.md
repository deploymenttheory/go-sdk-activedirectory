# Qualify the full operation and version matrix

Accepted on 2026-11-17. Readiness for building a Terraform provider requires
SDK-level qualification of all 151 operation equivalents and every applicable
scenario, parameter-set variant, and parameter claim on AD DS Server 2016, 2019,
2022, and 2025, retaining the existing per-parameter evidence bar. We chose this
full matrix over a small resource subset or Server 2025 qualification with
older-version smoke tests so the readiness guarantee covers the entire approved
surface on each named version.

The [readiness gate](../sdk-readiness.md) requires repeatable lifecycle and
reconciliation evidence, and allows evidenced observation limits with explicit
recovery paths. SDK tests establish the gate without requiring a provider
implementation. Live qualification targets amd64; arm64 compilation and portable
checks are required with runtime qualification explicitly pending, and AD LDS is
outside this initial guarantee. Aggregate coverage validation remains necessary
but cannot replace the separate claim-by-version review.
