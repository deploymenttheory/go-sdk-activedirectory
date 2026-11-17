# Release v1 with a public compatibility baseline

Accepted on 2026-11-17. Release v1.0.0 only when the
[readiness gate](../sdk-readiness.md) passes, and publish a compatibility baseline
covering the public interfaces for all 151 operation equivalents, including
identity, values, request/result types, errors, outcomes, and recovery contracts.
Subsequent breaking public interface changes require a major version, giving
provider development a stable dependency instead of requiring routine coordinated
breaking changes across the SDK and provider. Until that gate passes, the SDK
remains provisional; this decision does not declare existing interfaces stable.
