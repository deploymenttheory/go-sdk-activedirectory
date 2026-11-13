# Documentation

- [Operation coverage](coverage.md): the approved command surface, delivery
  ownership, and implementation/evidence status.
- [Maintaining coverage](coverage-guide.md): pinned sources, validation,
  regeneration, and evidence requirements.
- [Conditional expressions](conditions.md): typed builders and native Windows
  SDDL compilation.
- [Connection and RootDSE](connection.md): current and explicit identities,
  LDAPS/StartTLS, AD LDS SIMPLE binds and partitions, directory capabilities,
  typed/raw properties, and resource lifetime.
- [Directory discovery](discovery.md): native DC Locator candidates and current
  domain names, LDAP topology/trust projections, and remaining identity/filter
  and reference-evidence requirements.
- [Directory reference harness](directory-reference.md): opt-in preparation,
  collection/comparison, fixture ownership, real trust verification, and live-run
  prerequisites. No live qualification is implied by the local harness tests.
- [Directory search](search.md): scopes, selected raw attributes, paging, limits,
  cancellation and partial-result errors.
- [Optional features](optional-features.md): typed inspection, enabled-scope
  range continuation, guarded native enable/disable, and qualification limits.
- [DC cloning inclusion lists](dc-cloning.md): local native discovery, typed exclusions,
  explicit-path XML generation, and qualification limits.
- [DC clone configuration](dc-clone-configuration.md): online prerequisites,
  explicit offline generation, network/XML validation, and qualification limits.
- [Reference lab](lab.md): isolated Hyper-V provisioning, reference tests,
  version profiles, and cleanup.

The SDK is under development. Consult the coverage report before relying on an
operation; a planned operation is not an implemented API.
