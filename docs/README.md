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
- [Identities and values](identities-and-values.md): explicit DN/GUID/SID/account
  identities, naming-context scope, raw attributes and precise typed conversions.
- [Single-object synchronization](object-sync.md): explicit DC/object targeting,
  RODC password-only policy checks, uncertain outcomes and destination readback.
- [Generic object mutations](directory-objects.md): create, update, rename and
  delete objects with explicit attribute changes and observable write outcomes.
- [Group lifecycle](groups.md): typed reads, creation, property/scope changes,
  leaf deletion, and explicit membership qualification gaps.
- [User lifecycle](users.md): typed reads and properties, disabled creation with
  optional password and enablement stages, conditional flag updates and deletion.
- [Account control](account-control.md): shared stored flags, enable/disable,
  unlock, server-computed state and explicit mutation outcomes.
- [Typed LDAP filters](filters.md): escaped literal composition, binary values,
  AD matching rules, explicit raw filters and separate DN escaping.
- [Generic object mutations](directory-objects.md): create, update, rename and
  delete objects with explicit attribute changes and observable write outcomes.
- [Account passwords](account-passwords.md): distinct changes and resets with
  measured session protection, secret handling, and uncertain write outcomes.
- [AD filter expressions](ad-filters.md): portable parsing, explicit Go variables,
  property profiles, typed conversions and offline module reference checks.
- [Organizational units](organizational-units.md): typed OU lifecycle, explicit
  parent/OU protection ACL changes, partial outcomes and qualification limits.
- [Typed LDAP filters](filters.md): escaped literal composition, binary values,
  AD matching rules, explicit raw filters and separate DN escaping.
- [Account passwords](account-passwords.md): distinct changes and resets with
  measured session protection, secret handling, and uncertain write outcomes.
- [DC cloning inclusion lists](dc-cloning.md): local native discovery, typed exclusions,
  explicit-path XML generation, and qualification limits.
- [DC clone configuration](dc-clone-configuration.md): online prerequisites,
  explicit offline generation, network/XML validation, and qualification limits.
- [Reference lab](lab.md): isolated Hyper-V provisioning, reference tests,
  version profiles, and cleanup.

The SDK is under development. Consult the coverage report before relying on an
operation; a planned operation is not an implemented API.
