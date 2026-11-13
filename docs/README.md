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
- [Computer lifecycle](computers.md): computer-specific naming and attributes,
  conditional SPN/security updates, staged creation and explicit deletion scope.
- [Managed service accounts](service-accounts.md): sMSA/gMSA lifecycle, retrieval
  descriptors, outbound creation and bounded computer associations.
- [Account creation containers](account-creation-defaults.md): redirected
  default containers, explicit parents and naming-context selection.
- [Organizational units](organizational-units.md): typed OU lifecycle, explicit
  parent/OU protection ACL changes, partial outcomes and qualification limits.
- [Account control](account-control.md): shared stored flags, enable/disable,
  unlock, server-computed state and explicit mutation outcomes.
- [Account expiration and state](account-state.md): explicit expiration instants,
  never-expire values and bounded state searches with unreadable observations.
- [Principal memberships](principal-memberships.md): recursive group members,
  primary/foreign principals, explicit domain/catalog contexts, authorization
  SIDs and per-target membership write outcomes.
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
- [Account control](account-control.md): shared stored flags, enable/disable,
  unlock, server-computed state and explicit mutation outcomes.
- [Account password permission](account-password-permission.md): SELF/Everyone
  Change-Password ACE observations and explicit allow/deny DACL changes.
- [Fine-grained password policies](fine-grained-password-policy.md): typed PSO
  lifecycle, explicit subject links and server-selected resultant policies.
- [Account password permission](account-password-permission.md): SELF/Everyone
  Change-Password ACE observations and explicit allow/deny DACL changes.
- [Claim types](claim-types.md): derived value types, schema-settled sources,
  suggested values, and the referenced-delete guard.
- [Central access rules and policies](central-access.md): typed lifecycle,
  conditional permissions, policy SIDs, bounded memberships and native outcomes.
- [Typed LDAP filters](filters.md): escaped literal composition, binary values,
  AD matching rules, explicit raw filters and separate DN escaping.
- [Account passwords](account-passwords.md): distinct changes and resets with
  measured session protection, secret handling, and uncertain write outcomes.
- [Single-object synchronization](object-sync.md): explicit DC/object targeting,
  RODC password-only policy checks, uncertain outcomes and destination readback.
- [RODC password replication](rodc-password-replication.md): allowed/denied lists,
  distinct authentication/revealed usage, authoritative resultant policy and
  explicit mutation outcomes.
- [Object restoration](object-restoration.md): controlled deleted-object discovery,
  Recycle Bin restoration and explicit legacy tombstone reanimation.
- [Replication sites and subnets](replication-sites.md): typed topology lifecycle,
  UTC schedules, subnet associations and directory-server site placement.
- [Replication connections, links and bridges](replication-links.md): native
  connection settings, atomic membership changes and bounded reference reads.
- [Authentication policies](authentication-policies.md): typed lifecycle,
  headless descriptors, exact lifetimes, audit/enforcement and direct assignment.
- [Authentication policy silos](authentication-silos.md): policy references,
  distinct grants and assignments, bounded links and explicit mutation outcomes.
- [Typed LDAP filters](filters.md): escaped literal composition, binary values,
  AD matching rules, explicit raw filters and separate DN escaping.
- [Domain and forest settings](domain-forest-settings.md): typed settings and
  explicit functional-level raises/lowers with role and prerequisite checks.
- [Optional features](optional-features.md): typed inspection, enabled-scope
  range continuation, guarded native enable/disable, and qualification limits.
- [Object moves](object-moves.md): intrapartition AD DS/LDS and same-forest
  cross-domain moves with explicit delegation, RID checks and uncertain outcomes.
- [DC cloning inclusion lists](dc-cloning.md): local native discovery, typed exclusions,
  explicit-path XML generation, and qualification limits.
- [DC clone configuration](dc-clone-configuration.md): online prerequisites,
  explicit offline generation, network/XML validation, and qualification limits.
- [Reference lab](lab.md): isolated Hyper-V provisioning, reference tests,
  version profiles, and cleanup.

The SDK is under development. Consult the coverage report before relying on an
operation; a planned operation is not an implemented API.
