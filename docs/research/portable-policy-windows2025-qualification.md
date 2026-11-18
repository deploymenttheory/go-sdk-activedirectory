# Portable policy integration: Windows / Server 2025

The public SDK collector at `6acd7e15e8ad6e889eef9c04486714167804b56e` passed six
cases from Windows amd64 against Server 2025 using Go 1.27.4. Authentication-policy
updates cover all five binary descriptor properties; central-rule updates cover
current, proposed, history and resource-condition text. Accepted values matched
readback. Both families returned actual LDAP 50 for the narrowly denied actor,
and malformed conditions were refused without changing values.

The actual session reported complete mutual Kerberos authentication and AES-256
SASL sealing. TLS and channel binding were not used or qualified by this run.
No policy was assigned or enforced and no central rule was linked.

Independent teardown searched both domain and configuration naming contexts on
both DCs for all six GUIDs and ownership markers, verified exact server policy
baselines, and confirmed retirement of the protected actor credential. Public
journals remain intact. The Server 2025 VMs retain their original Running states.

Raw results, source snapshots, executed host/controller sources and build/input
ledgers are under
`portable-conditional-expression-evidence/server2025/windows-6acd7e1`.
The ledger records exact bytes. Every one of the 4,254 canonical build inputs was
checked against its Git blob and rechecked after building both collectors.
The source-freezer and build-controller copies were collected after their calls;
they are not pre-execution self-attestations. SDK test executables omit a VCS
stamp; the collector checked its explicit source revision label.

This qualifies one client/server cell. Remaining applicable Linux/Windows runs
against Server 2016/2019/2022/2025 are tracked in #198. It does not qualify SDK-06's
atomic ACL workflows, another architecture, or a provider release.
