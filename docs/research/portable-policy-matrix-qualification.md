# Portable policy integration qualification matrix

Frozen SDK source `6acd7e15e8ad6e889eef9c04486714167804b56e`, built with Go 1.27.4,
passes the complete applicable Windows/Linux amd64 matrix for SDK-08. Each cell
uses a fresh AES actor and four separate, GUID-recorded, unassigned/unlinked
policy objects. Normal public Dial and service calls are used without wrappers.

| Server | Windows | Linux |
| --- | --- | --- |
| 2016 | 6/6 | 6/6 |
| 2019 | 6/6 | 6/6 |
| 2022 | 6/6 | 6/6 |
| 2025 | 6/6 | 6/6 |

The 48 cases comprise 16 accepted updates with exact readback, 16 actual LDAP 50
permission refusals and 16 local malformed-input refusals with unchanged values.
Local invalid-input refusals are not server validation evidence. The accepted
updates exercise all five binary authentication-policy descriptor properties and
central current/proposed/history/resource-condition text.

Every cell reports complete mutual Kerberos AES-256 SASL sealing. These runs do
not use or qualify TLS/CBT. No authentication policy is assigned or enforced and
no central rule is linked. There are no global ACL or claims-definition changes.

Independent cleanup on both DCs checks all six GUIDs and ownership markers in
both domain and configuration naming contexts, exact original authentication
policy values, and protected actor credential retirement. Server 2016/2019/2022
trios return to their original Off states; Server 2025 retains its original
Running state. Linux returns to its Server 2025 private profile/Running baseline
and exact original resolver link. The Server 2016 public control cache is retired.

The temporary direct-DNS modes on Linux16/22 keep the same DC nameservers/search
domain; their exact change and restoration sources are retained. Server 2016
control staging uses public-only ISO media, verified primary/Joliet labels and
full executable hashes, with exact DVD/controller/disk/NIC restoration. These
are lab orchestration, not an SDK runtime gateway.

Raw results and source/build/binary ledgers live under
`portable-conditional-expression-evidence/server*/{windows,linux}-6acd7e1`.
Public setup/restoration sources and journals live under `matrix-setup`.
Recorded hashes apply to exact Git blobs; private credentials, executables and
ISO/VM payloads are excluded. Canonical build inputs match their Git objects;
test executables omit a VCS stamp and validate their explicit source label.
Build-controller copies were collected after execution, as their ledgers state.

The existing native corpus and actual portable LDAP wire tests remain in merged
implementation #197; they cover unsupported/malformed inputs and partial/lost
outcomes. This matrix completes #198's remaining applicable integration evidence.
It does not qualify SDK-06 atomic ACL workflows, another architecture, portable
RPC, or the provider release.
