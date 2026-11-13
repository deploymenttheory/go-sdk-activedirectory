# Server 2025 disposable unsupported-host observation

The SDK rejected the existing unjoined `ADSDK25MEM` guest with typed
`ErrNotDomainController` on 2026-11-13. Independent CIM observations report
standalone-server role 2, `PartOfDomain=false`, Windows Server 2025 Standard
Evaluation build 26100, and PowerShell 5.1.26100.7462. The one native child
completed with exit code 1, `Outcome=not_written`, `ChecksSkipped=false`,
incomplete prerequisites and no output files. No directory endpoint was observed.

The host held the canonical profile mutex and verified the existing VM, its
differencing disk/base disk, and private switch ownership. It temporarily
started that member and restored its initial **Off** state using normal shutdown
after known child/remoting completion. All four owned host jobs completed and
were removed; the terminal journal at 2026-11-13T00:00:34.4433629Z records success,
power restoration and no uncertainty. No join, RSAT installation, lab rebuild,
configured-flag change, directory write, forced shutdown or clone occurred.
Owned diagnostic staging remains preserved.

The executed SDK commit is `59346e9641feada4915a3313273ee2fc845bdbeb`, the PR83
head subsequently squash merged as `90f22fe9558f02c93fd9f8a1fb1a9ba306e05d77`.
The helper SHA-256 is
`09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957`.
Build manifests and helper source snapshots retain the actual build identity.

`import-audit.json` records 23 copied artifacts with source paths, lengths and
SHA-256 digests. The importer verifies all eight raw guest captures against the
original PSDirect envelope, process and terminal job records, source archive,
helper binary and manifest chain. The original envelope, executable and archive
remain on H: with their hashes recorded; base64 transport is not duplicated here.
`.gitattributes` preserves bytes. Go snapshots use `.go.txt` filenames.

The retained regression record shows the pre-fix shutdown assertion failed on
PS5.1 and PS7 when a completed wait returned while retaining job-removal
uncertainty. Both revised offline suites passed 72 checks. The executed host
rejects that uncertainty after every wait and before parsing a guest result;
a returned payload cannot clear an earlier uncertain state. The red record is
a recorded test outcome and digest, not a snapshot of the superseded test source.

This closes the disposable-profile unsupported-host observation required by
[#55](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/55).
Together with the retained offline, invalid-network and successful online
comparisons, the feature acceptance is met; see the
[acceptance mapping](../../../../../docs/dc-clone-configuration.md#feature-acceptance).
The full compatibility/variant matrix remains under
[#57](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/57).
Broader discovery work in #78 is separate. Coverage qualification states remain
unchanged; one standalone-server rejection does not qualify every non-DC role.
