# Native custom-list and XML-generation qualification

The reviewed SDK commit `bfc8f8adf6af90fc5ca93c5aee6ae7a58ce8a876` passed
25 custom-list cases and five generation cases on the owned Server 2025 DC at
2026-11-12 19:31 UTC. The environment was Windows Server build `26100.32230`,
AMD64, with Active Directory module DLL `10.0.26100.7309`.

The [reference report](reference.json) contains both tools' results. Two temporary
Uninstall records added one `Program` and one `WoW64Program` with the same display
name, including a non-ASCII character and XML metacharacters. Assertions required
both typed records and the unchanged baseline before custom-list tests began.
The exclusion counts were **28 before, 30 with the programs, and 28 after cleanup**.

The custom cases exercise service/program name and type matching, whitespace,
literal wildcards, duplicate records, UTF-16, malformed content, and independent
registry views. They include two documented validation differences: the SDK
rejects wrong roots/namespaces that this PowerShell build ignores. Malformed
files producing PowerShell's null-argument wrapper error produce an SDK
`ErrInvalidList`. These are expected validation outcomes, not identical error
contracts or a claim of full cmdlet parity.

| Generation scenario | Required and observed outcome |
| --- | --- |
| New file, without overwrite | Both succeed; XML bytes are identical |
| Existing seed, without overwrite | Both reject; original bytes preserved |
| Existing seed, with overwrite | Both succeed; XML bytes are identical |
| Existing generated file, without overwrite | Both reject; original bytes preserved |
| Unconfigured alternate directory, with overwrite | Both reject; no file created |

Both successful documents validate against the DC's Microsoft XSD and contain
all 30 default-only exclusions. The comparisons start from identical file bytes.
Explicit expected outcomes prevent two failures from passing a success case.
The historical harness recorded byte equality but gated success on semantic XML
equality. The retained [post-run audit](byte-audit.json) separately asserts the
byte lengths and SHA-256 equality of both successful pairs. Each document is
2,604 bytes. Future harness versions additionally require byte equality in
the case result; the historical source bytes remain unchanged.
The [offline checks](offline-checks.json) exercise four multiset comparisons,
12 VM ownership guard cases, and three generation-failure regressions.

The default list and unrelated sentinel hashes remained unchanged. Temporary
program keys, the `AllowListFolder` override, fixture directories, staging files,
native processes, and remoting session were cleaned up. The
[qualification report](qualification.json) records the VM identity and the
private-switch, adapter, and owned-disk guards applied before guest actions.

| Provenance | SHA-256 |
| --- | --- |
| Archived source | `C635615C4D1C63F057D97F53B031668B6A22CD252A1F71D0933971369EEB1927` |
| Native executable | `929A2560DB4D89713044E0E073546CD8E06448D39393230C5904AA6915AF8248` |
| Guest harness | `2505CB02D4D2A98E7251202599D999CF9B52029760EB9DC00E397D58268BFE89` |
| Host runner | `F0AA155E6C6E8BE62D809B9ADB3AAB778AB65E608D790FA59A3E83FBD701E2EA` |
| Reference report | `4504158D358E0B1542AAB424C0295113C74ECB4AFB4D7D4EB6F76250ACA8BF00` |
| Qualification report | `FC16516FDD0EB754DB94B53CC0E08F784612D474CB5354B6EA0E91D3D3399D80` |

The [build manifest](build.json) and exact host/guest/build/test script snapshots accompany the reports. They are
historical qualification sources with pinned lab identities and paths, not
general provisioning entry points. The source was archived from the reviewed
commit and compiled with Go 1.26.5, Windows amd64, CGO disabled,
`-mod=readonly -trimpath -buildvcs=false`. Working-tree edits were excluded.
Git attributes preserve the captured bytes and their digests.

Access-denied scenarios, repeated native resource cycles, and older-server
comparisons remain separate qualification work. This run does not exercise an
empty default-only delta, removable-media hardware, or a native ARM64 DC, and
does not close issue #54 or promote untested coverage scenarios.
