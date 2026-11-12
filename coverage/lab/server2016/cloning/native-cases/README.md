# Server 2016 cloning qualification

The reviewed native SDK passed 25 custom-list cases and five generation cases
on the owned Windows Server 2016 AMD64 DC at **12/11/2026 20:24:48** (UTC).
The OS build was `14393.693`, AD module `1.0.0.0`, module DLL `10.0.14393.0`.

The [reference report](reference.json) retains both observers' results, input
bytes, native output, default list/schema bytes, and cleanup evidence. Two owned
program records added one `Program` and one `WoW64Program`, both with a Unicode
and XML-special display name. Exclusion counts were **15 before, 17 with the
fixtures, and 15 after cleanup**. The service cases selected `ClipSVC` from the
actual baseline. The final inventory exactly matched the original multiset.

The custom cases cover name/type casing, literal wildcards, whitespace,
duplicates, both registry views, UTF-16, and malformed XML. Wrong root/namespace
cases explicitly expect the SDK's typed validation error where this PowerShell
build ignores the file. Other malformed cases compare validation outcomes,
not identical error contracts. These differences are not full cmdlet parity.

New-file and explicit-overwrite generation both succeeded. Each SDK/reference
pair was byte-identical, 1635 bytes, and validated against the captured Microsoft
XSD. Existing-file writes without overwrite and an unconfigured alternate
directory were rejected with their original bytes preserved. The runner gates
success on expected outcomes, semantic comparison, and raw byte equality.
The [import audit](import-audit.json) independently checks both successful pairs
and every copied artifact hash.

The [host journal](qualification.json) records exact VM/switch identities,
contained disks, a private network, fixed 4 GB startup memory, bounded owned
jobs, and per-profile locking. The originally stopped DC was gracefully
returned to **Off**. Guest/staging cleanup passed; the default list and unrelated
sentinel were unchanged. Any initial readiness failures remain in the journal;
the mutating fixture itself was not retried.

The native executable SHA-256 is
`929A2560DB4D89713044E0E073546CD8E06448D39393230C5904AA6915AF8248`.
Its archived source is `34b043bc69463fe0b4df32bceac3a1050e952a7b`, with production
code unchanged from `bfc8f8adf6af90fc5ca93c5aee6ae7a58ce8a876`.
Exact source/build/host/guest/report hashes are retained in the captured files.
These scripts are historical run snapshots with fixed lab identities, not
general provisioning entry points.

This qualifies these scenarios on this build. Live ACL-denial qualification
remains tracked in [#77](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/77);
offline size/media failure tests and broader native architecture qualification
remain distinct from this evidence.