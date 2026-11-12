# First access qualification attempt: fixture classifier failure

This run **failed** on Server 2025 build `26100.32230`, AD module `1.0.1.0`,
at 2026-11-12 20:43 UTC. The original reports remain unchanged.

Four positive controls passed: the 28-entry baseline, both program views
(30 entries), a readable custom list (29 entries), and overwrite generation.
The first denial case then failed its independent .NET probe classification.
`RegistryKey.OpenSubKey` threw a nested `System.Security.SecurityException`,
but the fixture accepted only exceptions whose HRESULT low word was 5.

Microsoft documents `SecurityException` for missing requested permissions as
well as invalid rights in this overload. The fixture supplied the fixed valid
`RegistryRights.QueryValues` constant and had established a readable positive
control. The recorded HRESULT `-2146233078` is a .NET exception code; its low
word `5386` is not evidence of a native Windows status.
[RegistryKey.OpenSubKey contract](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registrykey.opensubkey?view=netframework-4.8.1)

The native SDK independently reported `RegOpenKeyExW(program)` status **5**,
permission and incomplete-result errors, and the expected partial inventory:
the denied `Program` was absent while the same-named `WoW64Program` and other
readable entries remained. Re-evaluating the unchanged historical
`Test-RegistryDenial` predicate against the captured data returns true. This
does not turn the failed overall run into a pass. The custom-file and output
denial cases were not reached.

PowerShell's cmdlet returned an `ArgumentNullException` naming `xmlContent`
under this registry denial; that independent observation is retained rather
than interpreted as native status 5.

ACLs, registry keys, the inclusion-folder override, and the original inventory
were restored. All owned jobs completed; final child state was certain. The
host verified and copied the raw evidence before removing the owned staging
directory. The [host report](qualification.json), [job journal](run-journal.json),
and [guest report](native-access.json) retain those facts and the failed result.

All 31 original artifacts, including intermediate checkpoints and native
outputs, are copied byte-for-byte; [import-audit.json](import-audit.json) records
their hashes and lengths. The original Go helper is retained as `.go.txt` so
the captured source does not become an SDK build package; its bytes are unchanged.
The helper used archived SDK source `34b043bc` with
unchanged production code from the merged implementation. These historical
scripts have fixed lab identities and are not general lab entry points.

Correcting the classifier requires a separately identified, reviewed run.
The first attempt is not overwritten or automatically replayed. Qualification
remains open under [#77](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/77).
