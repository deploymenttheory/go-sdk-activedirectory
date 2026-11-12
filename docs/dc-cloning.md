# Local DC cloning inclusion lists

`dccloning` reads the local AD DS domain controller's services and installed
programs through Win32 APIs. Runtime execution needs Windows amd64 or arm64;
there is no PowerShell, RSAT, LDAP connection, or remote-agent dependency.
Portable XML functions and types build on other Go platforms.

```go
result, err := dccloning.Inspect(ctx)
if err != nil {
    // result.Entries may contain valid partial data. Do not treat it as complete.
    return err
}
for _, entry := range result.Entries {
    fmt.Printf("%s: %s\n", entry.Type, entry.Name)
}
```

The kinds are `Service` (SCM key name), `Program` (64-bit Uninstall
`DisplayName`), and `WoW64Program` (32-bit Uninstall `DisplayName`). An installed
item with the same display name in both registry views remains two typed items.
Names and known type tokens compare case-insensitively; inclusion names trim
surrounding XML whitespace. Names are literal, without wildcard expansion.
`DisplayVersion` is not an inclusion-list field. The package reads the live
system default list and the first custom list in Windows' documented search
order: configured `AllowListFolder`, DSA working directory, Windows NTDS
directory, then writable removable-drive roots by drive letter.
Candidates are resolved in that order as needed. Discovery stops at the first
custom file, so failures on lower-priority removable media do not block it.
Generation resolves only through its explicit output directory; failures needed
to establish that directory or an earlier file still stop the operation.

`Result.Complete` means that all observable sources were enumerated without a
reported failure. `AuthorizationLimited` remains true: Windows may silently omit
services the caller cannot query. An empty result does not certify cloning
safety. Vendor assessment and the other DC-cloning prerequisites remain the
administrator's responsibility. Reads are not a transactional snapshot of
simultaneously changing services, registry keys, and files.

Once the excluded applications have been assessed, generate the custom file at
an explicit supported directory:

```go
generated, err := dccloning.Generate(ctx, dccloning.GenerateOptions{
    Directory: `C:\Windows\NTDS`,
    Overwrite: false,
})
if err != nil {
    // Inspect generated.Outcome; an uncertain publication is never retried.
    return err
}
fmt.Println(generated.Path, generated.Outcome)
```

Generation compares the inventory against the **default list only**, preserving
all installed non-default entries even if a previous custom list includes them.
It writes only `CustomDCCloneAllowList.xml`. An empty default-only delta produces
`NotWritten` and leaves existing output untouched. Other results are `Written`
or `WriteUncertain`; an error may accompany any outcome, including cleanup
failure after publication. A complete temporary file is prepared in the output
directory, flushed, closed, and published once. Unrelated files are untouched.
Overwrite permission does not bypass a higher-priority existing custom list.
An arbitrary directory outside the configured search locations is rejected.

`ParseCustomAllowList`, `ParseDefaultAllowList`, and `EncodeCustomAllowList` work
without Windows. The custom root has namespace
`uri:microsoft.com:schemas:CustomDCCloneAllowList`; `Allow`, `Name`, and `Type`
children have no namespace. The parser accepts UTF-8 and UTF-16 with a BOM,
preserves duplicate records, and rejects malformed content, unsupported types,
empty names, DTDs, extra fields, and multiple documents. Lists are bounded to
8 MiB, with explicit errors for oversized files; data is never silently truncated.
The encoded document has the same limit, including escaped text and CRLF bytes.
An oversized generation fails with `ErrInvalidList` and `NotWritten` before
creating a temporary file, preserving any existing output.

Errors support `errors.Is` with `ErrUnsupported`, `ErrNotDomainController`,
`ErrInvalidList`, `ErrInvalidPath`, `ErrIncomplete`, `ErrOutputExists`, and
`ErrPrecedence`. `errors.As` can retrieve `*NativeError` with the operation,
numeric Windows code, and underlying error. Cancellation is observed between
native calls; it does not free resources while a synchronous call is active.

Build the runnable example on any development platform:

```text
GOOS=windows GOARCH=amd64 go build -o dccloning.exe ./examples/dccloning
```

On Windows PowerShell, set `$env:GOOS='windows'` and `$env:GOARCH='amd64'` before
running `go build`. Execute on the local DC:

```text
dccloning.exe
dccloning.exe -generate-directory C:\Windows\NTDS
dccloning.exe -generate-directory C:\Windows\NTDS -overwrite
```

The example emits JSON, retains partial result data, and uses a nonzero exit
status on error. `-overwrite` requires an explicit generation directory.

The read-only [reference harness](../scripts/lab/reference-cloning.ps1) runs
locally inside a disposable DC and compares typed inventory with PowerShell.
Supply `-NativeExecutable`, its `-ExpectedExecutableSHA256`,
`-ExpectedComputer`, and a new `-OutputPath`. The report records OS/module and
binary versions and preserves duplicate entries in the comparison. Generation
and controlled registry/XML cases are captured separately in the research
evidence. The historical probe scripts omitted the full disk and switch
ownership guards required for lab execution. They are retained as evidence
bytes and must not be reused directly; subsequent qualification requires the
corrected runner with complete ownership checks.
The harness bounds the native child with `-TimeoutSeconds` (default 60), waits
in short intervals, terminates only that owned process on expiry, and retains
structured failure reports for nonzero exits, invalid JSON, and timeout. Its
local helper test covers success, empty inventory, malformed output, failure,
and bounded termination without accessing a DC:

```text
go build -o cloning-helper.exe ./scripts/lab/testdata/cloning-helper
powershell.exe -File scripts/lab/test-reference-cloning-harness.ps1 -TestHelper .\cloning-helper.exe -OutputDirectory .\new-harness-results
```

The opt-in `TestNativeResourceCycles` test wraps the real per-call native
functions and runs the inspection core 100 times on the owned DC. Supply an
absolute, new report path through `ADSDK_CLONING_RESOURCE_REFERENCE` and run
the Windows test binary with `'-test.run=^TestNativeResourceCycles$'
'-test.timeout=2m'` (quote the flags in PowerShell). Its 90-second context bounds
work between native calls.
The JSON reports acquisition/release counts and zero outstanding role buffers,
registry keys, and SCM handles after every successful cycle. Failed releases
remain outstanding, and failures retain their report. Existing report files
are never overwritten. This measures native ownership, not working-set or Go
heap stability; the lab runner must supply ownership and version provenance.

The initial implementation merged through PR #75 and closed
[issue #54](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/54).
Remaining qualification is tracked in
[issue #77](https://github.com/deploymenttheory/go-sdk-activedirectory/issues/77).
The [research and evidence](research/dc-cloning-exclusions.md) distinguish
captured Server 2025 behavior from unqualified server versions and edge cases.
The [native baseline](../coverage/lab/server2025/cloning/baseline/README.md)
matches all 28 typed PowerShell exclusions on Server 2025 build 26100.32230.
That baseline belongs to source commit `de95729`. A
[fresh native fixture run](../coverage/lab/server2025/cloning/native-cases/README.md)
qualifies the build containing the later fixes at `bfc8f8a`: 25 custom
cases and five generation cases passed, including both registry views and two
successful documents byte-identical to PowerShell. Cleanup restored the original
28 exclusions. A separate [100-cycle native resource test](../coverage/lab/server2025/cloning/native-resources/README.md)
records balanced real role-buffer, registry-handle, and service-manager ownership
after every cycle. The lower-priority media failures and encoded-size boundaries
are covered by offline regressions, not these live fixtures.

The same reviewed native executable also passed 25 custom-list and five
generation cases on each older server build. Both successful XML documents on
each build were byte-identical to its installed PowerShell output, and all
three fixtures restored their original inventory and powered-off state.

| Server evidence | OS build | AD module | Exclusions before / fixture / after | Generated bytes |
| --- | --- | --- | --- | --- |
| [2016](../coverage/lab/server2016/cloning/native-cases/README.md) | 14393.693 | 1.0.0.0 | 15 / 17 / 15 | 1,635 |
| [2019](../coverage/lab/server2019/cloning/native-cases/README.md) | 17763.3650 | 1.0.1.0 | 21 / 23 / 21 | 2,089 |
| [2022](../coverage/lab/server2022/cloning/native-cases/README.md) | 20348.587 | 1.0.1.0 | 21 / 23 / 21 | 2,089 |

These are scenario-specific results on recorded AMD64 builds. Live access
failures remain pending. Cross-compilation is not evidence of native ARM64 DC
execution, and these results do not qualify every host/permission/role variant.

Two deliberate validation differences matter: the observed PowerShell build
silently ignores a wrong custom root/namespace, whereas this API returns
`ErrInvalidList`; PowerShell's null-argument exception for several malformed
files is represented by that same typed validation error. Neither behavior is
reported as a native Windows status or successful empty discovery.
