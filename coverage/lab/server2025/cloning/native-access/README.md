# Native access-denial qualification

The separately identified v2 run **passed** on the owned Server 2025 AMD64 DC
at 2026-11-12 20:52 UTC: OS build `26100.32230`, AD module `1.0.1.0`.
The [original guest report](native-access.json) records four positive controls
and all three denial cases. The [host report](qualification.json) and
[job journal](run-journal.json) confirm bounded completion, artifact capture,
and staging removal.

| Owned denial | Native SDK result | Independent PowerShell observation |
| --- | --- | --- |
| Registry64 program key: QueryValues | `NativeError` for `RegOpenKeyExW(program)`, Windows status 5, permission plus incomplete error; readable entries and the same-named WoW64Program retained | Cmdlet throws `ArgumentNullException` naming `xmlContent` |
| Custom inclusion file: ReadData | Incomplete inspection with a permission error and underlying Windows errno 5; no exclusions presented as a successful empty result | Cmdlet throws `ArgumentNullException` naming `xmlContent` |
| Output folder: CreateFiles; existing output: WriteData | `NotWritten`, errno 5 while creating the owned temporary output; complete discovery retained and existing bytes unchanged | Cmdlet throws `UnauthorizedAccessException`; existing bytes unchanged |

The file errors are preserved as filesystem errors with an underlying Windows
errno; the helper does not invent a `NativeError` wrapper for them. These are
explicit SDK/PowerShell error-contract differences, not identical-error parity.

Controls established the original 28 exclusions, both program views (30), a
readable custom list (29), and successful overwrite generation. The exact
owned Registry64 read operation also succeeded before its ACL denial. This
distinguishes the observed .NET `SecurityException` from an invalid-rights
request. Native status-5 and partial-result assertions remain independent of
that probe. The [failed first attempt](../native-access-first-failed/README.md)
is retained unchanged; its classifier failure was not recategorized as a pass.

All denial probes, native output, and PowerShell observations were durably
checkpointed before ACL recovery. DACLs, owners, and groups were restored
exactly; SACLs were neither read nor modified. Registry fixtures and the
inclusion-folder override were removed. The default list, unrelated sentinel,
and original inventory were unchanged. All jobs completed, final child state
was certain, and the host verified raw hashes before deleting owned staging.

The access helper calls only public SDK APIs. Its executable SHA-256 is
`344BA3CFE0C91A95F89BB82F6B33506D13A64C2D7909965FC66C46B6C1E3F51A`;
helper source SHA-256 is
`14A06FC2075A8305A076284DDA0F25FD433A6AA9098332AEEF30A2EDED18F2EB`.
It was built from archived SDK commit `34b043bc69463fe0b4df32bceac3a1050e952a7b`.
The production cloning package, example, and module pins match merged commit
`025b7f29670c683abfdedff307ad273d4eaf9605`; later differences are test-only.

All **44 original artifacts** are retained byte-for-byte. The
[import audit](import-audit.json) records their original names, hashes, and
lengths. The captured Go source uses `.go.txt` to avoid becoming a build package.
These scripts are historical snapshots with fixed lab identities, not general
provisioning entry points. The included offline test script exercises the
guards, classification, and uncertainty paths without VM or ACL operations:

```powershell
powershell.exe -NoProfile -File coverage/lab/server2025/cloning/native-access/test-cloning-access-cases.ps1
```

It passed 183 checks on Windows PowerShell 5.1 before the run. Historical-run
paths intentionally reject replay. Broader role, token, architecture, and
additional server-build qualification remains distinct from these three cases.
