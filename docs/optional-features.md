# Optional features

`Client.OptionalFeatures` returns typed feature/object GUIDs, raw scope flags,
disablability, optional required levels and enabled-scope DNs. Query by feature
GUID, object GUID, name, DN or LDAP filter; the zero query reads all features.
Read errors retain partial results. `Complete`, `LimitReached`, raw values and
`EnabledScopesState` distinguish completion, caller limits, missing attributes
and truncated ranges. Missing values stay unknown. Backlink range continuation
is pending; ranges return `ErrIncompleteResult` with their raw observations.

```go
features, err := client.OptionalFeatures(ctx, ad.OptionalFeatureQuery{})
// Inspect err, features.Complete, and each EnabledScopesState.

result, err := client.EnableOptionalFeature(ctx, ad.OptionalFeatureChangeRequest{
    FeatureGUID: ad.OptionalFeatureRecycleBinGUID,
    Scope: ad.OptionalFeatureForest,
    ScopeDN: "CN=Partitions,CN=Configuration,DC=example,DC=test",
    AcknowledgeIrreversible: true,
})
// result.WriteState survives a failed readback. Never replay an uncertain write.
```

Enabling Recycle Bin in this example cannot be undone. Use a disposable fixture
until live qualification is complete. `DisableOptionalFeature` accepts the same
request shape but rejects irreversible features before submission; the
acknowledgement cannot bypass that rejection. Recycle Bin, PAM and Database 32K
Pages remain irreversible even if their reported disablable flag is inconsistent.

Forest/configuration-set scope requires the Partitions object's DN and an
existing connection to its Domain Naming Master. Domain scope uses this AD DS
server's default domain NC; server scope uses its DSA DN. `Config.Partition`
cannot redirect these writes. AD LDS supports configuration/server scopes,
subject to feature flags and observed prerequisites; domain scope is rejected.
An unknown, unsynchronized or read-only target is rejected. Required levels are
checked; the 32K feature additionally checks every enumerated DSA's page size.
The server remains responsible for final capability and permission enforcement.

Native WinLDAP performs one rootDSE ADD via go-bindings-win32. The client gate
covers preflight, submission and readback. There is no PowerShell runtime,
agent, role transfer, reconnect, referral following, retry or rollback. An
unknown response retires the native session and returns
`ErrOptionalFeatureUncertain`; reconcile independently before another write.
LDAP codes and diagnostics remain accessible through `errors.As`.

An accepted response remains `OptionalFeatureWriteAccepted` if readback fails.
`Verified` only describes the local scope link, not forest convergence. If the
enabled-link attribute disappears after disabling the last feature, omission
cannot distinguish empty from inaccessible: the write is accepted but readback
is unverified. No compensating write is attempted.

## Runnable example and validation

On Windows amd64/arm64, the example uses the current Windows identity:

```powershell
go run ./examples/optionalfeatures -server dc1.example.test
go run ./examples/optionalfeatures -server naming-master.example.test -action enable `
  -feature-guid 766ddcd8-acd0-445e-f3b9-a7f9b6744f2a -scope ForestOrConfigurationSet `
  -scope-dn 'CN=Partitions,CN=Configuration,DC=example,DC=test' -acknowledge-irreversible
```

The second command performs the irreversible change. The SDK library also
supports the existing explicit-credential/TLS configuration. AD LDS uses its
instance LDAP port. Non-Windows builds compile and return the established
unsupported-native error when dialing.

`go test ./...` covers projection, unknown/malformed/missing/ranged values,
scope/owner/level/irreversibility guards, cancellation, partial native errors,
uncertainty and accepted-but-unverified outcomes. The Windows native test checks
the exact UTF-8 rootDSE operation and buffer/message ownership through the shared
Modify boundary. Shared native tests cover submission, cancellation, response
parsing, transport failures, cleanup and session retirement.

The reference comparison has offline positive and corruption tests. Run
`powershell.exe -NoProfile -File scripts/lab/test-optional-feature-reference.ps1
-ArtifactRoot <existing-temp-directory>` and the equivalent `pwsh` command in
fresh processes. They fake the external cmdlet boundary, perform no AD reads,
and retain their JSON reports in a new directory under the supplied path.

The live test requires `-tags integration` and
`AD_OPTIONAL_FEATURE_LAB_TARGET`, `AD_OPTIONAL_FEATURE_LAB_CONFIGURATION_GUID`
(the existing configuration object's GUID), and optionally `..._PORT`. It
defaults to a positive read. For a separately authorized disposable write, set
`..._ACTION=enable` or `disable`, `..._GUID`, `..._SCOPE`, `..._SCOPE_DN`, and
`..._ALLOW_CHANGES=disposable-directory`. Irreversible enables additionally need
`..._IRREVERSIBLE=acknowledge-irreversible`. `..._EXPECT` accepts `accepted`,
`prerequisite`, `scope`, `irreversible`, `permission` or `role`:

```powershell
go test -tags integration -run '^TestOptionalFeatureLive$' -v .
```

The integration test submits at most one write and does not provision, repair or
restore the fixture. Keep success enables and reference enables in separate
disposable configurations: enabling an irreversible feature twice is not a
valid differential test. Failed prerequisite/scope/disable cases require the
corresponding prepared state; the permission case requires an ordinary identity.

For independent read comparison, export the example's successful read JSON and
run `scripts/lab/reference-optional-features.ps1 -Server <endpoint>
-ConfigurationGUID <pinned-guid> -OutputPath <fresh-file> -NativeJSON <sdk-json>`.
The script only reads, pins configuration identity, compares GUIDs/flags/levels/
enabled scopes, and records collector OS, PowerShell/module versions and directory
functional levels. Actual server OS/build and source/binary pins must be retained
by the outer lab runner. It does not count empty/failed native collections as
success or imply full qualification.

Issue #29 remains open: live supported enable, insufficient prerequisites,
invalid scope, forbidden disable and permissions; applicable AD LDS and Server
2016/2019/2022/2025 evidence; and full ranged enabled-scope continuation remain
pending. No live directory operation was performed during implementation.

See [the protocol research](research/optional-features-contract.md).
