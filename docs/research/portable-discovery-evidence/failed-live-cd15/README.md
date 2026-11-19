# Windows Server 2025 discovery failure before authentication

Actual public Windows/amd64 Go1.27.4 collector source
`cd15bbacd32180479b07d1bd9e5edc5fc20048a9`, run
`sdk10-p25-20261119t005405075z`, exited1 with an incomplete SRV lookup.
It returned no DNS records, authenticated identity or topology projections.
This record qualifies no discovery/authentication matrix cell.

Independent read-only Windows DNS observation resolves the exact SRV query to
both owned controllers on389. The member has configured private DNS and zero
IPv4 default routes. No network, DNS, account, ACL, policy or service setting
was changed. Existing protected Administrator credentials were supplied only
through encrypted PSDirect/private stdin; authentication was never reached.

The production lookup forces `net.Resolver.PreferGo`. The exact installed
Go1.27.4 source retained here skips DNS adapters without a gateway. This is the
causal hypothesis to reproduce and correct before a fresh-source live run;
the original failed result must not be relabelled as passing.
Primary references: [Go DNS adapter selection](https://go.dev/src/net/dnsconfig_windows.go)
and [Go Windows resolver selection](https://go.dev/src/net/lookup_windows.go).
Source hashes bind the installed version separately from the current website.

The first read-only observation controller used a native route query which
throws when zero matching default routes exist; its source is retained as
`independent-os-dns-source.ps1.txt`. The v2 source enumerates routes then filters
and produced the independent report. Neither invokes the SDK or changes state.
Byte-preserved public originals are indexed by `artifact-hashes.json`.
