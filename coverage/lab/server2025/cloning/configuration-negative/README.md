# Server 2025 offline clone configuration negative cases

This directory preserves a completed 19-case qualification from 2026-11-12.
The host wrapper reached terminal success at 22:01:09.2578338Z; all three owned
jobs completed and were removed, with no timeout, wrapper error, or guest
uncertainty. Guest staging was preserved. The raw summary reports completion,
no process/publication uncertainty or capture failure, and all cases passed.

There are **two positive controls and 17 invalid-input cases**, not 19 invalid
cases. Both controls (control-v4-static and control-four-v6-dns) wrote files
through the SDK and the reference. All 17 invalid cases returned the SDK's
invalid_configuration result and left no SDK output file.

| Classification | Cases | Meaning |
| --- | ---: | --- |
| Positive controls | 2 | SDK and reference both wrote configuration files. |
| Invalid; reference also wrote no file | 8 | Expected publication outcomes agree; error representations can differ. |
| Invalid; SDK stricter, reference wrote a file | 9 | Intentional validation differences, not SDK/reference equivalence. |

The eight invalid cases with no reference file are dynamic-with-static-fields,
static-missing-address, static-missing-mask, static-missing-dns, static-empty-dns,
dynamic-with-gateway, five-v4-dns, and five-v6-dns.

The nine intentional differences are malformed-ipv4-address, broadcast-address,
broadcast-gateway, noncontiguous-mask, static-without-family, static-v4-dns-only,
broadcast-dns, malformed-v4-dns, and malformed-v6-dns. The SDK rejects malformed
or broadcast addresses, noncontiguous masks, and incomplete static settings.
The reference serializes those address strings or selects another configuration
shape: no IPSettings for static-without-family, and dynamic IPv4 for
static-v4-dns-only. Each raw case records its exact expectations and difference.

Qualification provenance remains SDK source commit
4120ce5d13dd49de490cef67d41767ac3b409715, source archive SHA-256
1FA1A904FDEE8ED7F49428117C8215989F895E3EBCF7AC3554827248654C2E19,
and the helper-v2 manifest and source/test pins retained here. The later
c72c7b0a4a785f177a70f26729b7d9ffff140a46 discovery fix changes online locator
flag selection only; it is not the source revision executed by this offline
qualification. These results do not establish completion of broader issue #55.

The raw qualification ran on ADSDK25DC1, OS 10.0.26100.0, Windows PowerShell
5.1.26100.7462. Reference observations record ActiveDirectory module 1.0.1.0
and assembly 10.0.26100.7309. Every call used explicit Offline mode; these results
do not qualify online prerequisite checks or a domain-controller cloning run.

The import validates all 359 raw files against the qualification hash map,
captured-evidence.json, and the base64 capture-return.json envelope. The raw
summary must equal guest-return.json; per-case results, process completion,
stream hashes, and XML presence/bytes must corroborate it. Import-audit.json
records every copied artifact's source, original name, destination name, length,
and SHA-256. Captured bytes are unchanged; local .gitattributes disables text
conversion. Go source/test snapshots use .go.txt filenames to keep them outside
SDK package discovery. No executable binaries are imported.

The frozen host, guest, and bootstrap scripts are retained, together with the
matching offline 160-check reports for Windows PowerShell 5.1 and PowerShell 7.
These reports exercise local harness helpers and are separate from the actual
19-case guest qualification. The guest-harness test source is retained, but no
saved 83-check guest-harness report was available for import; no such retained
report is claimed. The helper-v2 source, tests, build manifest, and test/build
logs are also retained. This import performs no guest or AD operations and
changes no coverage states.
