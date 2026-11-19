# Canonical d52 qualification source and first live cell

Actual source: `d52ac60a8300fdab43d7bc6db718c369efbdc80e`.
This evidence qualifies only the recorded Windows amd64 administrative-password
server-scope reads against Server 2025, with an independent native reference.
The complete SDK07 qualification remains pending.

`build/` retains the root agent's canonical source/binary manifests and build
information. Binary Git object reads independently verify all 4,419 source
hashes, every canonical ZIP entry and both binary hashes. These public binaries
omit a VCS stamp; provenance comes from the exact embedded source label and the
independently verified source/binary manifests. The retained live cell used the
canonical Windows binary; the Linux binary has build coverage and no live result
in this capture. Earlier EOL-converted archives/builds remain nonfinal; their
[additive correction](../source-basis-reconciliation/README.md) remains intact.

`offline/canonical-race-mit.log.txt` is the exact full canonical Go1.27.4 Linux
race log. Both AES17/18 independent MIT DCE and actual protected RPC lifecycle
tests ran and passed. The runner owner reported terminal exit zero. This offline
test peer is not part of SDK runtime or a Windows execution gateway.

`server2025/windows-{portable,native}-password/` retains exact public reports,
process envelopes, binary transfers, execution intents, independently observed
service identities and executed orchestration sources. Both process envelopes
have exit zero and their stdout JSON matches the corresponding result file.
No credential payload, private key, keytab or cache is retained here.

The independent comparison passed 85 checks: stable identities, flags, statuses,
nullability, array order and counts agree. Partners contain two rows, failures
one existing link-status row (8524, count zero), and queue an observed empty
collection. Every actual temporal USN/time difference is retained explicitly;
the reads were sequential, not an atomic snapshot. All six portable EPM/DRS
stage observations report AES18/256-bit, mutual authentication, header signing,
confidentiality, complete protection and a future service-ticket expiry.

`server2025/preflight-only-aborted/` preserves the earlier caller source and
metadata. Its case-sensitive registered-LDAP-principal selector did not match
the DC hostname's capitalization. The corrected caller selects the actual
registered literal with case-insensitive host comparison. No SDK process was
started in that aborted capture; it is not an SDK authentication failure.

`artifact-index.json` records exact bytes/SHA256 for every retained file except
itself. `canonical-input-validation.py.txt` is the executed host-only retention
and canonical verification source. Historical records are never rewritten.
