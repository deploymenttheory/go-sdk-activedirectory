# Corrected explicit-peer source and public collectors

Actual source: `ebb11a2aae28187c72ec0ea665bb5fe02aa451ed`.

This source fixes discovered topology peers being normalized against the
anchor LDAP principal. It retains the exact caller-selected per-peer service
identities and the transport-default topology port. The red/green fixtures are
retained separately under `../scope-principal-normalization/`; the original
actual D52 domain failure remains under `../failed-domain-d52/`.

Binary raw Git blobs were read through `git cat-file --batch`; an independent
second batch read checked every ZIP/extracted input byte-for-byte. All 4,474
tracked inputs, including 932 Go/module inputs, are indexed in the source proof.
The two public Go1.27.4 collectors were built from that exact extracted tree with
`-mod=readonly -buildvcs=false -trimpath` and the actual `main.buildRevision`
linker label. The binary manifest/build metadata preserve their exact hashes.
No VCS clean/dirty stamp is claimed. Later evidence-only commits do not relabel
these artifacts or claim every current tracked input matches the build.

Full Windows tests, vet, the 151-cmdlet inventory contract, configured diff lint
and Linux/macOS/WindowsARM64 builds passed before this freeze. Full canonical
Linux race and independent MIT17/18 interop verification is recorded separately
once terminal. No new live result is claimed here; the corrected runtime still
requires fresh applicable scope/credential/client/server qualification. This
proof does not close #172 or promote the earlier D52 server-scope result.
