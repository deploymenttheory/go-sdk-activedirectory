# Corrected OS resolver build

Actual source: `7c69c15ad3b959a76fe761e917dd11a55d93468e`.

The source proof indexes 4,369 tracked raw Git inputs, including 895 Go/module
inputs. Binary `git cat-file --batch` and an independent second read verified
the ZIP and extracted build bytes. The public Windows/amd64 and Linux/amd64
Go1.27.4 collectors were built from that exact tree with the source linker label,
`-mod=readonly -buildvcs=false -trimpath`. Their hashes and build metadata are
retained. No clean/dirty VCS stamp is claimed.

The production lookup uses the standard library's normal OS DNS selection.
Private buffered query completion bounds the caller's aggregate wait while the
OS may retain a cancelled native query until it returns. Late results cannot
mutate returned observations or make incomplete DNS results selectable.

Full Windows tests/vet/adcoverage151/tidy/configured diff lint and
Linux/macOS/WindowsARM64 builds pass. The retained local Windows preflight only
checks an invalid-domain refusal and matching source label before DNS; it is
not a live DNS/authentication result. Canonical Linux race is separately queued.
No live matrix cell is claimed here. The original pre-authentication cd15 live
failure is retained under `../failed-live-cd15/`, and red/green ownership tests
under `../os-resolver-regression/`. Fresh actual public-path Windows/Linux ×
Server2016/2019/2022/2025 qualification remains required under #175.

Later documentation/evidence commits do not relabel these binaries or claim all
current tracked bytes equal this build source. Indexed capture bytes are
preserved through the repository's evidence attributes.
