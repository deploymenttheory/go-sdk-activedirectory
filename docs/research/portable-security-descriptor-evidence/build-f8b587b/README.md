# Actual f8 descriptor collector build inputs

The logical source revision is [f8b587bf7f05d53d18638c4f53e69508cad0f5ed](https://github.com/deploymenttheory/go-sdk-activedirectory/commit/f8b587bf7f05d53d18638c4f53e69508cad0f5ed). Both Windows/amd64 and Linux/amd64 binaries were built with Go 1.27.4 from the same actual Windows Git archive variant. The retained manifests hash the unchanged archived/extracted bytes before and after building. They do **not** establish raw committed Git-blob identity.

Independent [archive/Git comparison](archive-git-blob-comparison.json) confirms all 3,011 regular archive files match the original source ledger. Of these, 1,866 are byte-identical to committed Git blobs; 1,145 differ only by CRLF/LF, including all 862 Go/module inputs. There are zero other differences. No hash-time normalization was applied to the actual build ledger. The [audit source](verify-archive.py.txt) can be rerun against the preserved archive and source repository; it reads evidence without rewriting it.

| Artifact | SHA-256 |
| --- | --- |
| Exact source archive | `34f1bfda0ea819ac0afb9a14e5809b2a8bd6b2b89fb510b5321343b2538e17d9` |
| Source-provenance JSON | `dd613767a1e8fd04abf580cbe17a6b098db5c3d452d8b7f70b67faf33192f1b0` |
| Windows/amd64 test executable | `fe60f065cf9fa7dc548d3faa541cf70774f763b6811256c1085ba4eed86c62c8` |
| Linux/amd64 test executable | `4b624ef322b9941546aa4c88e5347a886a39a36693e4e1eb5538e4113dae331f` |

The source archive and executable payloads remain retained in the lab controller's build artifacts rather than the SDK source distribution. Their manifests, exact buildinfo records and input hashes are public here. These test executables omit VCS stamps; the linker label prevents attributing results to another requested revision, while the independent archive/binary ledgers establish the actual build basis. The Linux executable's presence is build evidence only; this directory does not claim a Linux AD run.
