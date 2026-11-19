# Executed source-byte reconciliation

The original b7, fbca and d52 offline runs verified their archive hashes and all
extracted file hashes, and passed the recorded Go1.27.4 race/MIT tests. Independent
review subsequently found that `git archive` had applied checkout line-ending
conversions. The earlier claim that those bytes were raw committed Git objects is
withdrawn. This directory adds the correction; historical captures are unchanged.

| Executed source | Files compared | Exact | CRLF/LF only | Other changes |
| --- | ---: | ---: | ---: | ---: |
| b7ea9fa | 254 | 73 | 181 | 0 |
| fbca66d | 4,419 | 3,230 | 1,189 | 0 |
| d52ac60 | 4,419 | 3,230 | 1,189 | 0 |

Each audit uses `git ls-tree -r -z` and binary `git cat-file --batch`, checks
object/framing identities and compares actual preserved archive bytes. It records
canonical and executed hashes/sizes for every difference. The b7 snapshot has 173
differing Go/module paths; each complete snapshot has 891, including both module
manifests. No source normalization is performed by the audit.

The executed logs and original metadata are retained byte-for-byte, including
their superseded source-basis wording. Interpret them through this correction:
they establish only the recorded offline archive execution. Both AES17/18 MIT
tests actually ran; the independent acceptor was a local test process, never an
SDK runtime helper. No AD authorization or server-version claim follows.

The original d52 public binaries were withheld from live use and remain nonfinal.
Canonical qualification builds must read binary Git objects, verify actual build
bytes, and publish fresh source/binary identities. Do not relabel an earlier
archive run as that canonical build or as live qualification.

`artifact-index.json` records exact byte counts and SHA256 hashes for retained
audits, logs and the executed audit tool. Existing red cases and the isolated
candidate evidence remain in their original directories.
