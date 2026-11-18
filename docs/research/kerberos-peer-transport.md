# Pre-staged public SASL peer transport

The Server2016 qualification run started at 2026-11-18T21:07:51Z completed 65 of 84 cases before its first Linux signing relay case stalled. A separate diagnostic runspace located the host at `Invoke-KerberosQualificationDC`, synchronously preparing `New-KerberosSASLPeer` with the full peer byte array. The owned DC1 transport was idle; the new peer directory, process, firewall rule, and listener were absent. These facts locate the wait in the PSRP request/response path. They do not prove its lower-level cause.

The exact old transport process was retired once after rechecking its VM, creation time, executable, VMIC parent, idle state, and absence of child work. The runner retained `passed=false` and `cleanup_verified=false` because its original DC cleanup session was broken. Independent reconciliation through a fresh verified session checked all 11 recorded/current peer identities, removed the owned contact/child fixture, restored exact policy presence/type/value, and preserved the outer account, TLS fixture, and immutable credentials. Independent recovery does not rewrite the failed runner manifest.

## Optional local source

`kerberos-qualification.ps1` accepts `PreStagedPeerPath`, `PreStagedPeerOwner`, and `PreStagedPeerSHA256` together. The supplied hash must equal the collector's local `WindowsPeer` hash. The guest path must be exactly `C:\adsdk-kerberos-public-peer\<owner-guid>\peer.exe`.

The public cache contains only `peer.exe` and `owner.json`. Its owner record binds schema, purpose, completed phase, owner, run, server, profile, VM, path, hash, and size. The helper rejects missing paths, reparse points, extra entries, incomplete phases, changed ownership, mixed payload modes, and mismatched bytes. The collector performs this read-only preflight before strict policy changes.

For each relay case, the collector sends a small descriptor instead of the peer byte array. The verified guest makes a fresh local copy into the existing per-case owned directory and verifies its complete SHA256 before creating a firewall rule or process. Per-case ownership and cleanup guards remain unchanged. The public source cache has a separate lifetime and must be explicitly retired after qualification; per-case cleanup never deletes it.

Omitting all three options preserves the legacy byte-array path. Neither path retries a failed or indeterminate operation. The 84-case matrix, expected errors, SDK runtime, module pins, and latest Go requirement are unchanged.

## Verification and staging

The regression exercises the actual per-case preparation call with an 8 MiB synthetic legacy byte array still present in the context. The original implementation fails because it serializes that payload; the local-source request contains no byte array and serializes to 1,258 characters. Real filesystem guards exercise changed owner/run/profile/VM/path/hash/size/phase, same-size corruption, and mixed payload rejection before process, firewall, or directory mutation. Guest guards run under both Windows PowerShell 5.1 and PowerShell 7.

A separately reviewed host-lab ISO prototype can seed the public cache. It uses a fresh label of at most 16 ASCII characters and reads both actual primary and Joliet descriptors before accepting media or attaching it. It records the original owned DC1 DVD/controller/disk/NIC state, adds one new DVD, verifies the manifest and full local-copy hash, removes only that verified attachment, and compares the original device state. ISO contents are limited to the public executable and manifest. No credentials, autorun, network, policy, or account configuration belongs in the media. Preparing the prototype does not establish live qualification or authorize replay of a failed SDK operation.

This is a prerequisite for the remaining complete authentication qualification tracked by issue 194. It does not close that issue.
