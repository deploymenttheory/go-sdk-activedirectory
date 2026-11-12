# Base lab bootstrap media check

On 2026-11-12, an elevated Windows PowerShell 5.1 process ran:

```powershell
.\scripts\lab\provision.ps1 -ServerVersion 2025 -StorageRoot H:\ad-sdk-lab -MediaOnly
```

The [recorded result](media-check.json) passed. It reused and mounted the existing
ISO, inspected image 1 as amd64 Windows Server 2025 Standard Evaluation build
10.0.26100.32230, and recorded its SHA-256. No VM was created or removed and no
ISO was downloaded in this check. The result was copied from the host with a
matching file hash.

`scripts/lab/test-provision.ps1` separately exercises missing/cached/invalid media,
owned transfer retry, mismatched job rejection, checksum/version/architecture
checks, mount ownership, explicit media, and orchestration failure boundaries
without network or Hyper-V access. It passed on Windows PowerShell 5.1 and runs
in CI. These checks do not constitute a new full-download or teardown/rebuild
execution; the underlying base actions' earlier lifecycle evidence remains in
[the Server 2025 record](../README.md). Expansion profiles remain separate work.
