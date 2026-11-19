import hashlib
import json
from pathlib import Path
import shutil

root = Path(__file__).resolve().parent.parent
tree = root / "tmp/worktrees/sdk0710-remaining-qualification"
target = tree / "docs/research/portable-replication-evidence/server2025-ordinary-4022967"
target.mkdir(parents=True, exist_ok=True)
assert not (target / "artifact-index.json").exists(), "Completed publication requires a separate reviewed update"
index = []

def preserve(source, relative):
    source = Path(source)
    assert source.is_file() and not source.is_symlink(), source
    destination = target / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = source.read_bytes()
    if destination.exists():
        assert destination.read_bytes() == content, destination
    else:
        with destination.open("xb") as stream:
            stream.write(content)
    index.append({"path": relative, "source_path": str(source), "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})

audit_path = root / "tmp/sdk209-server2025-ordinary-independent-audit.json"
audit = json.loads(audit_path.read_text(encoding="utf-8-sig"))
assert audit["passed"] and audit["checks"] == 419 and len(audit["cells"]) == 10
allowed = {
    "host-execution-source.ps1.txt", "ordinary-actor-input-source.ps1.txt", "binary-manifest.json", "source-provenance.json", "protected-stdin-source.ps1.txt",
    "independent-service-identities.json", "windows-portable-password-binary-transfer.json", "windows-portable-password-execution-intent.json",
    "process.json", "result.json", "linux-control-source.ps1.txt", "portablereplication-linux-amd64.buildinfo.txt", "binary-transfer.json", "execution-intent.json", "result-transfer.json",
}
for cell in audit["cells"]:
    source = Path(cell["capture"])
    destination = f"captures/{cell['client']}/{cell['selection']}"
    for item in sorted(source.iterdir()):
        assert item.is_file() and item.name in allowed, item
        preserve(item, destination + "/" + item.name)

for run, group in (("sdk07-p25-20261119t061327773z", "completed-ordinary"), ("sdk07-p25-20261119t061023166z", "stopped-initial-membership-guard")):
    directory = Path("H:/ad-sdk-lab/portable-kerberos") / run
    names = {"prepare.json", "sdk07-ordinary-owner.json", "sdk07-ordinary-membership.json", "kerberos-fixture.ps1", "sdk07-actor-prepare-source.ps1.txt", "sdk07-actor-cleanup-source.ps1.txt"}
    for item in sorted(directory.iterdir()):
        if item.is_dir():
            assert item.name == "secrets"
            continue
        if item.name in names or item.name.startswith("cleanup-reconciliation-"):
            preserve(item, f"fixtures/{group}/{item.name}")
    owner = json.loads((directory / "sdk07-ordinary-owner.json").read_text(encoding="utf-8-sig"))
    assert owner["phase"] == "cleaned" and owner["private_credential_retired"]
    assert not Path(owner["actor"]["credential_file"]).exists()

local_files = [
    "sdk209-current-ordinary-windows.json", "sdk209-current-ordinary-linux.json", "sdk209-current-lab-baseline.json",
    "sdk209-server2025-ordinary-prepare.json", "sdk209-server2025-stopped-ordinary-cleanup.json", "sdk209-stopped-ordinary-reconciled.json",
    "sdk209-server2025-ordinary2-prepare.json", "sdk209-server2025-ordinary2-cleanup.json", "sdk209-server2025-ordinary-independent-audit.json",
    "sdk07-ordinary-input-offline-receipt.json", "sdk07-ordinary-input-offline-current-receipt.json", "sdk07-ordinary-actor-review.json",
    "sdk209-windows-ordinary-scopes-20261119t061542416z.json", "sdk209-windows-ordinary-scopes-20261119t061628195z.json",
    "sdk209-windows-ordinary-scopes-20261119t061645823z.json", "sdk209-linux-ordinary-scopes-20261119t061710653z.json",
    "sdk07-current-4022967-build.log",
]
for name in local_files:
    source = root / "tmp" / name
    preserve(source, "receipts/" + (name + ".txt" if name.endswith(".log") else name))
    saved_source = Path(str(source) + ".source.ps1.txt")
    if saved_source.exists():
        preserve(saved_source, "receipts/" + saved_source.name)
for name in (
    "sdk07-ordinary-actor.ps1", "sdk07-ordinary-input.ps1", "test-sdk07-ordinary-input.ps1", "reconcile-sdk07-ordinary-cleanup.ps1",
    "run-sdk07-windows-password.ps1", "run-sdk07-linux-password.ps1", "run-sdk209-ordinary-scopes.ps1",
    "run-sdk209-ordinary-scopes-source-optional-field-failure.ps1.txt", "read-sdk07-current-lab.ps1", "freeze-sdk0710-current.py",
    "build-sdk07-current.ps1", "audit-sdk209-server2025-ordinary.py", "publish-sdk209-ordinary.py",
):
    preserve(root / "tmp" / name, "tools/" + name)
for name in ("source-provenance.json", "binary-manifest.json", "portablereplication-windows-amd64.exe.buildinfo.txt", "portablereplication-linux-amd64.buildinfo.txt"):
    preserve(root / "tmp/sdk07-live/4022967" / name, "build/" + name)

(target / "artifact-index.json").write_text(json.dumps({"schema_version": 1, "source_revision": audit["source_revision"], "artifacts": index, "private_files_included": 0}, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"directory": str(target), "originals_and_tools": len(index), "raw_original_bytes": sum(item["bytes"] for item in index), "private_files": 0}))
