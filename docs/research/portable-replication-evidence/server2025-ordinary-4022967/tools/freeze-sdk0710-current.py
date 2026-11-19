import hashlib
import json
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

root = Path(__file__).resolve().parent.parent
tree = root / "tmp/worktrees/sdk0710-remaining-qualification"
revision = "4022967311b983ffb27f9cb59fedd100a3aca4b9"
assert subprocess.check_output(["git", "-C", str(tree), "rev-parse", "HEAD"], text=True).strip() == revision
directory = root / "tmp/sdk07-live" / revision[:7]
directory.mkdir(parents=True, exist_ok=False)
records = subprocess.check_output(["git", "-C", str(tree), "ls-tree", "-rz", "--full-tree", revision])
objects = {}
for record in records.split(b"\0"):
    if not record:
        continue
    metadata, name = record.split(b"\t", 1)
    mode, kind, oid = metadata.decode().split()
    assert kind == "blob" and mode in ("100644", "100755")
    objects[name.decode()] = oid

def read_blobs():
    payload = subprocess.check_output(["git", "-C", str(tree), "cat-file", "--batch"], input=("\n".join(objects.values()) + "\n").encode())
    offset = 0
    for name, expected in objects.items():
        end = payload.index(b"\n", offset)
        oid, kind, size = payload[offset:end].decode().split()
        assert oid == expected and kind == "blob"
        offset = end + 1
        content = payload[offset:offset + int(size)]
        offset += int(size)
        assert payload[offset:offset + 1] == b"\n"
        offset += 1
        yield name, content
    assert offset == len(payload)

archive = directory / "source.zip"
with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
    for name, content in read_blobs():
        bundle.writestr(name, content)
files = {}
with zipfile.ZipFile(archive) as bundle:
    assert set(bundle.namelist()) == set(objects)
    for name, canonical in read_blobs():
        content = bundle.read(name)
        assert content == canonical
        parts = PurePosixPath(name)
        assert not parts.is_absolute() and ".." not in parts.parts and "\\" not in name
        path = directory / "source" / Path(*parts.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        files[name] = hashlib.sha256(content).hexdigest()
proof = {
    "source_revision": revision,
    "source_variant": "Canonical raw-Git ZIP and extraction, verified by independent second Git read before build.",
    "source_archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "source_files": files,
    "files_verified": len(files),
    "go_module_files": sum(name.endswith(".go") or name.rsplit("/", 1)[-1] in ("go.mod", "go.sum") for name in files),
    "qualification_claimed": False,
}
(directory / "source-provenance.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
builder = (root / "tmp/build-sdk07-live.ps1").read_text(encoding="utf-8-sig")
assert "sdk07-live\\ebb11a2" in builder
builder = builder.replace("sdk07-live\\ebb11a2", "sdk07-live\\" + revision[:7]).replace("ebb11a2aae28187c72ec0ea665bb5fe02aa451ed", revision)
(root / "tmp/build-sdk07-current.ps1").write_text(builder, encoding="utf-8", newline="\n")
print(json.dumps({key: value for key, value in proof.items() if key != "source_files"}))
