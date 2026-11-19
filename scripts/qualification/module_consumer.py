#!/usr/bin/env python3
"""Verify a raw committed SDK snapshot through a fresh, downloaded Go module ZIP.

No directory connection is made. This is packaging/API evidence, never AD acceptance.
Only a newly created output directory is written; the source checkout is never copied
or trusted for source bytes. The tooling module is outside the staged SDK module.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time
import zipfile

MODULE = "github.com/deploymenttheory/go-sdk-activedirectory"
TOOL_SUM = """golang.org/x/mod v0.43.0 h1:MFuq5J6s35W9D3IjkwyWc9vHh0nENOrt5K8Iof4ofmg=
golang.org/x/mod v0.43.0/go.mod h1:4ec1JnuyBz5+FIVhg86UsA39YG8BpnrZdJYSNHmGzHY=
"""
TARGETS = [(system, arch) for system in ("windows", "linux", "darwin") for arch in ("amd64", "arm64")]
MAX_BLOB = 32 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or "\\" in name or ":" in name or path.as_posix() != name:
        raise ValueError(f"noncanonical module path: {name!r}")
    if any(part in ("..", ".git", "worktrees") for part in path.parts) or path.parts[0] == "tmp":
        raise ValueError(f"private/tool-state path in publication: {name!r}")
    if path.suffix.lower() in (".clixml", ".ccache", ".keytab", ".pfx", ".p12", ".key"):
        raise ValueError(f"private credential/key file in publication: {name!r}")
    if path.name in ("go.mod", "go.sum") and len(path.parts) > 1:
        raise ValueError(f"nested module metadata in publication: {name!r}")
    return path


def git(root, *arguments, data=None):
    return subprocess.run(
        ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root), *arguments],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout


def committed_files(root, revision):
    """Resolve once, read raw blobs in a single batch, and reject gitlinks/symlinks."""
    commit = git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError("revision did not resolve to a full immutable commit")
    entries = []
    for record in git(root, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if not record:
            continue
        header, name = record.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        name = name.decode("utf-8", errors="strict")
        safe_path(name)
        if mode not in ("100644", "100755") or kind != "blob":
            raise ValueError(f"nonregular publication entry: {mode} {kind} {name}")
        entries.append((name, oid))
    output = io.BytesIO(git(root, "cat-file", "--batch", data="".join(oid + "\n" for _, oid in entries).encode()))
    files = {}
    for name, expected_oid in entries:
        header = output.readline().decode("ascii").split()
        if len(header) != 3 or header[:2] != [expected_oid, "blob"]:
            raise ValueError("raw Git blob batch identity mismatch")
        size = int(header[2])
        if not 0 <= size <= MAX_BLOB:
            raise ValueError(f"publication blob exceeds bound: {name}")
        data = output.read(size)
        if len(data) != size or output.read(1) != b"\n" or name in files:
            raise ValueError("truncated/duplicate raw Git blob")
        files[name] = data
    if output.read():
        raise ValueError("unexpected raw Git batch suffix")
    if "go.mod" not in files or not any(name.startswith("3rd_party/") for name in files):
        raise ValueError("snapshot lacks root module or owned protocol sources")
    return commit, files


def write_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)


def write_json(path, value):
    write_new(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def verify_zip(archive, module, version, files):
    prefix = f"{module}@{version}/"
    with zipfile.ZipFile(archive) as handle:
        names = handle.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate ZIP path")
        if set(names) != {prefix + name for name in files}:
            raise ValueError("module ZIP omitted or added intended Git files")
        for name, raw in files.items():
            if handle.read(prefix + name) != raw:
                raise ValueError(f"module ZIP changed committed bytes: {name}")


def public_imports(files):
    packages = set()
    for name in files:
        parts = PurePosixPath(name).parts
        if parts[0] not in ("activedirectory", "conditions", "dccloning") or "internal" in parts:
            continue
        if name.endswith(".go") and not name.endswith("_test.go"):
            packages.add(PurePosixPath(name).parent.as_posix())
    return sorted(packages)


def validate_module(data):
    text = data.decode()
    require_module = f"module {MODULE}"
    if require_module not in text.splitlines() or re.search(r"(?m)^\s*replace(?:\s|\()", text):
        raise ValueError("wrong root module or replacement directive")
    minimum = re.search(r"(?m)^go (\d+\.\d+\.\d+)\s*$", text)
    if not minimum:
        raise ValueError("root module must declare the required full Go patch version")
    return minimum[1]


def verify_resolution(records, module_dir):
    selected = [item for item in records if item.get("ImportPath", "").startswith(MODULE + "/")]
    if not selected:
        raise ValueError("no compiled SDK imports in consumer dependency graph")
    root = Path(module_dir).resolve()
    for item in selected:
        module = item.get("Module", {})
        if module.get("Path") != MODULE or module.get("Replace") or Path(module.get("Dir", "")).resolve() != root:
            raise ValueError("SDK import resolved through another module/replacement")
        if not Path(item["Dir"]).resolve().is_relative_to(root):
            raise ValueError("SDK import escaped downloaded module directory")
    return len(selected)


def json_stream(raw):
    decoder, values = json.JSONDecoder(), []
    text = raw.decode()
    while text.strip():
        text = text.lstrip()
        value, end = decoder.raw_decode(text)
        values.append(value)
        text = text[end:]
    return values


def check(args):
    root, output = args.root.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": 1, "scope": "candidate module packaging and public API checks; no live AD qualification",
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "passed": False, "checks": [],
        "tool_sources_sha256": {}, "source_basis": "raw committed Git blobs via cat-file; no checkout/archive EOL transform",
    }
    try:
        commit, files = committed_files(root, args.revision)
        report["source_commit"] = commit
        minimum_go = validate_module(files["go.mod"])
        manifest = {name: digest(data) for name, data in sorted(files.items())}
        input_bytes = "".join(f"{sha}  {name}\n" for name, sha in manifest.items()).encode()
        report.update(input_sha256=digest(input_bytes), files=len(files), third_party_files=sum(
            name.startswith("3rd_party/") for name in files), go_and_module_files=sum(
            name.endswith(".go") or name in ("go.mod", "go.sum") for name in files), minimum_go=minimum_go)
        write_json(output / "source-manifest.json", manifest)
        for name, data in files.items():
            write_new(output / "stage" / name, data)
        stage, tool, consumer = output / "stage", output / "tool", output / "consumer"
        base = Path(__file__).resolve().parent
        for name in ("module_consumer.py", "modulezip.go.txt", "consumer_test.go.txt"):
            raw = (base / name).read_bytes()
            report["tool_sources_sha256"][name] = digest(raw)
            write_new(output / "executed-tool-sources" / name, raw)
        write_new(tool / "main.go", (base / "modulezip.go.txt").read_bytes())
        write_new(tool / "go.mod", f"module example.invalid/sdk-module-check-tool\n\ngo {minimum_go}\n\nrequire golang.org/x/mod v0.43.0\n".encode())
        write_new(tool / "go.sum", TOOL_SUM.encode())
        env = os.environ.copy()
        for name in ("GOOS", "GOARCH", "GOFLAGS", "GONOPROXY", "GONOSUMDB", "GOPRIVATE", "GOPATH", "GOMODCACHE"):
            env.pop(name, None)
        env.update(GOWORK="off", GOENV="off", GOTOOLCHAIN="local", CGO_ENABLED="0", GOMAXPROCS="2", GOMEMLIMIT="512MiB")

        def run(label, arguments, cwd, overrides=None):
            settings = env | (overrides or {})
            result = subprocess.run([str(args.go), *arguments], cwd=cwd, env=settings, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=args.timeout)
            write_new(output / f"{label}.log", result.stdout)
            report["checks"].append({"name": label, "exit_code": result.returncode, "log_sha256": digest(result.stdout)})
            if result.returncode:
                raise ValueError(f"Go check failed: {label}; see retained log")
            return result.stdout

        go_env = json.loads(run("go-environment", ["env", "-json", "GOVERSION", "GOOS", "GOARCH"], tool))
        report["toolchain"] = go_env["GOVERSION"]
        report["execution_platform"] = go_env["GOOS"] + "/" + go_env["GOARCH"]
        if go_env["GOVERSION"] != "go" + minimum_go:
            raise ValueError("verification Go toolchain differs from declared current minimum")
        version = "v0.0.0-sdkqualification." + report["input_sha256"][:16]
        proxy = output / "proxy" / MODULE / "@v"
        archive = proxy / (version + ".zip")
        proxy.mkdir(parents=True)
        run("create-module-zip", ["run", "-mod=readonly", ".", "-stage", str(stage), "-output", str(archive),
                                  "-module", MODULE, "-version", version], tool)
        verify_zip(archive, MODULE, version, files)
        report.update(version=version, zip_sha256=digest(archive.read_bytes()), canonical_zip_tool="golang.org/x/mod v0.43.0")
        write_new(proxy / (version + ".mod"), files["go.mod"])
        write_json(proxy / (version + ".info"), {"Version": version, "Time": report["started_utc"]})
        write_new(proxy / "list", (version + "\n").encode())
        packages = public_imports(files)
        imports = "\n".join(f'\t_ "{MODULE}/{name}"' for name in packages if name not in ("activedirectory", "conditions"))
        write_new(consumer / "consumer_test.go", (base / "consumer_test.go.txt").read_bytes().replace(b"\t// __PUBLIC_IMPORTS__", imports.encode()))
        write_new(consumer / "go.mod", f"module example.invalid/independent-sdk-consumer\n\ngo {minimum_go}\n\nrequire {MODULE} {version}\n".encode())
        env.update(GOMODCACHE=str(output / "fresh-module-cache"), GOPROXY=(output / "proxy").as_uri() + ",https://proxy.golang.org",
                   GONOSUMDB=MODULE, GONOPROXY="none", GOFLAGS="-mod=mod")
        downloaded = json.loads(run("download-sdk", ["mod", "download", "-json", MODULE + "@" + version], consumer))
        if digest(Path(downloaded["Zip"]).read_bytes()) != report["zip_sha256"]:
            raise ValueError("consumer did not download the generated module ZIP")
        downloaded_dir = Path(downloaded["Dir"]).resolve()
        if not downloaded_dir.is_relative_to((output / "fresh-module-cache").resolve()):
            raise ValueError("downloaded module escaped fresh cache")
        for name, raw in files.items():
            if (downloaded_dir / name).read_bytes() != raw:
                raise ValueError(f"downloaded module changed committed bytes: {name}")
        run("consumer-host-unit", ["test", "-count=1", "-v", "."], consumer)
        records = json_stream(run("consumer-import-resolution", ["list", "-test", "-deps", "-json", "."], consumer))
        report["sdk_imports_from_downloaded_module"] = verify_resolution(records, downloaded_dir)
        report["public_packages_imported"] = packages
        report["builds"] = []
        for system, arch in TARGETS:
            binary = output / "binaries" / f"consumer-{system}-{arch}.test"
            binary.parent.mkdir(exist_ok=True)
            run(f"build-{system}-{arch}", ["test", "-c", "-o", str(binary), "."], consumer, {"GOOS": system, "GOARCH": arch})
            report["builds"].append({"platform": system + "/" + arch, "sha256": digest(binary.read_bytes()), "executed": False})
        run("consumer-module-verify", ["mod", "verify"], consumer)
        # Re-hash the staged bytes after all external Go invocations; source checkout is never read for input bytes.
        if any(digest((stage / name).read_bytes()) != manifest[name] for name in files):
            raise ValueError("canonical stage changed during consumer checks")
        report.update(passed=True, exact_downloaded_files=len(files), source_stage_unchanged=True,
                      fresh_module_cache=True, workspace="off", nested_modules=0, local_replaces=0, gitlinks=0)
    finally:
        write_json(output / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True, help="fresh directory, never reused")
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600, help="per Go command bound in seconds")
    args = parser.parse_args()
    try:
        report = check(args)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({key: report[key] for key in ("source_commit", "toolchain", "files", "third_party_files", "zip_sha256", "passed")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
