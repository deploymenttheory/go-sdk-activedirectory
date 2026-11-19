import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--tree", required=True)
parser.add_argument("--revision", default="HEAD")
parser.add_argument("--output", required=True)
args = parser.parse_args()
tree = Path(args.tree).resolve()
base = "4022967311b983ffb27f9cb59fedd100a3aca4b9"
prefix = "docs/research/portable-replication-evidence/server2025-ordinary-4022967/"
checks = []

def require(value, label):
    assert value, label
    checks.append(label)

def objects(revision):
    data = subprocess.check_output(["git", "-C", str(tree), "ls-tree", "-rz", "--full-tree", revision])
    result = {}
    for item in data.split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        assert kind == "blob" and mode in ("100644", "100755")
        result[name.decode()] = oid
    return result

def blobs(oids):
    data = subprocess.check_output(["git", "-C", str(tree), "cat-file", "--batch"], input=("\n".join(oids.values()) + "\n").encode())
    position = 0
    result = {}
    for name, expected in oids.items():
        end = data.index(b"\n", position)
        oid, kind, size = data[position:end].decode().split()
        assert oid == expected and kind == "blob"
        position = end + 1
        result[name] = data[position:position + int(size)]
        position += int(size)
        assert data[position:position + 1] == b"\n"
        position += 1
    assert position == len(data)
    return result

current = objects(args.revision)
original = objects(base)
runtime = lambda files: {name: oid for name, oid in files.items() if name.endswith(".go") or name.rsplit("/", 1)[-1] in ("go.mod", "go.sum")}
require(runtime(current) == runtime(original) and len(runtime(current)) == 978, "all978 Go/module blobs exactly unchanged from tested4022967")
evidence = blobs({name[len(prefix):]: oid for name, oid in current.items() if name.startswith(prefix)})
index = json.loads(evidence["artifact-index.json"])
source_hashes = {}
for item in index["artifacts"]:
    name = item["path"]
    require(name in evidence and len(evidence[name]) == item["bytes"] and hashlib.sha256(evidence[name]).hexdigest() == item["sha256"], "raw committed original " + name)
    require("/secrets/" not in name and not name.endswith((".clixml", ".exe", ".zip")), "no private file or binary " + name)
    source_hashes[item["source_path"]] = item["sha256"]
audit = json.loads(evidence["receipts/sdk209-server2025-ordinary-independent-audit.json"])
require(audit["passed"] and audit["checks"] == 419, "independent original-record audit419 retained")
for name, digest in audit["input_sha256"].items():
    require(source_hashes.get(name) == digest, "original audit input pinned " + name)

proof = json.loads(evidence["build/source-provenance.json"])
require(proof["source_revision"] == base and proof["files_verified"] == 7478 and proof["go_module_files"] == 978, "canonical tested source scope")
require(set(proof["source_files"]) == set(original), "canonical source manifest covers every original Git input")
for name, payload in blobs(original).items():
    require(hashlib.sha256(payload).hexdigest() == proof["source_files"][name], "canonical raw Git build input " + name)

stage_count = 0
status_count = 0
for client in ("windows", "linux"):
    for selection in ("server", "explicit-two", "domain", "forest", "site"):
        report = json.loads(evidence[f"captures/{client}/{selection}/result.json"])
        require(report["source_revision"] == base and report["source_label_matches"] and report["platform"] == client + "/amd64", f"{client}/{selection} exact source/client")
        require(report["backend"] == "portable" and report["transport"] == "ldap-seal" and report["credential_source"] == "password", f"{client}/{selection} explicit secure public path")
        require(not report["success"] and report["error_class"] == "denied" and len(report["queries"]) == 3, f"{client}/{selection} aggregate denial")
        for query in report["queries"]:
            require(query["complete"] == (query["kind"] == "partners"), f"{client}/{selection}/{query['kind']} preserved success/denial")
            for status in query.get("statuses", []):
                require(status["code"] == 8453 and status["protocol"] == "win32-rpc" and status["operation"] == "IDL_DRSGetReplInfo", "actual precise denied RPC status")
                status_count += 1
            for server in query["result"]["Servers"]:
                for stage in server["Observation"]["rpc_protection"]:
                    require(stage["complete"] and stage["mutual_authentication"] and stage["header_signed"] and stage["confidential"] and stage["encryption_type"] == 18 and stage["cipher_bits"] == 256, "actual complete mutual/header-signed/confidential AES256 stage")
                    stage_count += 1
require(status_count == 36 and stage_count == 108, "exact36 denied statuses and108 protected stages")
for fixture in ("completed-ordinary", "stopped-initial-membership-guard"):
    owner = json.loads(evidence[f"fixtures/{fixture}/sdk07-ordinary-owner.json"])
    require(owner["phase"] == "cleaned" and owner["private_credential_retired"], "retained private credential retirement receipt " + fixture)
    if fixture == "completed-ordinary":
        require(owner["cleanup"]["verified"] and all(item["absent"] for item in owner["cleanup"]["observations"]), "both-DC completed fixture absence")
    else:
        require(not owner["cleanup"]["verified"] and owner["cleanup_reconciliation"]["verified"] and owner["cleanup_reconciliation"]["directory_deletes_submitted"] == 0, "stopped cleanup false retained with separate no-replay reconciliation")
output = {"passed": True, "revision": args.revision, "checks": len(checks), "originals_and_tools": len(index["artifacts"]), "canonical_git_inputs": 7478, "unchanged_go_module_blobs": 978, "actual_rpc8453": status_count, "actual_protected_rpc_stages": stage_count, "scope": "Raw committed bytes and actual public observation/cleanup receipts; no new live invocation or release qualification."}
Path(args.output).write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
print(json.dumps(output))
