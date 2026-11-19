import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
revision = "4022967311b983ffb27f9cb59fedd100a3aca4b9"
actor_run = "sdk07-p25-20261119t061327773z"
checks = []
inputs = {}

def require(ok, label):
    assert ok, label
    checks.append(label)

def read(path):
    path = Path(path)
    data = path.read_bytes()
    inputs[str(path)] = hashlib.sha256(data).hexdigest()
    return json.loads(data.decode("utf-8-sig"))

captures = []
for client in ("windows", "linux"):
    receipt = read(root / f"sdk209-current-ordinary-{client}.json")
    captures.append((client, "server", receipt))
for filename in (
    "sdk209-windows-ordinary-scopes-20261119t061542416z.json",
    "sdk209-windows-ordinary-scopes-20261119t061645823z.json",
    "sdk209-linux-ordinary-scopes-20261119t061710653z.json",
):
    batch = read(root / filename)
    require(batch["actor_fixture"] == actor_run and batch["revision"] == revision, f"batch actor/revision {filename}")
    for call in batch["calls"]:
        # The first explicit-two SDK call completed. Its host checker then tried
        # to access an omitted success-only JSON property under StrictMode.
        # Keep that stopped receipt unchanged and inspect the real result here.
        captures.append((batch["client"], call["variant"], call["receipt"]))
require(len(captures) == 10, "exactly ten declared public calls")
require(len({(client, variant) for client, variant, _ in captures}) == 10, "unique client/selection cells without replay")
membership = read(Path("H:/ad-sdk-lab/portable-kerberos") / actor_run / "sdk07-ordinary-membership.json")
require(membership["ordinary"] and membership["primary_group"] == 513 and membership["member_of"] == [], "ordinary actor has no direct role grant")
require(membership["account_group_changes"] == 0, "no group membership changes")
owner = read(Path("H:/ad-sdk-lab/portable-kerberos") / actor_run / "sdk07-ordinary-owner.json")
require(owner["client_guid"] == membership["client_guid"] and not owner["actor"]["policy_applied"], "exact actor GUID and unchanged policy")

cells = []
stage_count = 0
denials = 0
for client, variant, receipt in captures:
    directory = Path(receipt["capture"])
    report = read(directory / "result.json")
    require(report["source_revision"] == revision and report["source_label_matches"], f"{client}/{variant} exact current source")
    require(report["platform"] == f"{client}/amd64" and report["toolchain"] == "go1.27.4", f"{client}/{variant} platform/toolchain")
    require(report["backend"] == "portable" and report["credential_source"] == "password" and report["transport"] == "ldap-seal", f"{client}/{variant} explicit secure source")
    require(report["success"] is False and report["error_class"] == "denied", f"{client}/{variant} denial retained")
    intent_name = "windows-portable-password-execution-intent.json" if client == "windows" else "execution-intent.json"
    intent = read(directory / intent_name)
    require(intent["actor_fixture"] == actor_run and intent["actor_guid"] == membership["client_guid"], f"{client}/{variant} actual ordinary input identity")
    require([query["kind"] for query in report["queries"]] == ["partners", "failures", "queue"], f"{client}/{variant} exact category order")
    expected_servers = 1 if variant == "server" else 2
    for query in report["queries"]:
        label = f"{client}/{variant}/{query['kind']}"
        require(query["result"]["Targets"]["Complete"] and len(query["result"]["Targets"]["Servers"]) == expected_servers, f"{label} complete target selection")
        servers = query["result"]["Servers"]
        require(len(servers) == expected_servers, f"{label} exact result server count")
        if query["kind"] == "partners":
            require(query["complete"] and not query.get("statuses") and not query.get("error_class"), f"{label} success distinct from denial")
        else:
            require(not query["complete"] and query["error_class"] == "denied", f"{label} denied category is incomplete")
            statuses = query["statuses"]
            require(len(statuses) == expected_servers, f"{label} per-server statuses retained")
            require(all(s["protocol"] == "win32-rpc" and s["operation"] == "IDL_DRSGetReplInfo" and s["code"] == 8453 for s in statuses), f"{label} precise RPC8453")
            denials += len(statuses)
        for server in servers:
            observation = server["Observation"]
            require(observation["Complete"] == (query["kind"] == "partners"), f"{label} actual observation completeness")
            stages = observation["rpc_protection"]
            require([stage["stage"] for stage in stages] == ["endpoint-map", "drs"], f"{label} separate actual EPM/DRS stages")
            require(all(stage["complete"] and stage["mutual_authentication"] and stage["header_signed"] and stage["confidential"] and stage["encryption_type"] == 18 and stage["cipher_bits"] == 256 for stage in stages), f"{label} measured complete mutual header-signed AES256 confidentiality")
            stage_count += len(stages)
            if query["kind"] == "partners":
                require(server["Inbound"]["Requested"] and server["Inbound"]["Available"] and server["Inbound"]["Complete"] and server["Outbound"]["Requested"] and server["Outbound"]["Available"] and server["Outbound"]["Complete"], f"{label} both successful directions retained")
            elif query["kind"] == "failures":
                require(all(server[name]["Requested"] and not server[name]["Available"] and not server[name]["Complete"] for name in ("Connections", "Links")) and not server["Failures"], f"{label} unavailable failure categories are not confirmed empty")
            else:
                require(server["State"]["Requested"] and not server["State"]["Available"] and not server["State"]["Complete"] and not server["Operations"], f"{label} unavailable queue is not confirmed empty")
    cells.append({"client": client, "selection": variant, "capture": str(directory), "expected_servers": expected_servers})

require(owner["phase"] == "cleaned" and owner["private_credential_retired"], "ordinary actor cleanup and private credential retirement")
cleanup = owner["cleanup"]
require(cleanup["verified"] and cleanup["removed"]["verified"] and cleanup["removed"]["policy"]["verified"], "fixture deletion and exact policy baseline verified")
require(len(cleanup["observations"]) == 4 and all(item["absent"] for item in cleanup["observations"]), "both actor/parent GUIDs absent on both DCs")
require(not Path(owner["actor"]["credential_file"]).exists(), "private DPAPI credential leaf absent")
report = {"passed": True, "source_revision": revision, "checks": len(checks), "cells": cells, "public_queries": 30, "server_diagnostic_reads": 54, "actual_rpc_protection_observations": stage_count, "precise_rpc8453_statuses": denials, "directory_writes_by_collectors": 0, "input_sha256": inputs, "check_labels": checks, "scope": "Server2025 Windows/Linux ordinary password/Seal selections only; other SDK209 cells remain required."}
require(stage_count == 108 and denials == 36, "exact complete stage and denied-status counts")
report["checks"] = len(checks)
path = root / "sdk209-server2025-ordinary-independent-audit.json"
path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps({key: value for key, value in report.items() if key not in ("check_labels", "input_sha256", "cells")}))
