#!/usr/bin/env python3
"""Audit retained authentication evidence from raw Git blobs, without contacting AD.

Success means the selected retained records are internally consistent. It is not
a release decision, current-source equivalence claim, or substitute for missing
feature qualification. An optional immutable pending PR revision is reported as
candidate evidence separately from the selected main-based snapshot.
"""

import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath
import re
import sys

from module_consumer import committed_files, digest, write_json

LDAP = "docs/research/portable-ldap-evidence"
KERBEROS = "docs/research/portable-kerberos-evidence"
SASL = "docs/research/portable-sasl-evidence"
AUTH_SOURCE = "958d4a426561bb36a5cd6104f0e253e2a7aa7b2f"
TLS_SOURCE = "ca38eb1ac624c4452ac6aecb47ff6c3cda617d3a"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(files, path):
    require(path in files, f"missing retained artifact: {path}")
    return json.loads(files[path].decode("utf-8-sig"))


def hash_index(files, path):
    index = read(files, path)
    hashes = next((index[name] for name in ("artifacts_sha256", "sha256", "files") if isinstance(index.get(name), dict)), None)
    require(bool(hashes), f"no artifact hashes: {path}")
    covered = set()
    for name, expected in hashes.items():
        require(isinstance(expected, str) and re.fullmatch("[0-9a-fA-F]{64}", expected), f"invalid artifact hash: {path}:{name}")
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts and "\\" not in name, f"unsafe artifact reference: {name}")
        target = (PurePosixPath(path).parent / relative).as_posix()
        require(target in files and digest(files[target]) == expected.lower(), f"artifact byte mismatch: {target}")
        covered.add(target)
    return covered


def indexed_read(files, path, covered):
    require(path in covered, f"required evidence has no retained hash: {path}")
    return read(files, path)


def expected_cases():
    result = {}
    for client in ("windows", "linux"):
        for transport in ("ldaps", "starttls"):
            for variant in ("password", "keytab", "cache", "cache-tgt-only", "cache-keytab-issued",
                            "cbt-missing", "cbt-tampered", "expired-cache", "wrong-spn", "service-expiry"):
                scope = "local-credential" if variant == "expired-cache" else "local-config" if variant == "wrong-spn" else "live-ad"
                result[f"auth-{client}-{transport}-{variant}"] = (client, variant, scope)
            for protection in ("sign", "seal"):
                result[f"sasl-{client}-{transport}-{protection}-refused"] = (client, "invalid-config", "local-config")
        for protection in ("sign", "seal"):
            for variant in ("password", "keytab", "cache", "pass", "tampered", "reordered", "truncated-prefix", "truncated-body"):
                result[f"sasl-{client}-{protection}-{variant}"] = (client, variant, "live-ad")
        result[f"sasl-{client}-default-password"] = (client, "default", "live-ad")
        result[f"sasl-{client}-seal-selected-sign"] = (client, "selected-sign", "live-ad")
    return result


def identity(record, manifest, client):
    require(record.get("run_id") == manifest["run_id"] and record.get("source_revision") == AUTH_SOURCE,
            "case source/run identity mismatch")
    require(record.get("platform") == client + "/amd64" and record.get("toolchain") == "go1.27.4",
            "case client architecture/toolchain mismatch")


def auth_result(record, variant):
    if variant in ("expired-cache", "wrong-spn", "invalid-config"):
        require(record.get("success") is False and record.get("complete") is False, "local refusal claimed authentication")
        key = "kerberos_expired" if variant == "expired-cache" else "invalid_config"
        require(record.get(key) is True, "local refusal lacks the expected typed cause")
    elif variant.startswith("cbt-"):
        require(all(record.get(key) is True for key in ("fault_applied", "server_refused", "success")), "CBT fault/refusal not observed")
        require(record.get("ldap_code") == 49 and record.get("cbt_status") == "SEC_E_BAD_BINDINGS(0x80090346)",
                "CBT rejection lacks actual server status")
        require(record.get("final_acceptance_observed") is False and record.get("application_operations") == 0,
                "CBT refusal admitted application work")
    elif variant == "service-expiry":
        require(all(record.get(key) is True for key in ("short_ticket_observed", "authenticated", "read_before_expiry",
                    "expired_error", "operation_admission_refused", "retired", "success")), "active service-context expiry not demonstrated")
        require(record.get("requested_lifetime_seconds") == 10 and 0 < record.get("observed_remaining_milliseconds", 0) <= 10000,
                "service expiry did not observe an actual short-lived context")
    else:
        require(all(record.get(key) is True for key in ("success", "source_label_matches", "tls_verified", "mutual_authentication",
                    "channel_binding_sent", "complete")), "Kerberos/TLS protection facts missing")
        require(record.get("channel_bound") is False and record.get("channel_binding_peer_verification") == "unconfirmed",
                "mutual bind manufactured peer CBT acknowledgement")
        require(record.get("tls_version", 0) >= 771 and record.get("cipher_bits", 0) >= 128 and record.get("sasl_protection") == "none",
                "Kerberos/TLS profile differs from required protection")


def sasl_result(record, variant, case_id, peer=None):
    if variant == "selected-sign":
        require(record.get("success") is True and record.get("final_acceptance_observed") is True
                and record.get("actual_mechanism_layer") == 2 and record.get("client_refused_mismatch") is True,
                "exact-layer mismatch was not observed/refused")
        require(record.get("write_state") == "not-attempted" and record.get("probe_application_operations") == 0,
                "layer mismatch admitted application work")
        return
    protection = record.get("protection", {})
    mode = 2 if "-sign-" in case_id else 3
    require(record.get("success") is True and record.get("root_dse_verified") is True and record.get("identity_verified") is True,
            "SASL public identity/read preflight missing")
    require(protection.get("Backend") == 1 and protection.get("Authentication") == 2 and protection.get("Transport") == 0
            and protection.get("SASLProtection") == mode and protection.get("MutualAuthentication") is True
            and protection.get("Complete") is True and protection.get("TLSVerified") is False, "SASL protection facts differ from request")
    require(protection.get("SASLEncryptionType") in (17, 18, 19, 20), "SASL AES profile unobserved")
    require(protection.get("SASLCipherBits", 0) >= 128 if mode == 3 else protection.get("SASLCipherBits") == 0,
            "SASL cipher strength was inferred incorrectly")
    if variant in ("tampered", "reordered", "truncated-prefix", "truncated-body"):
        require(all(record.get(key) is True for key in ("retired", "subsequent_write_not_submitted", "reconciliation_read_only",
                    "reconciliation_matches")), "fault did not retire/reconcile the uncertain session")
        if variant == "reordered":
            require(record.get("write_state") == "not-attempted" and record.get("error_class") == "invalid-request",
                    "reordered read was relabelled as a submitted mutation")
        else:
            require(record.get("write_state") == "uncertain" and record.get("error_class") == "uncertain",
                    "damaged write outcome lost uncertainty")
        require(peer and peer.get("injected") is True and peer.get("fault_record_forwarded") is True and peer.get("complete") is True,
                "fault was attempted without actual forwarding evidence")
        if variant == "reordered":
            require(record.get("preflight_schema_bytes", 0) > 65535 and peer.get("server_protected_records", 0) >= 2,
                    "reordering probe did not prove multiple actual protected records")
    else:
        require(record.get("write_state") == "accepted" and record.get("readback_matches") is True, "SASL write/readback not verified")


def outer_cleanup(record):
    require(record.get("verified") is True, "outer cleanup unverified")
    peers = record.get("independent_domain_controllers", [])
    require(len(peers) == 2 and len({item.get("server") for item in peers}) == 2, "independent two-DC cleanup missing")
    for peer in peers:
        require(peer.get("verified") is True and peer.get("live_owned_objects_remaining") == 0
                and peer.get("exact_policy_baseline_restored") is True, "DC cleanup/policy baseline unverified")
    for system in ("windows", "linux", "host"):
        item = record.get(system + "_credentials", {})
        require(item.get("verified") is True and item.get("private_credentials_remaining") == 0,
                f"{system} private credential retirement missing")
    tls = record.get("tls", {}).get("cleanup", {})
    require(tls.get("verified") is True and tls.get("baseline_preserved") is True and tls.get("owned_certificates_remaining") == 0
            and tls.get("owned_private_keys_remaining") == 0 and tls.get("cached_owned_certificate_presented") is False,
            "TLS certificate/key baseline not restored")


def credential_digests(before, after):
    expected = {"client.keytab", "tgt-only.ccache", "password.ccache", "keytab.ccache", "expiry-probe-2m.ccache"}
    baseline = None
    for observation in (before, after):
        require(observation.get("verified") is True, "caller credential inventory unverified")
        for platform in ("windows", "linux"):
            rows = observation.get("files", {}).get(platform, [])
            hashes = {row.get("name"): row.get("sha256") for row in rows}
            require(len(rows) == 5 and set(hashes) == expected and all(isinstance(value, str)
                    and re.fullmatch("[0-9a-f]{64}", value) for value in hashes.values()), "missing/duplicate caller credential digest")
            if baseline is None:
                baseline = hashes
            require(hashes == baseline, "caller credential files changed between clients or observations")


def kerberos_profile(files, server):
    folder, sasl = f"{KERBEROS}/server{server}", f"{SASL}/server{server}"
    manifest = read(files, folder + "/manifest.json")
    require(manifest.get("server_version") == server and manifest.get("source_revision") == AUTH_SOURCE,
            "profile server/source mismatch")
    require(manifest.get("scope") == "All" and manifest.get("case_filter") == [] and manifest.get("full_expected_case_set") is True,
            "filtered profile cannot qualify the complete matrix")
    expected, rows = expected_cases(), manifest.get("cases", [])
    require(len(rows) == len(expected) and {row.get("case_id") for row in rows} == set(expected), "missing/duplicate/unexpected case identity")
    auth_index = folder + ("/artifact-index.json" if server == "2025" else "/artifact-hashes.json")
    covered = hash_index(files, auth_index) | hash_index(files, sasl + "/artifact-hashes.json")
    require(folder + "/manifest.json" in covered, "profile manifest has no retained hash")
    credential_digests(indexed_read(files, folder + "/credential-digests-before.json", covered),
                       indexed_read(files, folder + "/credential-digests-after.json", covered))
    policy = indexed_read(files, folder + "/strict-policy.json", covered)
    values = {row.get("name"): row.get("value") for row in policy.get("policy_values", []) if row.get("present") is True}
    require(values.get("LdapEnforceChannelBinding") == 2 and values.get("LDAPServerIntegrity") == 2,
            "strict policy prerequisite not recorded")
    require(server != "2025" or values.get("LDAPServerEnforceIntegrity") == 1, "Server2025 signing override unobserved")
    directory = indexed_read(files, folder + "/directory-policy-cleanup.json", covered)
    require(directory.get("contact", {}).get("verified") is True and directory["contact"].get("live_owned_objects_remaining") == 0
            and directory.get("policy", {}).get("exact_presence_type_and_value_restored") is True, "child fixture/policy cleanup incomplete")
    scopes = Counter()
    for row in rows:
        case_id = row["case_id"]
        client, variant, scope = expected[case_id]
        require(row.get("passed") is True and row.get("source_revision") == AUTH_SOURCE and row.get("evidence_scope") == scope,
                f"incorrect case acceptance/scope: {case_id}")
        scopes[scope] += 1
        base = folder if case_id.startswith("auth-") else sasl
        record = indexed_read(files, f"{base}/{case_id}.json", covered)
        identity(record, manifest, client)
        process = indexed_read(files, f"{base}/{case_id}-process.json", covered)
        require(process.get("exit_code") == (1 if scope.startswith("local-") else 0), f"case process failed: {case_id}")
        if case_id.startswith("auth-") or scope.startswith("local-"):
            auth_result(record, variant)
        else:
            peer_path = f"{base}/{case_id}-peer-result.json"
            peer = indexed_read(files, peer_path, covered) if peer_path in files else None
            sasl_result(record, variant, case_id, peer)
            if peer is not None:
                require(peer.get("run_id") == manifest["run_id"] and peer.get("scenario") == variant, "fault relay identity mismatch")
                cleanup = indexed_read(files, f"{base}/{case_id}-peer-cleanup.json", covered)
                require(cleanup.get("verified") is True and cleanup.get("processes_remaining") == 0
                        and cleanup.get("firewall_rules_remaining") == 0, "fault relay independent cleanup incomplete")
    require(scopes == {"live-ad": 68, "local-config": 12, "local-credential": 4}, "local refusals counted as AD qualification")
    cleanup_paths = [name for name in files if name.startswith(folder + "/outer-cleanup") and name.endswith(".json")]
    require(len(cleanup_paths) == 1, "ambiguous/missing final outer cleanup")
    outer_cleanup(indexed_read(files, cleanup_paths[0], covered))
    return {"server": server, "source": AUTH_SOURCE, "platforms": ["windows/amd64", "linux/amd64"],
            "actual_ad_cases": 68, "local_config_cases": 12, "local_credential_cases": 4, "hashed_artifacts_verified": len(covered),
            "independent_outer_cleanup_verified": True}


def tls_profile(files, server):
    folder = f"{LDAP}/server{server}"
    manifest = read(files, folder + "/manifest.json")
    require(manifest.get("server_version") == server and manifest.get("source_revision") == TLS_SOURCE, "TLS profile source/server mismatch")
    covered = hash_index(files, folder + "/artifact-hashes.json")
    require(folder + "/manifest.json" in covered, "TLS manifest has no retained hash")
    for client in ("windows", "linux"):
        for transport in ("ldaps", "starttls"):
            base = f"{folder}/{client}-{transport}"
            record = indexed_read(files, base + "-sdk.json", covered)
            require(record.get("source_revision") == TLS_SOURCE and record.get("run_id") == manifest["run_id"]
                    and record.get("platform") == client + "/amd64" and record.get("go_version") == "go1.27.4", "TLS case identity mismatch")
            protection = record.get("protection", {})
            require(record.get("passed") is True and protection.get("Backend") == 1 and protection.get("Authentication") == 1
                    and protection.get("TLSVerified") is True and protection.get("Complete") is True
                    and protection.get("CipherBits", 0) >= 128 and protection.get("TLSVersion", 0) >= 771, "TLS simple bind protection missing")
            for variant in ("valid", "expired", "untrusted", "wrong-host", *(["refusal"] if transport == "starttls" else [])):
                process = indexed_read(files, f"{base}-{variant}-process.json", covered)
                report = json.loads(process["stdout"])
                require(process.get("exit_code") == 0 and report.get("passed") is True and report.get("source_revision") == TLS_SOURCE,
                        "controlled TLS process/source failed")
                peer = indexed_read(files, f"{base}-{variant}-peer.json", covered)["connections"]
                require(len(peer) == 1, "controlled peer has ambiguous connections")
                if variant == "valid":
                    require(report.get("tls_verified") is True and report.get("cipher_bits", 0) >= 128
                            and peer[0].get("handshake_complete") is True and peer[0].get("upstream_handshake_complete") is True
                            and peer[0].get("bind_requests") == 1 and peer[0].get("ldap_bytes_forwarded", 0) > 0,
                            "TLS control did not verify protection and forward actual LDAP")
                else:
                    require(report.get("tls_verified") is False and report.get("tls_failure") is True, "invalid TLS peer accepted")
                    require(all(peer[0].get(key) == 0 for key in ("bind_requests", "plaintext_bind_requests", "ldap_bytes_received", "ldap_bytes_forwarded")),
                            "TLS failure exposed LDAP/credential bytes")
    cleanup = indexed_read(files, folder + "/cleanup.json", covered)
    require(cleanup.get("directory", {}).get("verified") is True and cleanup["directory"].get("live_owned_objects_remaining") == 0,
            "TLS directory cleanup incomplete")
    item = cleanup.get("tls", {}).get("cleanup", {})
    require(item.get("verified") is True and item.get("baseline_preserved") is True and item.get("owned_certificates_remaining") == 0
            and item.get("owned_private_keys_remaining") == 0 and item.get("cached_owned_certificate_presented") is False,
            "TLS certificate/key cleanup incomplete")
    negative = indexed_read(files, folder + "/negative-cleanup.json", covered)
    require(negative.get("verified") is True and all(negative.get(key) == 0 for key in (
        "owned_processes_remaining", "owned_private_key_files_remaining", "owned_firewall_rules_remaining")), "controlled peer cleanup incomplete")
    return {"server": server, "source": TLS_SOURCE, "direct_sdk_cells": 4, "controlled_peer_cases": 18,
            "hashed_artifacts_verified": len(covered), "independent_cleanup_verified": True}


def source_proofs(root, files):
    _, auth = committed_files(root, AUTH_SOURCE)
    proof = read(files, KERBEROS + "/build/canonical-input-proof.json")
    require(proof.get("source_revision") == AUTH_SOURCE and proof.get("all_tracked_inputs_canonical_git_bytes") is True,
            "authentication build lacks canonical source proof")
    hashes = proof.get("all_paths_sha256", {})
    require(set(hashes) == set(auth) and len(auth) == proof.get("files_verified"), "authentication source proof omitted committed inputs")
    require(all(digest(auth[name]) == expected for name, expected in hashes.items()), "authentication source proof differs from raw Git blobs")
    _, tls = committed_files(root, TLS_SOURCE)
    tls_proof = read(files, LDAP + "/collector-source-ca38eb1.json")
    runtime = tls_proof.get("runtime_files_sha256", {})
    require(tls_proof.get("source_revision") == TLS_SOURCE and len(runtime) == 437
            and all(name in tls and digest(tls[name]) == expected for name, expected in runtime.items()),
            "TLS runtime source proof differs from raw Git blobs")
    return {"authentication_all_canonical_inputs_verified": len(auth), "authentication_source": AUTH_SOURCE,
            "tls_runtime_canonical_inputs_verified": len(runtime), "tls_source": TLS_SOURCE,
            "tls_limit": "437 runtime files verified against Git blobs; no blanket raw-Git identity for all historical archive/checkout files"}


def audit(root, revision, pending_auth_revision=None):
    commit, files = committed_files(root, revision)
    result = {"schema_version": 1, "audited_commit": commit, "source_basis": "raw Git blobs",
              "scope": "retained authentication evidence integrity; not current-source or SDK/provider release qualification",
              "tls_simple": [], "kerberos_sasl": [], "pending_candidate_evidence": [], "missing_merged_coverage": [],
              "release_status": "pending; see docs/provider-qualification.md and open feature gates"}
    result["source_proofs"] = source_proofs(root, files)
    for server in ("2016", "2019", "2022", "2025"):
        result["tls_simple"].append(tls_profile(files, server))
        if f"{KERBEROS}/server{server}/manifest.json" in files:
            result["kerberos_sasl"].append(kerberos_profile(files, server))
        else:
            result["missing_merged_coverage"].append({"server": server, "feature": "kerberos-sasl", "state": "pending-evidence-merge", "issue": 194})
    if pending_auth_revision:
        require(re.fullmatch(r"[0-9a-f]{40}", pending_auth_revision), "pending evidence must use an immutable full commit")
        candidate, pending = committed_files(root, pending_auth_revision)
        item = kerberos_profile(pending, "2016")
        item.update(evidence_commit=candidate, integration="pending PR201; not merged evidence in audited_commit")
        result["pending_candidate_evidence"].append(item)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--pending-auth-revision")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(args.root.resolve(), args.revision, args.pending_auth_revision)
        write_json(args.output, report)
    except (ValueError, KeyError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
