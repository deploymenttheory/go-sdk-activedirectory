#!/usr/bin/env python3
"""Reject plausible but insufficient qualification claims using retained controls."""

from collections import Counter
import copy
import json
from pathlib import Path
import unittest

import audit_auth_evidence as audit

ROOT = Path(__file__).resolve().parents[2]


def artifact(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))


class AuthenticationEvidenceTests(unittest.TestCase):
    def test_expected_case_identity_does_not_count_local_refusals_as_ad(self):
        cases = audit.expected_cases()
        self.assertEqual(len(cases), 84)
        self.assertEqual(Counter(value[2] for value in cases.values()),
                         {"live-ad": 68, "local-config": 12, "local-credential": 4})

    def test_cbt_requires_actual_server_status_and_no_application_work(self):
        record = artifact(audit.KERBEROS + "/server2025/auth-linux-ldaps-cbt-missing.json")
        audit.auth_result(record, "cbt-missing")
        for key, value in (("ldap_code", 0), ("cbt_status", ""), ("fault_applied", False),
                           ("server_refused", False), ("final_acceptance_observed", True), ("application_operations", 1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit.auth_result(record | {key: value}, "cbt-missing")

    def test_tls_mutual_authentication_cannot_manufacture_peer_cbt_confirmation(self):
        record = artifact(audit.KERBEROS + "/server2025/auth-linux-ldaps-cache.json")
        audit.auth_result(record, "cache")
        for key, value in (("channel_bound", True), ("channel_binding_sent", False),
                           ("tls_verified", False), ("mutual_authentication", False), ("cipher_bits", 0)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit.auth_result(record | {key: value}, "cache")

    def test_short_context_expiry_requires_before_and_after_observations(self):
        record = artifact(audit.KERBEROS + "/server2025/auth-linux-ldaps-service-expiry.json")
        audit.auth_result(record, "service-expiry")
        for key, value in (("observed_remaining_milliseconds", 0), ("read_before_expiry", False),
                           ("operation_admission_refused", False), ("retired", False)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit.auth_result(record | {key: value}, "service-expiry")

    def test_damaged_write_requires_uncertainty_retirement_and_forwarded_fault(self):
        case_id = "sasl-linux-seal-tampered"
        record = artifact(audit.SASL + f"/server2025/{case_id}.json")
        peer = artifact(audit.SASL + f"/server2025/{case_id}-peer-result.json")
        audit.sasl_result(record, "tampered", case_id, peer)
        for key, value in (("write_state", "accepted"), ("retired", False),
                           ("subsequent_write_not_submitted", False), ("reconciliation_read_only", False)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit.sasl_result(record | {key: value}, "tampered", case_id, peer)
        with self.assertRaises(ValueError):
            audit.sasl_result(record, "tampered", case_id, peer | {"fault_record_forwarded": False})

    def test_reordered_read_does_not_invent_a_submitted_write(self):
        case_id = "sasl-linux-seal-reordered"
        record = artifact(audit.SASL + f"/server2025/{case_id}.json")
        peer = artifact(audit.SASL + f"/server2025/{case_id}-peer-result.json")
        audit.sasl_result(record, "reordered", case_id, peer)
        with self.assertRaises(ValueError):
            audit.sasl_result(record | {"write_state": "uncertain"}, "reordered", case_id, peer)
        with self.assertRaises(ValueError):
            audit.sasl_result(record, "reordered", case_id, peer | {"server_protected_records": 1})

    def test_reported_cleanup_success_cannot_hide_one_dc_or_private_credentials(self):
        record = artifact(audit.KERBEROS + "/server2025/outer-cleanup.json")
        audit.outer_cleanup(record)
        changed = copy.deepcopy(record)
        changed["independent_domain_controllers"][1]["exact_policy_baseline_restored"] = False
        with self.assertRaises(ValueError):
            audit.outer_cleanup(changed)
        with self.assertRaises(ValueError):
            audit.outer_cleanup(record | {"independent_domain_controllers": record["independent_domain_controllers"][:1]})
        with self.assertRaises(ValueError):
            audit.outer_cleanup(record | {"linux_credentials": {"verified": True, "private_credentials_remaining": 1}})

    def test_hash_index_rejects_changed_bytes_missing_files_and_parent_escape(self):
        files = {"capture/index.json": b'{"files":{"result.json":"' + b"0" * 64 + b'"}}', "capture/result.json": b"result"}
        with self.assertRaises(ValueError):
            audit.hash_index(files, "capture/index.json")
        files["capture/index.json"] = json.dumps({"files": {"result.json": audit.digest(b"result")}}).encode()
        self.assertEqual(audit.hash_index(files, "capture/index.json"), {"capture/result.json"})
        del files["capture/result.json"]
        with self.assertRaises(ValueError):
            audit.hash_index(files, "capture/index.json")
        files["capture/index.json"] = json.dumps({"files": {"../result.json": "0" * 64}}).encode()
        with self.assertRaises(ValueError):
            audit.hash_index(files, "capture/index.json")

    def test_unchanged_digest_claim_cannot_hide_a_missing_or_modified_caller_file(self):
        before = artifact(audit.KERBEROS + "/server2025/credential-digests-before.json")
        after = artifact(audit.KERBEROS + "/server2025/credential-digests-after.json")
        audit.credential_digests(before, after)
        changed = copy.deepcopy(after)
        changed["files"]["linux"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            audit.credential_digests(before, changed)
        changed = copy.deepcopy(after)
        changed["files"]["windows"].pop()
        with self.assertRaises(ValueError):
            audit.credential_digests(before, changed)


if __name__ == "__main__":
    unittest.main()
