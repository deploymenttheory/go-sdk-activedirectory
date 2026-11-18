"""Offline checks for the MIT fixture producer's pre-authentication boundary."""
import base64
import hashlib
import importlib.util
import pathlib
import unittest
from unittest import mock

source = pathlib.Path(__file__).with_name("kerberos-reference.py")
spec = importlib.util.spec_from_file_location("kerberos_reference", source)
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


class ReferenceInputTests(unittest.TestCase):
    def test_tool_failures_export_only_fixed_stage_exit_and_category(self):
        secret = b"never-publish-this-secret"
        process = mock.Mock(returncode=1, stderr=b"Password incorrect " + secret)
        with mock.patch.object(reference.subprocess, "run", return_value=process):
            with self.assertRaises(reference.ToolFailure) as error:
                reference.tool({}, "password-kinit", ["fixture-tool"])
        self.assertEqual(error.exception.step, "password-kinit")
        self.assertEqual(error.exception.exit_code, 1)
        self.assertEqual(error.exception.category, "preauthentication-failed")
        self.assertNotIn(secret.decode(), str(error.exception))
        self.assertEqual(reference.tool_failure_category("ktutil", b"Password incorrect " + secret), "unclassified")
        self.assertEqual(reference.tool_failure_category("password-kinit", secret), "unclassified")

    def fixture(self):
        run = "sdk04-offline-reference"
        return {
            "run_id": run,
            "principal": "sdkkrb" + hashlib.sha256(run.encode()).hexdigest()[:12] + "@AD.SDK.TEST",
            "client_kvno": 2,
            "server": "adsdk25dc1.ad.sdk.test",
            "linux_owner": "9566955a-6418-4f64-8575-6997aebe50f5",
            "password_base64": base64.b64encode(b"fixture-only-strong-password!").decode(),
        }

    def test_all_explicit_lab_profiles(self):
        for version in ("16", "19", "22", "25"):
            value = self.fixture()
            value["server"] = "adsdk" + version + "dc1.ad.sdk.test"
            self.assertEqual(reference.validate_request(value), b"fixture-only-strong-password!")

    def test_identity_and_command_injection_rejected_before_authentication(self):
        for field, invalid in (
            ("run_id", "../outside"),
            ("run_id", "UPPERCASE"),
            ("principal", "Administrator@AD.SDK.TEST"),
            ("principal", "user@OTHER.TEST"),
            ("server", "adsdk25dc1.ad.sdk.test;echo injected"),
            ("server", "dc1.production.test"),
            ("server", "adsdk25dc2.ad.sdk.test"),
            ("client_kvno", 0),
            ("client_kvno", True),
            ("client_kvno", 2**32),
            ("linux_owner", "../outside"),
        ):
            value = self.fixture()
            value[field] = invalid
            with self.assertRaises(reference.FixtureError):
                reference.validate_request(value)

    def test_secret_bounds_and_non_echoing_errors(self):
        for secret in (b"short", b"a" * 257, b"a" * 24 + b"\n", b"a" * 24 + b"\r", b"a" * 24 + b"\0"):
            value = self.fixture()
            value["password_base64"] = base64.b64encode(secret).decode()
            with self.assertRaises(reference.FixtureError) as error:
                reference.validate_request(value)
            self.assertNotIn(value["password_base64"], str(error.exception))
        value = self.fixture()
        value["password_base64"] = "not-valid-base64!"
        with self.assertRaises(reference.FixtureError):
            reference.validate_request(value)

    def test_unknown_input_is_not_silently_accepted(self):
        value = self.fixture()
        value["shell_command"] = "injected"
        with self.assertRaises(reference.FixtureError):
            reference.validate_request(value)


if __name__ == "__main__":
    unittest.main()
