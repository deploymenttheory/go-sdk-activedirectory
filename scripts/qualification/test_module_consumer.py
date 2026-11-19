#!/usr/bin/env python3
"""Offline adversarial checks for the publication boundary; no network or AD."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location("module_consumer", Path(__file__).with_name("module_consumer.py"))
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)


class PublicationBoundaryTests(unittest.TestCase):
    def test_rejects_replacements_even_when_indented_or_block_form(self):
        valid = f"module {consumer.MODULE}\n\ngo 1.27.4\n".encode()
        self.assertEqual(consumer.validate_module(valid), "1.27.4")
        for suffix in (b"replace x => ../local\n", b"  replace x => ../local\n", b"\nreplace (\nx => ../local\n)\n"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                consumer.validate_module(valid + suffix)

    def test_rejects_private_nested_and_noncanonical_paths(self):
        for name in ("../secret", "/absolute", "a/../../secret", "a//b", "a\\b", "C:/secret",
                     "tmp/worktrees/file.go", "x/.git/config", "a/worktrees/b", "client.clixml",
                     "secret.ccache", "secret.keytab", "private.pfx", "inner/go.mod", "inner/go.sum"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                consumer.safe_path(name)
        self.assertEqual(str(consumer.safe_path("3rd_party/ldap/LICENSE")), "3rd_party/ldap/LICENSE")
        consumer.safe_path("3rd_party/ldap/upstream-go.mod.txt")

    def test_zip_requires_every_committed_byte_and_no_extra_path(self):
        files = {"go.mod": b"module example.invalid\n", "3rd_party/ldap/LICENSE": b"license\r\n"}
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "module.zip"
            for fault in ("valid", "omit-license", "normalize-license", "extra", "duplicate"):
                with self.subTest(fault=fault):
                    with zipfile.ZipFile(archive, "w") as handle:
                        for name, raw in files.items():
                            if fault == "omit-license" and name.endswith("LICENSE"):
                                continue
                            if fault == "normalize-license":
                                raw = raw.replace(b"\r\n", b"\n")
                            handle.writestr("example.invalid@v0.0.1/" + name, raw)
                        if fault == "extra":
                            handle.writestr("example.invalid@v0.0.1/tmp/private", b"data")
                        if fault == "duplicate":
                            handle.writestr("example.invalid@v0.0.1/go.mod", b"other")
                    if fault == "valid":
                        consumer.verify_zip(archive, "example.invalid", "v0.0.1", files)
                    else:
                        with self.assertRaises(ValueError):
                            consumer.verify_zip(archive, "example.invalid", "v0.0.1", files)

    def test_import_resolution_rejects_replacement_and_cache_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cache"
            item = {"ImportPath": consumer.MODULE + "/conditions", "Dir": str(root / "conditions"),
                    "Module": {"Path": consumer.MODULE, "Dir": str(root)}}
            self.assertEqual(consumer.verify_resolution([item], root), 1)
            for fault in ("replace", "module", "directory"):
                with self.subTest(fault=fault):
                    changed = json.loads(json.dumps(item))
                    if fault == "replace":
                        changed["Module"]["Replace"] = {"Dir": str(root)}
                    elif fault == "module":
                        changed["Module"]["Path"] += "/3rd_party/ldap"
                    else:
                        changed["Dir"] = str(Path(directory) / "checkout")
                    with self.assertRaises(ValueError):
                        consumer.verify_resolution([changed], root)
            with self.assertRaises(ValueError):
                consumer.verify_resolution([], root)

    def test_snapshot_reads_raw_git_blobs_and_rejects_gitlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*arguments):
                return subprocess.run(["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root), *arguments],
                                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

            git("init", "-q")
            git("config", "user.name", "Offline fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "core.autocrlf", "false")
            (root / "3rd_party" / "ldap").mkdir(parents=True)
            (root / "go.mod").write_bytes(b"module example.invalid\n")
            (root / "3rd_party/ldap/LICENSE").write_bytes(b"raw license\n")
            git("add", ".")
            git("commit", "-qm", "fixture")
            (root / "3rd_party/ldap/LICENSE").write_bytes(b"uncommitted changed license\r\n")
            commit, files = consumer.committed_files(root, "HEAD")
            self.assertEqual(files["3rd_party/ldap/LICENSE"], b"raw license\n")
            git("update-index", "--add", "--cacheinfo", f"160000,{commit},3rd_party/submodule")
            git("commit", "-qm", "bad gitlink")
            with self.assertRaisesRegex(ValueError, "nonregular"):
                consumer.committed_files(root, "HEAD")


if __name__ == "__main__":
    unittest.main()
