import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from scouter.cli import main
from tests.helpers import fake_service, free_port


def run(*argv):
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_requires_authorization_flag_without_scope(self):
        code, _, err = run("-t", "127.0.0.1", "--backend", "socket")
        self.assertEqual(code, 2)
        self.assertIn("--confirm-authorized", err)

    def test_requires_some_target(self):
        code, _, err = run("--backend", "socket")
        self.assertEqual(code, 2)

    def test_refuses_out_of_scope_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = os.path.join(tmp, "scope.txt")
            with open(scope, "w") as fh:
                fh.write("10.9.9.0/30\n")
            code, _, err = run("-s", scope, "-t", "127.0.0.1", "-o", tmp, "--backend", "socket")
        self.assertEqual(code, 2)
        self.assertIn("out of scope", err)

    def test_dry_run_sends_nothing_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = os.path.join(tmp, "out")
            code, out, _ = run("-t", "127.0.0.1", "--confirm-authorized", "--dry-run",
                               "--backend", "socket", "-o", out_dir)
            self.assertEqual(code, 0)
            self.assertIn("would scan", out)
            self.assertFalse(os.path.exists(out_dir))

    def test_full_scan_writes_folder_structure(self):
        with fake_service(b"SSH-2.0-OpenSSH_9.6\r\n") as port, tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run("-t", "127.0.0.1", "--confirm-authorized", "-p", "%d,%d" % (port, free_port()),
                               "--backend", "socket", "--timeout", "1", "-o", tmp)
            self.assertEqual(code, 0)
            self.assertIn("Power level: 1", out)
            host_dir = os.path.join(tmp, "127.0.0.1")
            for name in ("scan.json", "report.md", os.path.join("raw", "banners.txt")):
                self.assertTrue(os.path.exists(os.path.join(host_dir, name)), name)
            self.assertTrue(os.path.exists(os.path.join(tmp, "summary.md")))
            with open(os.path.join(host_dir, "scan.json")) as fh:
                data = json.load(fh)
            self.assertEqual(data["services"][0]["name"], "ssh")
            with open(os.path.join(host_dir, "report.md")) as fh:
                report = fh.read()
            self.assertIn("Suggested next steps", report)
            self.assertIn("OpenSSH", report)

    def test_scope_file_expands_and_honours_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope = os.path.join(tmp, "scope.txt")
            with open(scope, "w") as fh:
                fh.write("127.0.0.1\n127.0.0.2\n!127.0.0.2\n")
            code, out, _ = run("-s", scope, "--dry-run", "--backend", "socket", "-o", tmp)
        self.assertEqual(code, 0)
        self.assertIn("127.0.0.1", out)
        self.assertNotIn("127.0.0.2", out)


if __name__ == "__main__":
    unittest.main()
