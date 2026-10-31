"""Validate detection content embedded in skills and the documented tshark commands.

Optional dependencies are used when present and the tests are skipped (with the reason) otherwise:
  - yara-python      -> compiles every ```yara block   (yara-authoring)
  - sigma-cli + pySigma-backend-splunk -> `sigma check` and `sigma convert` on every Sigma block
                         (sigma-authoring, sigma-conversion, and skills embedding Sigma rules)
  - tshark           -> runs the pcap-analysis commands against tests/fixtures/http_dns.pcap
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "claude_blue.py"
PCAP = ROOT / "tests" / "fixtures" / "http_dns.pcap"
SIGMA = os.environ.get("SIGMA_CLI") or shutil.which("sigma")


def extract(out):
    subprocess.run([sys.executable, str(CLI), "extract-rules", "--out", out], check=True, capture_output=True)
    return Path(out)


class EmbeddedYara(unittest.TestCase):
    def test_yara_authoring_rules_compile(self):
        try:
            import yara
        except ImportError:
            self.skipTest("yara-python not installed")
        with tempfile.TemporaryDirectory() as tmp:
            rules = sorted((extract(tmp) / "yara").glob("*.yar"))
            self.assertTrue(rules, "no yara blocks found")
            for rule in rules:
                compiled = yara.compile(filepath=str(rule))
                self.assertEqual(compiled.match(data=b"MZ" + b"\0" * 64), [], rule.name)


class EmbeddedSigma(unittest.TestCase):
    def setUp(self):
        if not SIGMA:
            self.skipTest("sigma-cli not installed (set SIGMA_CLI or put `sigma` on PATH)")

    def test_sigma_check_has_no_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            sigma_dir = extract(tmp) / "sigma"
            self.assertGreaterEqual(len(list(sigma_dir.glob("*.yml"))), 4)
            result = subprocess.run([SIGMA, "check", str(sigma_dir)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Found 0 errors, 0 condition errors and 0 issues", result.stdout)

    def test_sigma_conversion_to_splunk(self):
        with tempfile.TemporaryDirectory() as tmp:
            sigma_dir = extract(tmp) / "sigma"
            result = subprocess.run([SIGMA, "convert", "-t", "splunk", "-p", "splunk_windows", str(sigma_dir)],
                                    text=True, capture_output=True)
            if "Unknown target" in result.stdout + result.stderr:
                self.skipTest("pySigma-backend-splunk not installed")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('CommandLine="*comsvcs*" CommandLine="*MiniDump*"', result.stdout)
            self.assertIn("EventCode=4769", result.stdout)


@unittest.skipUnless(shutil.which("tshark"), "tshark not installed")
class PcapAnalysis(unittest.TestCase):
    def tshark(self, *args):
        return subprocess.run(["tshark", "-r", str(PCAP), *args], text=True, capture_output=True, check=True).stdout

    def test_conversations(self):
        self.assertIn("203.0.113.10:80", self.tshark("-q", "-z", "conv,tcp"))

    def test_dns_and_http_extraction(self):
        dns = self.tshark("-Y", "dns.flags.response==0", "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name")
        self.assertIn("updates.evil-example.test", dns)
        http = self.tshark("-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.request.uri", "-e", "http.user_agent")
        self.assertIn("/gate.php?id=abc", http)
        self.assertIn("MSIE 6.0", http)

    def test_tls_fingerprint_fields_exist(self):
        fields = subprocess.run(["tshark", "-G", "fields"], text=True, capture_output=True).stdout
        for field in ("tls.handshake.ja3", "tls.handshake.ja4", "tls.handshake.extensions_server_name"):
            self.assertIn(f"\t{field}\t", fields)

    def test_export_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.tshark("-q", "--export-objects", f"http,{tmp}")
            self.assertTrue(any(Path(tmp).iterdir()))


if __name__ == "__main__":
    unittest.main()
