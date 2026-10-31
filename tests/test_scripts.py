"""Execute every bundled skill script against the fixtures in tests/fixtures."""
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
FIX = ROOT / "tests" / "fixtures"


def run(script, *args, expect=0):
    result = subprocess.run([sys.executable, str(script), *map(str, args)], text=True, capture_output=True)
    if expect is not None:
        assert result.returncode == expect, f"{script.name} exit {result.returncode}: {result.stderr}"
    return result


class TimelineAnalysis(unittest.TestCase):
    script = SKILLS / "dfir/timeline-analysis/scripts/merge_timeline.py"

    def test_merges_sources_in_utc_order_and_reports_bad_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "edr.csv", Path(tmp) / "ct.jsonl"
            a.write_text("Timestamp,Host\n2025-03-01T10:00:05Z,WS1\n2025-03-01 09:59:00,WS1\nbad,WS1\n")
            b.write_text('{"eventTime":"2025-03-01T11:00:01+01:00","eventName":"ConsoleLogin"}\n'
                         '{"eventTime":1740823200000,"eventName":"GetObject"}\n')
            out = run(self.script, "--source", f"edr={a}:Timestamp", "--source", f"ct={b}:eventTime")
            rows = list(csv.DictReader(out.stdout.splitlines()))
            self.assertEqual([r["timestamp_utc"][:19] for r in rows],
                             ["2025-03-01T09:59:00", "2025-03-01T10:00:00", "2025-03-01T10:00:01", "2025-03-01T10:00:05"])
            self.assertIn("1 rows in source 'edr'", out.stderr)

    def test_assume_tz_and_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "local.csv"
            a.write_text("t,x\n2025-03-01 12:00:00,1\n2025-03-02 12:00:00,2\n")
            out = run(self.script, "--source", f"l={a}:t", "--assume-tz", "+02:00", "--end", "2025-03-01T23:00:00Z")
            rows = list(csv.DictReader(out.stdout.splitlines()))
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["timestamp_utc"].startswith("2025-03-01T10:00:00"))


class BeaconingHunt(unittest.TestCase):
    def test_regular_beacon_scores_above_random_traffic(self):
        import random
        random.seed(7)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "conns.csv"
            with path.open("w", newline="") as handle:
                w = csv.writer(handle)
                w.writerow(["ts", "src", "dst", "bytes"])
                for i in range(60):
                    w.writerow([1700000000 + i * 60 + random.uniform(-3, 3), "10.0.0.5", "c2.example", 512])
                for _ in range(40):
                    w.writerow([1700000000 + random.uniform(0, 7200), "10.0.0.9", "cdn.example", random.randint(100, 90000)])
            out = run(SKILLS / "threat-hunting/beaconing-hunt/scripts/beacon_score.py", path, "--min-count", "20")
            rows = list(csv.DictReader(out.stdout.splitlines()))
            self.assertEqual(rows[0]["dst"], "c2.example")
            self.assertGreater(float(rows[0]["score"]), 80)
            self.assertLess(float(rows[1]["score"]), 50)


class EmailHeaderAnalysis(unittest.TestCase):
    def test_flags_spoofing_indicators(self):
        out = run(SKILLS / "email-security/email-header-analysis/scripts/parse_eml.py", FIX / "phish.eml")
        data = json.loads(out.stdout)
        self.assertEqual(data["authentication_results"]["dmarc"], "fail")
        self.assertIn("reply-to domain differs from From domain", data["flags"])
        self.assertEqual(data["received_hops_oldest_first"][0]["ips"], ["198.51.100.25"])
        self.assertEqual(data["urls_defanged"], ["hxxps://login[.]corp-payroll[.]example/verify?u=alice"])
        self.assertEqual(data["attachments"][0]["filename"], "invoice.html")


class IocAssessment(unittest.TestCase):
    def test_refangs_and_classifies(self):
        text = ("C2 hxxps://upd-cdn[.]example/api and 8.8.4.4, internal 10.0.0.5. loader.exe "
                f"sha256 {'a' * 64} md5 {'b' * 32}. Mail bad[@]evil-example[.]test. CVE-2024-3400\n")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.txt"
            path.write_text(text)
            data = json.loads(run(SKILLS / "threat-intelligence/ioc-assessment/scripts/ioc_extract.py", path).stdout)
            self.assertEqual(data["url"], ["https://upd-cdn.example/api"])
            self.assertEqual(data["ipv4"], ["8.8.4.4"])
            self.assertEqual(data["non_global_ip"], ["10.0.0.5"])
            self.assertNotIn("loader.exe", data["domain"])
            self.assertEqual(data["cve"], ["CVE-2024-3400"])
            defanged = json.loads(run(SKILLS / "threat-intelligence/ioc-assessment/scripts/ioc_extract.py", path, "--defang").stdout)
            self.assertEqual(defanged["url"], ["hxxps://upd-cdn[.]example/api"])


class GithubActionsHardening(unittest.TestCase):
    script = SKILLS / "devsecops/github-actions-hardening/scripts/gha_audit.py"

    def test_bad_workflow(self):
        out = run(self.script, FIX / "workflow_bad.yml", expect=1)
        rules = {f["rule"] for f in json.loads(out.stdout)}
        self.assertEqual(rules, {"missing-top-level-permissions", "unpinned-action",
                                 "privileged-untrusted-checkout", "script-injection"})

    def test_good_workflow(self):
        out = run(self.script, FIX / "workflow_good.yml", expect=0)
        self.assertEqual(json.loads(out.stdout), [])


class K8sRbacReview(unittest.TestCase):
    def test_risky_bindings(self):
        out = run(SKILLS / "kubernetes-security/k8s-rbac-review/scripts/rbac_audit.py", FIX / "rbac.json")
        found = {(f["subject"], f["resource"], f["severity"]) for f in json.loads(out.stdout)}
        self.assertIn(("ServiceAccount:build/ci", "*", "critical"), found)
        self.assertIn(("Group:system:authenticated", "secrets", "critical"), found)
        self.assertIn(("User:bob", "pods/exec", "high"), found)
        self.assertFalse(any(s.startswith("User:alice") for s, _, _ in found))


class CloudtrailInvestigation(unittest.TestCase):
    def test_summary(self):
        out = run(SKILLS / "aws-security/cloudtrail-investigation/scripts/cloudtrail_summary.py", FIX / "cloudtrail.json")
        data = json.loads(out.stdout)
        self.assertEqual(data["record_count"], 4)
        self.assertEqual([e["event"] for e in data["high_risk_events"]], ["ConsoleLogin", "CreateAccessKey", "StopLogging"])
        alice = data["identities"][0]
        self.assertEqual((alice["events"], alice["errors"], alice["access_keys"]), (3, 1, ["ASIAEXAMPLE1"]))

    def test_lookup_events_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = json.loads((FIX / "cloudtrail.json").read_text())["Records"]
            path = Path(tmp) / "lookup.json"
            path.write_text(json.dumps({"Events": [{"CloudTrailEvent": json.dumps(r)} for r in records]}))
            data = json.loads(run(SKILLS / "aws-security/cloudtrail-investigation/scripts/cloudtrail_summary.py", path).stdout)
            self.assertEqual(data["record_count"], 4)


class AwsIamReview(unittest.TestCase):
    def test_policy_lint(self):
        out = run(SKILLS / "aws-security/aws-iam-review/scripts/iam_policy_lint.py", FIX / "iam_policy.json", expect=1)
        found = {(f["rule"], f["where"].rsplit(" ", 1)[-1]) for f in json.loads(out.stdout)}
        self.assertIn(("admin-wildcard", "Admin"), found)
        self.assertIn(("privilege-escalation-actions", "PassAny"), found)
        self.assertIn(("service-wildcard", "S3All"), found)
        self.assertFalse(any(sid in ("ReadOnly", "DenyStuff") for _, sid in found))


class PasswordSprayDetection(unittest.TestCase):
    def test_spray_and_success(self):
        out = run(SKILLS / "identity-security/password-spray-detection/scripts/spray_detect.py", FIX / "auth_events.csv", expect=1)
        data = json.loads(out.stdout)
        self.assertEqual([(s["source"], s["type"]) for s in data["flagged_sources"]], [("198.51.100.66", "spray")])
        self.assertEqual(data["successes_from_flagged_sources"][0]["user"], "user7@corp.example")


if __name__ == "__main__":
    unittest.main()
