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


class PlaybookLint(unittest.TestCase):
    script = SKILLS / "security-automation/soar-playbook-design/scripts/playbook_lint.py"

    def test_clean_playbook_passes(self):
        out = run(self.script, FIX / "playbook_good.json")
        self.assertEqual(json.loads(out.stdout), [])

    def test_unsafe_playbook_is_rejected_with_specific_findings(self):
        out = run(self.script, FIX / "playbook_bad.json", expect=1)
        rules = {(f["rule"], f["step"]) for f in json.loads(out.stdout)}
        for expected in [("no-kill-switch", None), ("inline-secret", "lookup"), ("decision-without-default", "check"),
                         ("dangling-reference", "isolate"), ("disruptive-without-approval", "isolate"),
                         ("unmarked-disruptive-action", "isolate"), ("unbounded-loop", "poll"),
                         ("unreachable", "orphan"), ("never-terminates", "lookup")]:
            self.assertIn(expected, rules)
        # vault references are not secrets
        self.assertNotIn(("inline-secret", "enrich"), rules)

    def test_bounded_loop_and_auto_approval_rules(self):
        book = {"owner": "x", "kill_switch": "y", "start": "a", "steps": {
            "a": {"type": "query", "timeout_s": 5, "next": "b", "max_iterations": 3},
            "b": {"type": "decision", "branches": {"again": "a", "go": "c"}, "default": "z"},
            "c": {"type": "action", "action": "revoke_sessions", "destructive": True, "auto_approved_by": "policy",
                  "rollback": "n/a", "idempotency_key": "k", "timeout_s": 5, "on_error": "z", "next": "z"},
            "z": {"type": "end"}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            path.write_text(json.dumps(book))
            out = run(self.script, path, expect=1)
        rules = {f["rule"] for f in json.loads(out.stdout)}
        self.assertNotIn("unbounded-loop", rules)
        self.assertIn("auto-action-without-exclusions", rules)


class DetectionCoverageMatrix(unittest.TestCase):
    script = SKILLS / "security-testing/detection-validation/scripts/coverage_matrix.py"

    def test_classifies_detected_other_and_missed(self):
        out = run(self.script, "--plan", FIX / "emulation_plan.json", "--alerts", FIX / "emulation_alerts.csv")
        rows = {r["id"]: r for r in csv.DictReader(out.stdout.splitlines())}
        self.assertEqual(rows["PT-01"]["status"], "detected")
        self.assertEqual(rows["PT-01"]["latency_s"], "250")  # FQDN host matched, other host ignored
        self.assertEqual(rows["PT-02"]["status"], "detected-other")
        self.assertEqual(rows["PT-03"]["status"], "detected")  # epoch-ms timestamp
        self.assertEqual(rows["PT-04"]["status"], "missed")    # alert outside the 15 min window
        self.assertIn("detected_pct=50.0", out.stderr)
        self.assertIn("median_latency_s=725", out.stderr)
        self.assertIn("skipped 1 alert rows", out.stderr)

    def test_fail_under_and_json(self):
        out = run(self.script, "--plan", FIX / "emulation_plan.json", "--alerts", FIX / "emulation_alerts.csv",
                  "--format", "json", "--fail-under", "75", expect=1)
        self.assertEqual(len(json.loads(out.stdout)), 4)


class ZeekTriage(unittest.TestCase):
    script = SKILLS / "network-security/zeek-log-analysis/scripts/zeek_triage.py"

    def test_tsv_and_json_logs_produce_each_finding_type(self):
        logs = sorted((FIX / "zeek").glob("*.log"))
        out = run(self.script, *logs, "--dc", "10.0.0.11")
        found = json.loads(out.stdout)
        types = {f["type"] for f in found}
        self.assertEqual(types, {"dcsync", "remote-service", "executable-transfer", "large-upload", "dns-tunnel-like",
                                 "invalid-cert", "long-connection", "scan-like", "rare-user-agent"})
        self.assertEqual(found[0]["type"], "dcsync")                     # highest severity first
        dcsync = [f for f in found if f["type"] == "dcsync"]
        self.assertEqual([f["src"] for f in dcsync], ["10.0.0.6"])     # listed DC is not flagged
        upload = [f for f in found if f["type"] == "large-upload"]
        self.assertEqual([f["dst"] for f in upload], ["203.0.113.9"])  # internal 90 MB SMB copy ignored
        dns = [f for f in found if f["type"] == "dns-tunnel-like"]
        self.assertEqual(len(dns), 1)                                    # short random label not flagged

    def test_gzip_input(self):
        import gzip
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "conn.log.gz"
            with gzip.open(target, "wt") as handle:
                handle.write((FIX / "zeek" / "conn.log").read_text())
            found = json.loads(run(self.script, target).stdout)
        self.assertIn("long-connection", {f["type"] for f in found})


class OktaHunts(unittest.TestCase):
    script = SKILLS / "saas-security/okta-log-investigation/scripts/okta_hunts.py"

    def test_each_hunt_fires_once_on_the_right_user(self):
        found = json.loads(run(self.script, FIX / "okta_syslog.json").stdout)
        got = sorted((f["hunt"], f["user"]) for f in found)
        self.assertEqual(got, sorted([
            ("factor-reset-then-new-ip", "alice@example.com"), ("session-multi-ip", "bob@example.com"),
            ("push-fatigue", "carol@example.com"), ("rogue-idp", "eve@example.com"),
            ("human-api-token", "eve@example.com"), ("admin-grant", "eve@example.com")]))

    def test_thresholds_and_jsonl(self):
        events = json.loads((FIX / "okta_syslog.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "log.jsonl"
            path.write_text("\n".join(json.dumps(e) for e in events))
            found = json.loads(run(self.script, path, "--push-count", "7", "--reset-hours", "1").stdout)
        hunts = {f["hunt"] for f in found}
        self.assertNotIn("push-fatigue", hunts)
        self.assertNotIn("factor-reset-then-new-ip", hunts)


class EntraSigninReview(unittest.TestCase):
    script = SKILLS / "azure-security/entra-signin-investigation/scripts/signin_review.py"

    def test_graph_export(self):
        found = json.loads(run(self.script, FIX / "entra_signins_graph.json").stdout)
        got = sorted((f["indicator"], f["user"]) for f in found)
        self.assertEqual(got, sorted([
            ("impossible-travel", "alice@contoso.example"), ("session-new-country", "alice@contoso.example"),
            ("spray-then-success", "carol@contoso.example"), ("legacy-auth-success", "carol@contoso.example"),
            ("mfa-denied-burst", "dave@contoso.example")]))  # bob's 4 h Munich -> Hamburg trip is not flagged

    def test_log_analytics_jsonl_with_string_location(self):
        found = json.loads(run(self.script, FIX / "entra_signins_la.jsonl").stdout)
        self.assertEqual([(f["indicator"], f["user"], f["country"]) for f in found],
                         [("scripted-client", "eve@contoso.example", "IE")])


class OsqueryDiff(unittest.TestCase):
    script = SKILLS / "endpoint-security/osquery-investigation/scripts/osquery_diff.py"

    def test_osqueryi_output_ignores_volatile_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, now = Path(tmp) / "b.json", Path(tmp) / "n.json"
            base.write_text(json.dumps([{"name": "sshd", "path": "/usr/sbin/sshd", "pid": "10"}]))
            now.write_text(json.dumps([{"name": "sshd", "path": "/usr/sbin/sshd", "pid": "99"},
                                       {"name": "miner", "path": "/dev/shm/miner", "pid": "123"}]))
            out = run(self.script, "--baseline", base, "--current", now, expect=1)
        report = json.loads(out.stdout)
        self.assertEqual([r["name"] for r in report["added"]], ["miner"])
        self.assertEqual(report["removed"], [])

    def test_fleet_result_logs_per_host(self):
        def line(host, cols, action="added"):
            return json.dumps({"name": "pack/keys", "hostIdentifier": host, "action": action, "columns": cols})
        with tempfile.TemporaryDirectory() as tmp:
            base, now = Path(tmp) / "b.log", Path(tmp) / "n.log"
            base.write_text(line("web-1", {"username": "root", "key": "ssh-ed25519 AAA ops"}) + "\n")
            now.write_text("\n".join([line("web-1", {"username": "root", "key": "ssh-ed25519 AAA ops"}),
                                      line("web-1", {"username": "root", "key": "ssh-ed25519 BBB attacker"}),
                                      line("web-2", {"username": "root", "key": "ssh-ed25519 AAA ops"})]) + "\n")
            out = run(self.script, "--baseline", base, "--current", now, "--key", "username", "--key", "key", expect=1)
        report = json.loads(out.stdout)
        self.assertEqual([r["key"] for r in report["web-1"]["added"]], ["ssh-ed25519 BBB attacker"])
        self.assertEqual(report["web-2"]["note"], "host has no baseline")
