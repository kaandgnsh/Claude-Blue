"""Tests for the security-engineering builder skills.

host-firewall-build: policy validation, nft syntax (nft -c in a user+net namespace), real-traffic
netns_test.py including a negative control, and safe_apply.sh confirm/reject/rollback paths.
ssh-hardening-build: generator validation, sshd -t, and live_test.sh against hardened and weak configs.
security-tool-development: scaffolded project passes its own tests and its CI passes gha_audit.py.
Tests needing unshare/nft/sshd are skipped with a reason when the environment lacks them.
"""
import grp
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENG = ROOT / "skills" / "security-engineering"
FW = ENG / "host-firewall-build" / "scripts"
SSH = ENG / "ssh-hardening-build" / "scripts"
TOOL = ENG / "security-tool-development" / "scripts"
GHA = ROOT / "skills" / "devsecops" / "github-actions-hardening" / "scripts" / "gha_audit.py"


def run(*cmd, expect=0, **kw):
    result = subprocess.run([str(c) for c in cmd], text=True, capture_output=True, **kw)
    if expect is not None:
        assert result.returncode == expect, f"{cmd} -> {result.returncode}\n{result.stdout}\n{result.stderr}"
    return result


def netns_available():
    if not (shutil.which("unshare") and shutil.which("nft") and shutil.which("nsenter") and shutil.which("ip")):
        return False
    return subprocess.run(["unshare", "-rn", "nft", "list", "ruleset"], capture_output=True).returncode == 0


NETNS = netns_available()
POLICY = {
    "name": "test",
    "inbound": [
        {"name": "ssh", "proto": "tcp", "ports": [22], "sources": ["10.20.0.0/24"], "rate_limit": "10/minute", "management": True},
        {"name": "web", "proto": "tcp", "ports": [80, 443], "sources": ["any"]},
        {"name": "metrics", "proto": "tcp", "ports": [9100], "sources": ["10.20.5.10"]},
        {"name": "syslog", "proto": "udp", "ports": [514], "sources": ["10.20.0.0/24"]},
    ],
}


class FirewallPolicy(unittest.TestCase):
    def gen(self, policy, *extra, expect=0):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.json"
            path.write_text(json.dumps(policy))
            return run(sys.executable, FW / "nft_policy.py", path, *extra, expect=expect)

    def test_generates_single_managed_table(self):
        out = self.gen(POLICY).stdout
        self.assertIn("table inet cb_filter\ndelete table inet cb_filter", out)
        self.assertNotIn("flush ruleset", out)
        self.assertIn("policy drop;", out)
        self.assertIn("add @in_ssh_rl4 { ip saddr limit rate over 10/minute", out)

    def test_refuses_lockout(self):
        policy = {"name": "x", "inbound": [{"name": "web", "proto": "tcp", "ports": [443], "sources": ["any"]}]}
        self.assertIn("lock out", self.gen(policy, expect=2).stderr)

    def test_rejects_invalid_input(self):
        for bad in ({"inbound": [{"name": "Bad", "proto": "tcp", "ports": [22], "sources": ["any"], "management": True}]},
                    {"inbound": [{"name": "a", "proto": "icmp", "ports": [1], "sources": ["any"], "management": True}]},
                    {"inbound": [{"name": "a", "proto": "tcp", "ports": [70000], "sources": ["any"], "management": True}]},
                    {"inbound": [{"name": "a", "proto": "tcp", "ports": [22], "sources": ["10.0.0.300/8"], "management": True}]},
                    {"inbound": [], "typo": 1}):
            self.gen(bad, expect=2)

    def test_warns_on_exposed_admin_port_and_strict_fails(self):
        policy = {"name": "x", "inbound": [{"name": "ssh", "proto": "tcp", "ports": [22], "sources": ["any"], "management": True}]}
        self.assertIn("sensitive port(s) [22]", self.gen(policy).stderr)
        self.gen(policy, "--strict", expect=1)


@unittest.skipUnless(NETNS, "unprivileged user+network namespaces with nft unavailable")
class FirewallFunctional(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.policy = self.dir / "policy.json"
        self.policy.write_text(json.dumps(POLICY))
        self.rules = self.dir / "fw.nft"
        run(sys.executable, FW / "nft_policy.py", self.policy, "-o", self.rules)

    def tearDown(self):
        self.tmp.cleanup()

    def test_syntax_check(self):
        run("unshare", "-rn", "nft", "-c", "-f", self.rules)

    def test_real_traffic_matches_policy(self):
        out = run(sys.executable, FW / "netns_test.py", self.policy, self.rules).stdout
        self.assertIn("failures=0", out)
        self.assertRegex(out, r"ok\s+10\.20\.0\.1 -> udp/514 +expected=open")
        self.assertRegex(out, r"ok\s+203\.0\.113\.77 -> tcp/22 +expected=blocked")

    def test_negative_control_detects_overly_permissive_ruleset(self):
        loose = dict(POLICY, inbound=[dict(r, sources=["any"]) for r in POLICY["inbound"]])
        loose_policy = self.dir / "loose.json"
        loose_policy.write_text(json.dumps(loose))
        loose_rules = self.dir / "loose.nft"
        run(sys.executable, FW / "nft_policy.py", loose_policy, "-o", loose_rules)
        out = run(sys.executable, FW / "netns_test.py", self.policy, loose_rules, expect=1).stdout
        self.assertRegex(out, r"FAIL\s+203\.0\.113\.77 -> tcp/22 +expected=blocked got=open")

    def safe_apply(self, script):
        env = dict(os.environ, CB_FW_STATE_DIR=str(self.dir / "state"), SAFE=str(FW / "safe_apply.sh"),
                   RULES=str(self.rules))
        return run("unshare", "-rn", "bash", "-c", script, env=env, expect=None)

    def test_safe_apply_confirm_keeps_table(self):
        out = self.safe_apply('echo yes | "$SAFE" "$RULES" 5 >/dev/null && nft list tables').stdout
        self.assertIn("table inet cb_filter", out)

    def test_safe_apply_reject_restores_previous_version(self):
        changed = self.dir / "changed.nft"
        changed.write_text(self.rules.read_text().replace("9100", "9200"))
        out = self.safe_apply(f'echo yes | "$SAFE" "$RULES" 5 >/dev/null; echo no | "$SAFE" "{changed}" 5 >/dev/null; '
                              'echo rc=$?; nft list table inet cb_filter').stdout
        self.assertIn("rc=1", out)
        self.assertIn("9100", out)
        self.assertNotIn("9200", out)

    def test_safe_apply_rolls_back_when_session_dies(self):
        # $! is the last command of the pipeline, i.e. safe_apply.sh itself: SIGKILL simulates a dead
        # SSH session; the detached rollback timer must still restore the previous state.
        out = self.safe_apply('sleep 30 | "$SAFE" "$RULES" 2 >/dev/null 2>&1 & APPLY=$!; sleep 1; '
                              'echo during=$(nft list tables | wc -l); kill -9 "$APPLY"; sleep 3; '
                              'echo after=$(nft list tables | wc -l)').stdout
        self.assertIn("during=1", out)
        self.assertIn("after=0", out)

    def test_safe_apply_rejects_invalid_file(self):
        bad = self.dir / "bad.nft"
        bad.write_text("garbage\n")
        out = self.safe_apply(f'"$SAFE" "{bad}" 5 </dev/null >/dev/null 2>&1; echo rc=$?; nft list tables | wc -l').stdout
        self.assertNotIn("rc=0", out)
        self.assertTrue(out.strip().endswith("0"))


class SshPolicy(unittest.TestCase):
    def gen(self, policy, expect=0):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.json"
            path.write_text(json.dumps(policy))
            return run(sys.executable, SSH / "sshd_harden.py", path, "--no-detect", expect=expect)

    def test_core_settings(self):
        out = self.gen({"allow_groups": ["ssh-users"]}).stdout
        for line in ("PermitRootLogin no", "PasswordAuthentication no", "AuthenticationMethods publickey",
                     "AllowGroups ssh-users", "AllowTcpForwarding no", "X11Forwarding no"):
            self.assertIn(line + "\n", out)
        self.assertNotIn("cbc", out)
        self.assertNotIn("hmac-sha1", out)

    def test_refuses_empty_groups_and_bad_values(self):
        for bad in ({"allow_groups": []}, {"allow_groups": ["Bad Group"]}, {"allow_groups": ["a"], "port": 0},
                    {"allow_groups": ["a"], "banner": "relative/path"}, {"allow_groups": ["a"], "typo": True}):
            self.gen(bad, expect=2)


@unittest.skipUnless(shutil.which("sshd") and shutil.which("ssh") and shutil.which("ssh-keygen"), "OpenSSH not installed")
class SshLive(unittest.TestCase):
    def test_hardened_passes_and_weak_fails(self):
        group = grp.getgrgid(os.getgid()).gr_name
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp) / "p.json"
            policy.write_text(json.dumps({"allow_groups": [group]}))
            conf = Path(tmp) / "00-cb.conf"
            run(sys.executable, SSH / "sshd_harden.py", policy, "-o", conf)
            good = run("bash", SSH / "live_test.sh", conf, "22942", expect=None)
            if "key login (allowed user)" in good.stdout and "FAIL key login" in good.stdout:
                self.skipTest("unprivileged sshd cannot authenticate in this environment")
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            self.assertIn("only key-based methods offered     publickey", good.stdout)
            weak = Path(tmp) / "weak.conf"
            weak.write_text(f"AllowGroups {group}\nPasswordAuthentication yes\nAllowTcpForwarding no\n")
            bad = run("bash", SSH / "live_test.sh", weak, "22952", expect=1).stdout
            self.assertIn("FAIL only key-based methods offered", bad)


class ToolScaffold(unittest.TestCase):
    def test_generated_project_tests_pass_and_ci_is_hardened(self):
        with tempfile.TemporaryDirectory() as tmp:
            run(sys.executable, TOOL / "new_tool.py", "log-sentry", "--dir", tmp)
            project = Path(tmp) / "log-sentry"
            env = dict(os.environ, PYTHONPATH=str(project / "src"))
            result = run(sys.executable, "-m", "unittest", "discover", "-s", "tests", cwd=project, env=env, expect=None)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(run(sys.executable, GHA, project / ".github" / "workflows").stdout), [])
            run(sys.executable, TOOL / "new_tool.py", "log-sentry", "--dir", tmp, expect=2)  # no overwrite
            run(sys.executable, TOOL / "new_tool.py", "Bad_Name", "--dir", tmp, expect=2)


if __name__ == "__main__":
    unittest.main()
