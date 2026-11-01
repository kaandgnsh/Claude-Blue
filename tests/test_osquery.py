"""Run the osquery-investigation query library inside an osquery container against a planted scenario.

The scenario plants a deleted-binary process, a process running from /dev/shm, an SSH key, a cron
entry and a recent web shell, then executes every Linux-applicable query from the skill's SQL block.
Skipped when Docker or the osquery image is unavailable (CI pulls it explicitly).
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/endpoint-security/osquery-investigation/SKILL.md"
IMAGE = os.environ.get("OSQUERY_IMAGE", "osquery/osquery:5.17.0-ubuntu24.04")
MACOS_ONLY = ("launchd",)
SEP = "=====QUERY-END====="
# systemd/dbus tables print warnings on stderr in a container without dbus; stderr is dropped and a
# non-zero exit (unknown table, SQL error) is recorded as a failure instead.

SCENARIO = r"""
set -e
cp /bin/sleep /tmp/implant && /tmp/implant 300 &
cp /bin/sleep /dev/shm/miner && /dev/shm/miner 300 &
sleep 1; rm -f /tmp/implant
mkdir -p /root/.ssh && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlanted planted@attacker" > /root/.ssh/authorized_keys
echo "* * * * * root /dev/shm/miner" > /etc/cron.d/miner
mkdir -p /var/www/html && echo '<?php system($_GET["c"]); ?>' > /var/www/html/shell.php
mkdir -p /usr/local/bin && cp /bin/true /usr/local/bin/suspicious
while IFS= read -r -d $'\0' q; do
  /opt/osquery/bin/osqueryd -S --json "$q" 2>/dev/null || echo '{"error": true}'
  echo "%s"
done < /queries.bin
""" % SEP


def skill_queries():
    body = SKILL.read_text(encoding="utf-8")
    sql = re.search(r"```sql\n(.*?)```", body, re.S).group(1)
    sql = "\n".join(line for line in sql.splitlines() if not line.strip().startswith("--"))
    queries = [q.strip() for q in sql.split(";") if q.strip()]
    return [q for q in queries if not any(re.search(rf"\b{t}\b", q) for t in MACOS_ONLY)]


def have_image():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


@unittest.skipUnless(have_image(), f"docker image {IMAGE} not available")
class OsqueryLibrary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.queries = skill_queries()
        with tempfile.TemporaryDirectory() as tmp:
            qfile = Path(tmp) / "queries.bin"
            qfile.write_bytes(b"".join(q.encode() + b"\0" for q in cls.queries))
            os.chmod(tmp, 0o755)
            os.chmod(qfile, 0o644)
            result = subprocess.run(
                ["docker", "run", "--rm", "--network", "none", "--tmpfs", "/dev/shm:rw,exec", "-v", f"{qfile}:/queries.bin:ro",
                 IMAGE, "bash", "-c", SCENARIO], capture_output=True, text=True, timeout=180)
        chunks = result.stdout.split(SEP)[:-1]
        assert len(chunks) == len(cls.queries), result.stdout[-2000:] + result.stderr[-2000:]
        cls.results = {}
        for query, chunk in zip(cls.queries, chunks):
            text = chunk.strip()
            failed = text.endswith('{"error": true}')
            cls.results[query] = {"error": text} if failed or not text.startswith("[") else json.loads(text)

    def find(self, needle):
        for query, rows in self.results.items():
            if needle in query:
                return rows
        self.fail(f"no query containing {needle!r}")

    def test_every_linux_query_runs(self):
        bad = {q: r for q, r in self.results.items() if isinstance(r, dict)}
        self.assertEqual(bad, {}, "queries that failed in osquery")
        self.assertGreaterEqual(len(self.results), 10)

    def test_deleted_binary_process_found(self):
        rows = self.find("on_disk = 0")
        self.assertTrue(any(r["path"].startswith("/tmp/implant") for r in rows), rows)

    def test_process_in_writable_path_found(self):
        rows = self.find("/dev/shm/%")
        self.assertTrue(any(r["path"] == "/dev/shm/miner" for r in rows), rows)

    def test_planted_ssh_key_found(self):
        rows = self.find("authorized_keys")
        self.assertTrue(any("planted@attacker" in r["key"] or "Planted" in r["key"] for r in rows), rows)

    def test_cron_persistence_found(self):
        rows = self.find("FROM crontab")
        self.assertTrue(any("/dev/shm/miner" in r["command"] for r in rows), rows)

    def test_recent_web_shell_found(self):
        rows = self.find("/var/www/%%")
        self.assertTrue(any(r["path"].endswith("shell.php") for r in rows), rows)

    def test_hash_sweep_returns_sha256(self):
        rows = self.find("FROM hash")
        self.assertEqual(len(rows), 1)
        self.assertRegex(rows[0]["sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
