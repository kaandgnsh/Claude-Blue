"""Catalog validation and installer/uninstaller safety tests."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "claude_blue.py"
spec = importlib.util.spec_from_file_location("claude_blue", CLI)
cb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cb)


def skills_in(category):
    return sorted(p.parent.name for p in (ROOT / "skills" / category).glob("*/SKILL.md"))


class Catalog(unittest.TestCase):
    def run_cli(self, *args, expect=0):
        result = subprocess.run([sys.executable, str(CLI), *args], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, expect, result.stdout + result.stderr)
        return result

    def test_validate_passes_and_meets_scale(self):
        out = self.run_cli("validate").stdout
        counts = dict(part.split("=") for part in out.split()[:3])
        self.assertGreaterEqual(int(counts["skills"]), 220)
        self.assertGreaterEqual(int(counts["categories"]), 35)
        self.assertNotIn("ERROR", out)

    def test_catalog_json_matches_files(self):
        data = json.loads((ROOT / "catalog.json").read_text())
        self.assertEqual(data["skill_count"], len(list((ROOT / "skills").glob("*/*/SKILL.md"))))

    def test_profiles_list(self):
        self.assertIn("soc", self.run_cli("list", "--profiles").stdout)


class Frontmatter(unittest.TestCase):
    def test_parses_nested_metadata(self):
        fields, body = cb.parse_frontmatter('---\nname: a\ndescription: "x: y"\nmetadata:\n  category: c\n---\n# T\n')
        self.assertEqual(fields["description"], "x: y")
        self.assertEqual(fields["metadata"], {"category": "c"})
        self.assertEqual(body, "# T\n")

    def test_rejects_bad_frontmatter(self):
        for text in ("name: a\n", "---\nname: a\n", "---\nname: a\nname: b\n---\n", "---\nname:\ttab\n---\n",
                     "---\n  orphan: x\n---\n", "---\ntags: [a, b]\n---\n"):
            with self.assertRaises(cb.FrontmatterError, msg=text):
                cb.parse_frontmatter(text)


class Installer(unittest.TestCase):
    def cli(self, *args, expect=0):
        result = subprocess.run([sys.executable, str(CLI), *args], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, expect, result.stdout + result.stderr)
        return result

    def test_requires_explicit_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.cli("install", "--target", str(Path(tmp) / "s"), expect=1)
            self.assertIn("--profile", result.stderr)

    def test_dry_run_creates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            self.cli("install", "--target", str(target), "--category", "dfir", "--dry-run")
            self.assertFalse(target.exists())

    def test_round_trip_and_incremental_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            self.cli("install", "--target", str(target), "--category", "dfir")
            self.cli("install", "--target", str(target), "--category", "deception")
            manifest = json.loads((target / cb.MANIFEST_NAME).read_text())
            self.assertEqual(sorted(manifest["skills"]), sorted(skills_in("dfir") + skills_in("deception")))
            self.assertTrue((target / "timeline-analysis" / "scripts" / "merge_timeline.py").is_file())
            self.cli("install", "--target", str(target), "--category", "dfir")       # idempotent
            self.cli("uninstall", "--target", str(target), "--category", "deception")
            self.assertFalse((target / "honeytoken-deployment").exists())
            self.assertTrue((target / "evidence-intake").exists())
            self.cli("uninstall", "--target", str(target))
            self.assertFalse((target / cb.MANIFEST_NAME).exists())
            self.assertEqual(list(target.iterdir()), [])

    def test_project_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.cli("install", "--scope", "project", "--project-dir", tmp, "--skill", "alert-triage")
            self.assertTrue((Path(tmp) / ".claude" / "skills" / "alert-triage" / "SKILL.md").is_file())

    def test_refuses_to_overwrite_foreign_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            (target / "evidence-intake").mkdir(parents=True)
            (target / "evidence-intake" / "SKILL.md").write_text("local")
            self.cli("install", "--target", str(target), "--category", "dfir", expect=1)
            self.assertEqual((target / "evidence-intake" / "SKILL.md").read_text(), "local")
            self.assertFalse((target / "timeline-analysis").exists())

    def test_modified_skills_are_kept_on_upgrade_and_uninstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            self.cli("install", "--target", str(target), "--category", "dfir")
            note = target / "evidence-intake" / "local-notes.md"
            note.write_text("keep")
            out = self.cli("install", "--target", str(target), "--category", "dfir", "--upgrade").stdout
            self.assertIn("skip-modified: evidence-intake", out)
            out = self.cli("uninstall", "--target", str(target), expect=1).stdout
            self.assertIn("kept (modified or not a regular directory): evidence-intake", out)
            self.assertTrue(note.exists())
            self.assertFalse((target / "timeline-analysis").exists())
            manifest = json.loads((target / cb.MANIFEST_NAME).read_text())
            self.assertEqual(list(manifest["skills"]), ["evidence-intake"])

    def test_bytecode_caches_neither_ship_nor_count_as_modification(self):
        source_cache = ROOT / "skills/dfir/timeline-analysis/scripts/__pycache__"
        created = not source_cache.exists()
        source_cache.mkdir(exist_ok=True)
        (source_cache / "probe.cpython-399.pyc").write_bytes(b"x")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / "skills"
                self.cli("install", "--target", str(target), "--skill", "timeline-analysis")
                installed = target / "timeline-analysis" / "scripts"
                self.assertFalse((installed / "__pycache__").exists())
                (installed / "__pycache__").mkdir()
                (installed / "__pycache__" / "merge_timeline.cpython-314.pyc").write_bytes(b"y")
                self.cli("uninstall", "--target", str(target))
                self.assertFalse((target / "timeline-analysis").exists())
        finally:
            (source_cache / "probe.cpython-399.pyc").unlink()
            if created:
                source_cache.rmdir()

    def test_upgrade_replaces_unmodified_outdated_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            self.cli("install", "--target", str(target), "--skill", "alert-triage")
            manifest_path = target / cb.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text())
            # Simulate an older install: change the file and record its hash as the installed state.
            skill_file = target / "alert-triage" / "SKILL.md"
            skill_file.write_text("old version")
            manifest["skills"]["alert-triage"]["files"] = cb.tree_hashes(target / "alert-triage")
            manifest_path.write_text(json.dumps(manifest))
            self.assertIn("skip-outdated", self.cli("install", "--target", str(target), "--skill", "alert-triage").stdout)
            self.cli("install", "--target", str(target), "--skill", "alert-triage", "--upgrade")
            self.assertEqual(skill_file.read_text(), (ROOT / "skills/soc-operations/alert-triage/SKILL.md").read_text())

    def test_rejects_unsafe_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            target.mkdir()
            (target / cb.MANIFEST_NAME).write_text(json.dumps({"skills": {"../etc": {"path": "../etc", "files": {}}}}))
            result = self.cli("uninstall", "--target", str(target), expect=1)
            self.assertIn("unsafe entry", result.stderr)

    def test_v1_manifest_is_understood(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            target.mkdir()
            (target / cb.MANIFEST_NAME).write_text(json.dumps({"skills": [{"name": "gone", "path": "gone", "files": {}}]}))
            self.cli("uninstall", "--target", str(target))
            self.assertFalse((target / cb.MANIFEST_NAME).exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_uninstall_never_follows_symlinked_skill_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "skills"
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "SKILL.md").write_text("precious")
            self.cli("install", "--target", str(target), "--skill", "alert-triage")
            import shutil
            shutil.rmtree(target / "alert-triage")
            os.symlink(outside, target / "alert-triage")
            self.cli("uninstall", "--target", str(target), expect=1)
            self.assertEqual((outside / "SKILL.md").read_text(), "precious")


if __name__ == "__main__":
    unittest.main()


def load_tool(name):
    tool_spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(tool_spec)
    tool_spec.loader.exec_module(module)
    return module


class AttackRefresh(unittest.TestCase):
    def bundle(self):
        def technique(tid, name, tactic, **extra):
            return {"type": "attack-pattern", "name": name, "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": tactic}],
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}], **extra}
        return {"objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "21.0"},
            {"type": "x-mitre-tactic", "x_mitre_shortname": "credential-access"},
            {"type": "x-mitre-tactic", "x_mitre_shortname": "old-tactic", "x_mitre_deprecated": True},
            technique("T1003", "OS Credential Dumping", "credential-access"),
            technique("T1003.001", "LSASS Memory", "credential-access"),
            technique("T9999", "Gone", "credential-access", revoked=True),
            technique("T9998", "Old", "credential-access", x_mitre_deprecated=True),
            {"type": "attack-pattern", "name": "No id", "external_references": [{"source_name": "capec"}]},
        ]}

    def test_build_keeps_only_active_objects(self):
        snap = load_tool("refresh_attack").build(self.bundle(), "test")
        self.assertEqual(snap["attack_version"], "21.0")
        self.assertEqual(snap["tactics"], ["credential-access"])
        self.assertEqual(list(snap["techniques"]), ["T1003", "T1003.001"])
        self.assertEqual(snap["technique_tactics"]["T1003.001"], ["credential-access"])

    def test_cli_check_and_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle, out = Path(tmp) / "b.json", Path(tmp) / "snap.json"
            bundle.write_text(json.dumps(self.bundle()))
            cmd = [sys.executable, str(ROOT / "tools/refresh_attack.py"), "--input", str(bundle), "--output", str(out)]
            self.assertEqual(subprocess.run(cmd + ["--check"], capture_output=True).returncode, 1)
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(cmd + ["--check"], capture_output=True).returncode, 0)

    def test_bundled_snapshot_is_well_formed(self):
        snap = json.loads((ROOT / "tools/data/attack-enterprise.json").read_text())
        self.assertEqual(set(snap), {"source", "attack_version", "tactics", "techniques", "technique_tactics"})
        self.assertEqual(set(snap["techniques"]), set(snap["technique_tactics"]))


class LinkCheck(unittest.TestCase):
    def test_extract_skips_code_and_placeholders(self):
        links = load_tool("check_links")
        with tempfile.TemporaryDirectory() as tmp:
            md = Path(tmp) / "a.md"
            md.write_text("See https://docs.example.org/x and https://real.test/page.\n"
                          "Inline `https://code.test/skip` and <https://angle.test/a>\n"
                          "```sh\ncurl https://fenced.test/skip\n```\n| https://table.test/t |\n")
            urls = set(links.extract([md]))
        self.assertEqual(urls, {"https://real.test/page", "https://angle.test/a", "https://table.test/t"})

    def test_probe_classifies_ok_broken_and_blocked(self):
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                code = {"/ok": 200, "/gone": 404, "/forbidden": 403, "/nohead": 405}.get(self.path, 404)
                self.send_response(code)
                self.end_headers()

            def do_GET(self):
                code = {"/ok": 200, "/gone": 404, "/forbidden": 403, "/nohead": 200}.get(self.path, 404)
                self.send_response(code)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        links = load_tool("check_links")
        try:
            self.assertEqual(links.probe(base + "/ok", 5)[0], "ok")
            self.assertEqual(links.probe(base + "/nohead", 5)[0], "ok")
            self.assertEqual(links.probe(base + "/gone", 5)[0], "broken")
            self.assertEqual(links.probe(base + "/forbidden", 5)[0], "blocked")
        finally:
            server.shutdown()
            server.server_close()
