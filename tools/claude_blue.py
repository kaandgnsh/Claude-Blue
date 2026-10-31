#!/usr/bin/env python3
"""Claude-Blue catalog tool: validate skills, generate the catalog, list/install/uninstall skills.

Standard library only. Run `python3 tools/claude_blue.py --help`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
DATA = ROOT / "tools" / "data"
PROFILES_FILE = ROOT / "tools" / "profiles.json"
CATALOG_JSON = ROOT / "catalog.json"
CATALOG_MD = ROOT / "CATALOG.md"
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
PLUGIN_PREFIX = "blue-team"  # names starting with "claude-" are reserved by Claude Code
MANIFEST_NAME = ".claude-blue-manifest.json"
VERSION = "2.0.0"

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
SIGMA_TACTIC_RE = re.compile(r"^\s*-\s*attack\.([a-z][a-z-]+)\s*$", re.M)
RELATIVE_LINK_RE = re.compile(r"\]\((?!https?://|mailto:|#)([^)\s]+)\)")
SCRIPT_REF_RE = re.compile(r"\bscripts/[A-Za-z0-9_.-]+\.(?:py|sh|ps1)\b")
URL_RE = re.compile(r"https?://\S+")

# Keys accepted by every Agent Skills surface (Claude Code, claude.ai upload, Skills API).
PORTABLE_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
REQUIRED_METADATA = {"category", "version", "verification"}
VERIFICATION_LEVELS = {"documented", "tested"}
REQUIRED_SECTIONS = ("## Related skills", "## References")
RESERVED_WORDS = ("anthropic", "claude")
MAX_DESCRIPTION = 1024
MAX_BODY_LINES = 500
MIN_BODY_CHARS = 1800
BOILERPLATE_MIN_LEN = 60
BOILERPLATE_MAX_SKILLS = 8


class FrontmatterError(ValueError):
    pass


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_frontmatter(text: str):
    """Parse the restricted YAML subset used by Claude-Blue skills.

    Supports top-level `key: value` pairs and one level of nested mappings indented by two
    spaces (used for `metadata`). Rejects tabs, duplicate keys and anything else, so a file
    that passes here is also valid YAML for Claude Code's loader.
    """
    if not text.startswith("---\n"):
        raise FrontmatterError("frontmatter must start on the first line with ---")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise FrontmatterError("frontmatter closing --- missing")
    fields: dict = {}
    current = None
    for number, line in enumerate(text[4:end].splitlines(), start=2):
        if not line.strip():
            continue
        if "\t" in line:
            raise FrontmatterError(f"line {number}: tabs are not allowed")
        if line.startswith("  "):
            if current is None:
                raise FrontmatterError(f"line {number}: indented line without a parent key")
            key, sep, value = line.strip().partition(":")
            if not sep or not value.strip():
                raise FrontmatterError(f"line {number}: expected 'key: value' under {current}")
            if key in fields[current]:
                raise FrontmatterError(f"line {number}: duplicate key {current}.{key}")
            fields[current][key] = unquote(value)
            continue
        key, sep, value = line.partition(":")
        if not sep:
            raise FrontmatterError(f"line {number}: expected 'key: value'")
        key = key.strip()
        if key in fields:
            raise FrontmatterError(f"line {number}: duplicate key {key}")
        if value.strip():
            if value.strip()[0] in "[{>|&*!":
                raise FrontmatterError(f"line {number}: complex YAML values are not supported for {key}")
            fields[key] = unquote(value)
            current = None
        else:
            fields[key] = {}
            current = key
    return fields, text[end + 5:]


def skill_paths():
    return sorted(SKILLS.glob("*/*/SKILL.md"))


def load_skill(path: Path):
    fields, body = parse_frontmatter(path.read_text(encoding="utf-8"))
    title = next((line[2:].strip() for line in body.splitlines() if line.startswith("# ")), fields.get("name", ""))
    meta = fields.get("metadata") if isinstance(fields.get("metadata"), dict) else {}
    return {
        "name": fields.get("name", ""),
        "title": title,
        "description": fields.get("description", ""),
        "category": path.parent.parent.name,
        "verification": meta.get("verification", ""),
        "version": meta.get("version", ""),
        "path": path.parent.relative_to(ROOT).as_posix(),
        "fields": fields,
        "body": body,
    }


def section(body: str, heading: str) -> str:
    start = body.find(heading + "\n")
    if start < 0:
        return ""
    rest = body[start + len(heading) + 1:]
    nxt = re.search(r"^## ", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def load_attack():
    path = DATA / "attack-enterprise.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def validate(check_catalog: bool = True):
    errors: list[str] = []
    warnings: list[str] = []
    paths = skill_paths()
    skills = []
    names = Counter()
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        try:
            skill = load_skill(path)
        except (FrontmatterError, UnicodeDecodeError) as exc:
            errors.append(f"{rel}: {exc}")
            continue
        skills.append(skill)
        names[skill["name"]] += 1
    known = set(names)
    attack = load_attack()
    line_owners: dict[str, set] = defaultdict(set)

    for symlink in (p for p in SKILLS.rglob("*") if p.is_symlink()):
        errors.append(f"{symlink.relative_to(ROOT)}: symlinks are not allowed in skills/")
    for stray in SKILLS.glob("*/*"):
        if stray.is_dir() and not (stray / "SKILL.md").is_file():
            errors.append(f"{stray.relative_to(ROOT)}: skill directory without SKILL.md")

    for skill in skills:
        rel = skill["path"] + "/SKILL.md"
        fields, body, name, desc = skill["fields"], skill["body"], skill["name"], skill["description"]
        skill_dir = ROOT / skill["path"]
        extra = set(fields) - PORTABLE_KEYS
        if extra:
            errors.append(f"{rel}: non-portable frontmatter keys {sorted(extra)}")
        if not NAME_RE.fullmatch(name) or len(name) > 64:
            errors.append(f"{rel}: invalid name {name!r}")
        if any(word in name for word in RESERVED_WORDS):
            errors.append(f"{rel}: name contains a reserved word")
        if name != skill_dir.name:
            errors.append(f"{rel}: name {name!r} does not match directory {skill_dir.name!r}")
        if names[name] > 1:
            errors.append(f"{rel}: duplicate skill name {name!r}")
        if not desc or len(desc) > MAX_DESCRIPTION:
            errors.append(f"{rel}: description missing or longer than {MAX_DESCRIPTION} characters")
        elif "Use when" not in desc and "Use for" not in desc and "Use after" not in desc and "Use as" not in desc and "Use at" not in desc:
            errors.append(f"{rel}: description must say when to use the skill ('Use when ...')")
        if "<" in desc or ">" in desc:
            errors.append(f"{rel}: description must not contain angle brackets")
        meta = fields.get("metadata") if isinstance(fields.get("metadata"), dict) else {}
        missing_meta = REQUIRED_METADATA - set(meta)
        if missing_meta:
            errors.append(f"{rel}: metadata missing {sorted(missing_meta)}")
        if meta.get("category") and meta["category"] != skill["category"]:
            errors.append(f"{rel}: metadata.category {meta['category']!r} does not match directory {skill['category']!r}")
        if meta.get("version") and not SEMVER_RE.fullmatch(meta["version"]):
            errors.append(f"{rel}: metadata.version must be MAJOR.MINOR.PATCH")
        if meta.get("verification") and meta["verification"] not in VERIFICATION_LEVELS:
            errors.append(f"{rel}: metadata.verification must be one of {sorted(VERIFICATION_LEVELS)}")
        if meta.get("verification") == "tested" and not tested_evidence(skill):
            errors.append(f"{rel}: verification 'tested' requires a bundled script or a test in tests/ naming the skill")
        if not re.search(r"^# \S", body, re.M):
            errors.append(f"{rel}: missing H1 title")
        for heading in REQUIRED_SECTIONS:
            if heading + "\n" not in body:
                errors.append(f"{rel}: missing section {heading!r}")
        if len(body.strip()) < MIN_BODY_CHARS:
            errors.append(f"{rel}: body shorter than {MIN_BODY_CHARS} characters")
        if body.count("\n") > MAX_BODY_LINES:
            errors.append(f"{rel}: SKILL.md body exceeds {MAX_BODY_LINES} lines; move detail to reference files")
        refs = section(body, "## References")
        if not URL_RE.search(refs):
            errors.append(f"{rel}: References section has no URL")
        related = re.findall(r"`([a-z0-9-]+)`", section(body, "## Related skills"))
        if not related:
            errors.append(f"{rel}: Related skills section lists no skills")
        for other in related:
            if other not in known:
                errors.append(f"{rel}: related skill {other!r} does not exist")
            elif other == name:
                errors.append(f"{rel}: lists itself as a related skill")
        prose_only = re.sub(r"`[^`\n]*`", "", re.sub(r"```.*?```", "", body, flags=re.S))
        for link in RELATIVE_LINK_RE.findall(prose_only):
            if not (skill_dir / link.split("#")[0]).exists():
                errors.append(f"{rel}: broken relative link {link!r}")
        for script in set(SCRIPT_REF_RE.findall(body)):
            if not (skill_dir / script).is_file():
                errors.append(f"{rel}: referenced script {script!r} not found")
        if attack:
            techniques = attack["techniques"]
            for tid in sorted(set(ATTACK_ID_RE.findall(body))):
                if tid not in techniques:
                    errors.append(f"{rel}: ATT&CK ID {tid} not in ATT&CK v{attack['attack_version']} (deprecated or invalid)")
            tactics = set(attack["tactics"])
            for tactic in SIGMA_TACTIC_RE.findall(body):
                if tactic not in tactics and not re.fullmatch(r"t\d{4}(\.\d{3})?", tactic) and not tactic.startswith(("g", "s")):
                    errors.append(f"{rel}: Sigma tag attack.{tactic} is not an ATT&CK v{attack['attack_version']} tactic")
        prose = body.replace(refs, "") if refs else body
        for line in prose.splitlines():
            text = " ".join(line.split())
            if len(text) >= BOILERPLATE_MIN_LEN and not text.startswith(("|", "```", "- http", "http")):
                line_owners[text].add(name)

    for text, owners in sorted(line_owners.items()):
        if len(owners) > BOILERPLATE_MAX_SKILLS:
            errors.append(f"boilerplate line repeated in {len(owners)} skills (write task-specific content): {text[:90]!r}")

    for profile, cats in load_profiles().items():
        for cat in cats:
            if not (SKILLS / cat).is_dir():
                errors.append(f"tools/profiles.json: profile {profile!r} references unknown category {cat!r}")

    if check_catalog and not errors:
        expected_json, expected_md = render_catalog(skills)
        if not CATALOG_JSON.is_file() or CATALOG_JSON.read_text(encoding="utf-8") != expected_json:
            errors.append("catalog.json is stale; run: python3 tools/claude_blue.py catalog")
        if not CATALOG_MD.is_file() or CATALOG_MD.read_text(encoding="utf-8") != expected_md:
            errors.append("CATALOG.md is stale; run: python3 tools/claude_blue.py catalog")
        if not MARKETPLACE.is_file() or MARKETPLACE.read_text(encoding="utf-8") != render_marketplace(skills):
            errors.append(".claude-plugin/marketplace.json is stale; run: python3 tools/claude_blue.py catalog")
    return skills, errors, warnings


def tested_evidence(skill) -> bool:
    skill_dir = ROOT / skill["path"]
    if (skill_dir / "scripts").is_dir() and any((skill_dir / "scripts").iterdir()):
        return True
    tests = ROOT / "tests"
    return any(skill["name"] in p.read_text(encoding="utf-8") for p in tests.glob("test_*.py"))


def load_profiles():
    data = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def render_catalog(skills):
    by_cat = defaultdict(list)
    for skill in skills:
        by_cat[skill["category"]].append(skill)
    catalog = {
        "project": "Claude-Blue",
        "version": VERSION,
        "skill_count": len(skills),
        "category_count": len(by_cat),
        "tested_skill_count": sum(1 for s in skills if s["verification"] == "tested"),
        "categories": [
            {
                "id": cat,
                "skills": [
                    {k: s[k] for k in ("name", "title", "description", "verification", "version", "path")}
                    for s in sorted(items, key=lambda s: s["name"])
                ],
            }
            for cat, items in sorted(by_cat.items())
        ],
    }
    lines = [
        "# Claude-Blue catalog",
        "",
        "Generated by `python3 tools/claude_blue.py catalog` — do not edit by hand.",
        "",
        f"**{catalog['skill_count']} skills in {catalog['category_count']} categories.** "
        f"{catalog['tested_skill_count']} skills are marked `tested` (bundled scripts or examples executed by the test suite); "
        "the rest are `documented` (commands and queries written from vendor documentation, not executed here).",
        "",
        "| Category | Skills |",
        "|---|---|",
    ]
    for cat in catalog["categories"]:
        lines.append(f"| [{cat['id']}](#{cat['id']}) | {len(cat['skills'])} |")
    for cat in catalog["categories"]:
        lines += ["", f"## {cat['id']}", "", "| Skill | Verification | Description |", "|---|---|---|"]
        for s in cat["skills"]:
            desc = s["description"].replace("|", "\\|")
            lines.append(f"| [`{s['name']}`]({s['path']}/SKILL.md) | {s['verification']} | {desc} |")
    return json.dumps(catalog, indent=2) + "\n", "\n".join(lines) + "\n"


def render_marketplace(skills) -> str:
    """One plugin per install profile (plus one with everything), all sourced from the repo root."""
    cats = sorted({s["category"] for s in skills})
    counts = Counter(s["category"] for s in skills)
    plugins = []
    for profile, profile_cats in sorted(load_profiles().items()):
        plugins.append({
            "name": f"{PLUGIN_PREFIX}-{profile}",
            "source": "./",
            "description": f"Claude-Blue {profile} profile: {sum(counts[c] for c in profile_cats)} defensive security skills "
                           f"({', '.join(profile_cats)}).",
            "version": VERSION,
            "license": "MIT",
            "keywords": ["security", "blue-team", profile],
            "strict": False,
            "skills": [f"./skills/{c}" for c in profile_cats],
        })
    plugins.append({
        "name": f"{PLUGIN_PREFIX}-all",
        "source": "./",
        "description": f"All {len(skills)} Claude-Blue skills in {len(cats)} categories. Large: may exceed the skill listing budget; prefer a profile plugin.",
        "version": VERSION,
        "license": "MIT",
        "keywords": ["security", "blue-team"],
        "strict": False,
        "skills": [f"./skills/{c}" for c in cats],
    })
    data = {
        "name": "claude-blue-marketplace",
        "owner": {"name": "Claude-Blue maintainers"},
        "metadata": {"description": "Defensive cybersecurity skills for Claude Code", "version": VERSION},
        "plugins": plugins,
    }
    return json.dumps(data, indent=2) + "\n"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_hashes(directory: Path) -> dict:
    return {
        p.relative_to(directory).as_posix(): sha256(p)
        for p in sorted(directory.rglob("*"))
        if p.is_file() and not p.is_symlink()
    }


def select_skills(skills, categories, profiles, names, all_skills):
    known_cats = {s["category"] for s in skills}
    known_names = {s["name"] for s in skills}
    wanted_cats = set(categories or [])
    available_profiles = load_profiles()
    for profile in profiles or []:
        if profile not in available_profiles:
            raise SystemExit(f"Unknown profile {profile!r}. Available: {', '.join(sorted(available_profiles))}")
        wanted_cats.update(available_profiles[profile])
    unknown = wanted_cats - known_cats
    if unknown:
        raise SystemExit("Unknown categories: " + ", ".join(sorted(unknown)))
    unknown = set(names or []) - known_names
    if unknown:
        raise SystemExit("Unknown skills: " + ", ".join(sorted(unknown)))
    if all_skills:
        return skills
    if not (wanted_cats or names):
        raise SystemExit("Select what to install with --profile, --category, --skill or --all "
                         "(see `list --profiles`). Installing every skill can exceed Claude Code's skill listing budget.")
    return [s for s in skills if s["category"] in wanted_cats or s["name"] in (names or [])]


def resolve_target(args) -> Path:
    if args.target:
        return Path(args.target).expanduser().resolve()
    if args.scope == "project":
        return (Path(args.project_dir).expanduser().resolve() / ".claude" / "skills")
    return Path.home() / ".claude" / "skills"


def read_manifest(target: Path):
    manifest = target / MANIFEST_NAME
    if not manifest.is_file():
        return {"project": "Claude-Blue", "version": VERSION, "skills": {}}
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if isinstance(data.get("skills"), list):  # v1 manifest format
        data["skills"] = {item["name"]: item for item in data["skills"]}
    for name, item in data.get("skills", {}).items():
        if not NAME_RE.fullmatch(name) or item.get("path") != name:
            raise SystemExit(f"Refusing to use manifest {manifest}: unsafe entry {name!r}")
    return data


def write_manifest(target: Path, data) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".claude-blue-manifest.", dir=target)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, target / MANIFEST_NAME)


def refuse_root(args) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not args.allow_root:
        raise SystemExit("Refusing to run as root: skills are per-user files. Re-run as your user "
                         "(or pass --allow-root for a deliberate managed deployment).")


def install(args) -> int:
    refuse_root(args)
    skills, errors, _ = validate(check_catalog=False)
    if errors:
        raise SystemExit("Refusing to install: the catalog has validation errors. Run `validate`.")
    selected = select_skills(skills, args.category, args.profile, args.skill, args.all)
    target = resolve_target(args)
    if target.exists() and not target.is_dir():
        raise SystemExit(f"Target {target} exists and is not a directory")
    manifest = read_manifest(target) if target.is_dir() else {"project": "Claude-Blue", "version": VERSION, "skills": {}}
    owned = manifest["skills"]
    plan = []
    for skill in selected:
        name, source = skill["name"], ROOT / skill["path"]
        dest = target / name
        source_hashes = tree_hashes(source)
        if name in owned:
            if not dest.is_dir():
                plan.append(("install", skill, source_hashes))
            elif tree_hashes(dest) != owned[name]["files"]:
                plan.append(("skip-modified", skill, source_hashes))
            elif owned[name]["files"] == source_hashes:
                plan.append(("unchanged", skill, source_hashes))
            elif args.upgrade:
                plan.append(("upgrade", skill, source_hashes))
            else:
                plan.append(("skip-outdated", skill, source_hashes))
        elif dest.exists() or dest.is_symlink():
            plan.append(("conflict", skill, source_hashes))
        else:
            plan.append(("install", skill, source_hashes))
    conflicts = [s["name"] for action, s, _ in plan if action == "conflict"]
    if conflicts:
        raise SystemExit(f"Refusing to overwrite skills not installed by Claude-Blue in {target}: " + ", ".join(conflicts))
    counts = Counter(action for action, _, _ in plan)
    print(f"target={target}")
    for action, skill, _ in plan:
        if action in ("skip-modified", "skip-outdated") or args.verbose:
            note = {"skip-modified": " (local edits detected; left untouched)",
                    "skip-outdated": " (newer version available; pass --upgrade)"}.get(action, "")
            print(f"{action}: {skill['name']}{note}")
    if args.dry_run:
        print("dry-run: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        return 0
    target.mkdir(parents=True, exist_ok=True)
    for action, skill, source_hashes in plan:
        if action not in ("install", "upgrade"):
            continue
        name, source, dest = skill["name"], ROOT / skill["path"], target / skill["name"]
        staging = Path(tempfile.mkdtemp(prefix=f".cb-staging-{name}-", dir=target))
        try:
            shutil.copytree(source, staging / name, symlinks=True)
            if tree_hashes(staging / name) != source_hashes:
                raise SystemExit(f"Copy verification failed for {name}")
            if action == "upgrade":
                retired = Path(tempfile.mkdtemp(prefix=f".cb-retired-{name}-", dir=target))
                os.replace(dest, retired / name)
                os.replace(staging / name, dest)
                shutil.rmtree(retired)
            else:
                os.replace(staging / name, dest)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        owned[name] = {"name": name, "path": name, "category": skill["category"],
                       "version": skill["version"], "files": source_hashes}
        manifest["version"] = VERSION
        write_manifest(target, manifest)
    print(", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0


def uninstall(args) -> int:
    refuse_root(args)
    target = resolve_target(args)
    if not (target / MANIFEST_NAME).is_file():
        raise SystemExit(f"No Claude-Blue manifest in {target}; nothing removed")
    manifest = read_manifest(target)
    owned = manifest["skills"]
    names = set(args.skill or [])
    cats = set(args.category or [])
    chosen = [n for n, item in owned.items() if (not names and not cats) or n in names or item.get("category") in cats]
    removed, kept = [], []
    for name in sorted(chosen):
        dest = target / owned[name]["path"]
        if dest.resolve().parent != target.resolve():
            raise SystemExit(f"Refusing to remove {dest}: outside {target}")
        if not dest.exists():
            removed.append(name)
            continue
        if dest.is_symlink() or not dest.is_dir() or tree_hashes(dest) != owned[name]["files"]:
            kept.append(name)
            continue
        removed.append(name)
        if not args.dry_run:
            shutil.rmtree(dest)
    if not args.dry_run:
        for name in removed:
            owned.pop(name, None)
        if owned:
            write_manifest(target, manifest)
        else:
            (target / MANIFEST_NAME).unlink()
    print(f"target={target} removed={len(removed)} kept_modified={len(kept)}" + (" (dry-run)" if args.dry_run else ""))
    for name in kept:
        print(f"kept (modified or not a regular directory): {name}")
    return 1 if kept else 0


def cmd_validate(args) -> int:
    skills, errors, warnings = validate()
    cats = {s["category"] for s in skills}
    tested = sum(1 for s in skills if s["verification"] == "tested")
    print(f"skills={len(skills)} categories={len(cats)} tested={tested}")
    for w in warnings:
        print("WARNING:", w)
    for e in errors:
        print("ERROR:", e)
    return 1 if errors else 0


def cmd_catalog(args) -> int:
    skills, errors, _ = validate(check_catalog=False)
    if errors:
        for e in errors:
            print("ERROR:", e)
        return 1
    expected_json, expected_md = render_catalog(skills)
    CATALOG_JSON.write_text(expected_json, encoding="utf-8")
    CATALOG_MD.write_text(expected_md, encoding="utf-8")
    MARKETPLACE.parent.mkdir(exist_ok=True)
    MARKETPLACE.write_text(render_marketplace(skills), encoding="utf-8")
    print(f"wrote catalog.json, CATALOG.md and .claude-plugin/marketplace.json ({len(skills)} skills)")
    return 0


def cmd_list(args) -> int:
    if args.profiles:
        for name, cats in sorted(load_profiles().items()):
            count = sum(1 for p in skill_paths() if p.parent.parent.name in cats)
            print(f"{name:10} {count:3} skills  {', '.join(cats)}")
        return 0
    for path in skill_paths():
        skill = load_skill(path)
        if args.category and skill["category"] not in args.category:
            continue
        print(f"{skill['category']:32} {skill['name']:40} {skill['verification']}")
    return 0


def cmd_extract_rules(args) -> int:
    """Write embedded Sigma (```yaml with logsource/detection) and YARA (```yara) blocks to a directory."""
    out = Path(args.out)
    (out / "sigma").mkdir(parents=True, exist_ok=True)
    (out / "yara").mkdir(parents=True, exist_ok=True)
    count = Counter()
    for path in skill_paths():
        text = path.read_text(encoding="utf-8")
        name = path.parent.name
        for i, block in enumerate(re.findall(r"```yaml\n(.*?)```", text, re.S)):
            if "logsource:" in block and "detection:" in block:
                (out / "sigma" / f"{name}-{i}.yml").write_text(block, encoding="utf-8")
                count["sigma"] += 1
        for i, block in enumerate(re.findall(r"```yara\n(.*?)```", text, re.S)):
            (out / "yara" / f"{name}-{i}.yar").write_text(block, encoding="utf-8")
            count["yara"] += 1
    print(f"sigma={count['sigma']} yara={count['yara']} out={out}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="validate skills, references, ATT&CK IDs and catalog freshness")
    sub.add_parser("evaluate", help="alias of validate (kept for CI compatibility)")
    sub.add_parser("catalog", help="regenerate catalog.json, CATALOG.md and the plugin marketplace")
    lp = sub.add_parser("list", help="list skills or install profiles")
    lp.add_argument("--category", action="append")
    lp.add_argument("--profiles", action="store_true")
    ep = sub.add_parser("extract-rules", help="export embedded Sigma/YARA rules for external linting")
    ep.add_argument("--out", required=True)
    for name in ("install", "uninstall"):
        p = sub.add_parser(name)
        p.add_argument("--target", help="explicit skills directory (overrides --scope)")
        p.add_argument("--scope", choices=("user", "project"), default="user",
                       help="user: ~/.claude/skills (default); project: <project-dir>/.claude/skills")
        p.add_argument("--project-dir", default=".")
        p.add_argument("--category", action="append")
        p.add_argument("--skill", action="append")
        p.add_argument("--dry-run", action="store_true")
        p.add_argument("--allow-root", action="store_true")
        if name == "install":
            p.add_argument("--profile", action="append")
            p.add_argument("--all", action="store_true")
            p.add_argument("--upgrade", action="store_true", help="replace unmodified older Claude-Blue installs")
            p.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)
    handlers = {"validate": cmd_validate, "evaluate": cmd_validate, "catalog": cmd_catalog, "list": cmd_list,
                "extract-rules": cmd_extract_rules, "install": install, "uninstall": uninstall}
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
