#!/usr/bin/env python3
"""Scaffold a defensive security tool (Python CLI) with secure defaults, tests and hardened CI.

Usage: new_tool.py <tool-name> [--dir DEST] [--description TEXT]
Creates DEST/<tool-name>/ (refuses to overwrite) with:
  src/<pkg>/cli.py      argparse CLI, validated inputs, JSON/human output, exit codes
  src/<pkg>/safe.py     helpers: bounded file reads, atomic writes, subprocess without shell, redaction
  tests/                unittest suite (runs with `python -m unittest`)
  pyproject.toml, README.md, SECURITY.md, .gitignore
  .github/workflows/ci.yml   pinned actions, read-only token, tests + bandit/ruff (optional)
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,38}[a-z0-9]$")

SAFE_PY = '''"""Security helpers: use these instead of ad-hoc file and process handling."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

MAX_READ_BYTES = 50 * 1024 * 1024
_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\\s*)(bearer|basic)\\s+\\S+"),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\\s*[=:]\\s*)\\S+"),
    re.compile(r"\\bAKIA[0-9A-Z]{16}\\b"),
]


class InputError(ValueError):
    """Raised for invalid user input; the CLI maps it to exit code 2."""


def read_bounded(path: str | os.PathLike, max_bytes: int = MAX_READ_BYTES) -> bytes:
    """Read a regular file without following it into devices/FIFOs and with a size cap."""
    p = Path(path)
    if not p.is_file():
        raise InputError(f"not a regular file: {p}")
    size = p.stat().st_size
    if size > max_bytes:
        raise InputError(f"{p} is {size} bytes; limit is {max_bytes}")
    with p.open("rb") as handle:
        return handle.read(max_bytes + 1)[:max_bytes]


def write_atomic(path: str | os.PathLike, data: bytes, mode: int = 0o600) -> None:
    """Write via a temp file in the same directory, then rename; never leaves partial files."""
    p = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{p.name}.", dir=p.parent or ".")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def run(argv: list[str], timeout: float = 30.0) -> subprocess.CompletedProcess:
    """Run an external program with an argument list (never a shell string) and a timeout."""
    # A plain string is iterable (each character is a str), so check the container type explicitly.
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
        raise InputError("argv must be a non-empty list of strings, never a shell command string")
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, shell=False)


def redact(text: str) -> str:
    """Mask common credential patterns before logging or printing."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", text)
    return text
'''

CLI_PY = '''"""{description}"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from . import __version__
from .safe import InputError, read_bounded, redact

log = logging.getLogger("{pkg}")


def analyse(data: bytes) -> dict:
    """Replace with the tool's real logic. Keep it pure (no I/O) so it is easy to test."""
    text = data.decode("utf-8", errors="replace")
    return {{"bytes": len(data), "lines": text.count("\\n"), "preview": redact(text[:200])}}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="{name}", description=__doc__)
    ap.add_argument("input", help="file to analyse (read-only)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {{__version__}}")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        result = analyse(read_bounded(args.input))
    except InputError as exc:
        print(f"error: {{exc}}", file=sys.stderr)
        return 2
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        for key, value in result.items():
            print(f"{{key}}: {{value}}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

TEST_PY = '''import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from {pkg}.cli import analyse, main
from {pkg}.safe import InputError, read_bounded, redact, run, write_atomic


class SafeHelpers(unittest.TestCase):
    def test_redact(self):
        self.assertEqual(redact("password=hunter2"), "password=[REDACTED]")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", redact("key AKIAABCDEFGHIJKLMNOP"))
        self.assertIn("[REDACTED]", redact("Authorization: Bearer abc.def"))

    def test_read_bounded_rejects_large_and_non_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "big"
            big.write_bytes(b"x" * 11)
            with self.assertRaises(InputError):
                read_bounded(big, max_bytes=10)
            with self.assertRaises(InputError):
                read_bounded(tmp)

    def test_write_atomic_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.json"
            write_atomic(target, b"{{}}")
            self.assertEqual(target.read_bytes(), b"{{}}")
            if os.name == "posix":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_run_refuses_shell_strings(self):
        with self.assertRaises(InputError):
            run("echo hi")  # type: ignore[arg-type]


class Cli(unittest.TestCase):
    def test_analyse_redacts_preview(self):
        self.assertNotIn("hunter2", analyse(b"token=hunter2\\n")["preview"])

    def test_json_output_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "s.txt"
            sample.write_text("a\\nb\\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertEqual(main([str(sample), "--json"]), 0)
            self.assertEqual(json.loads(buf.getvalue())["bytes"], 4)
            self.assertEqual(main([str(Path(tmp) / "missing")]), 2)


if __name__ == "__main__":
    unittest.main()
'''

CI_YML = '''name: ci
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0
        with:
          python-version: "3.12"
      - run: python -m pip install --upgrade pip bandit ruff
      - run: ruff check src tests
      - run: bandit -q -r src
      - run: PYTHONPATH=src python -m unittest discover -s tests -v
'''

PYPROJECT = '''[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[project]
name = "{name}"
version = "0.1.0"
description = "{description}"
requires-python = ">=3.10"
license = {{text = "MIT"}}
dependencies = []

[project.scripts]
{name} = "{pkg}.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
'''

README = '''# {name}

{description}

## Usage

```bash
python -m pip install .
{name} path/to/input --json
```

## Safety

Read-only by default; reads at most 50 MB per file; never invokes a shell; redacts common secrets
in output. Use only on data and systems you are authorized to analyse.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```
'''

SECURITY_MD = '''# Security policy

Report vulnerabilities privately via the repository's security advisories ("Report a vulnerability")
rather than public issues. Please include steps to reproduce and affected versions.
'''


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name")
    ap.add_argument("--dir", default=".")
    ap.add_argument("--description", default="Defensive security utility.")
    args = ap.parse_args(argv)
    if not NAME_RE.fullmatch(args.name):
        print("error: name must be lowercase letters, digits and hyphens (3-40 chars)", file=sys.stderr)
        return 2
    if any(c in args.description for c in '"\\\n'):
        print("error: description must not contain quotes, backslashes or newlines", file=sys.stderr)
        return 2
    pkg = args.name.replace("-", "_")
    root = Path(args.dir) / args.name
    if root.exists():
        print(f"error: {root} already exists; refusing to overwrite", file=sys.stderr)
        return 2
    values = {"name": args.name, "pkg": pkg, "description": args.description}
    files = {
        f"src/{pkg}/__init__.py": '__version__ = "0.1.0"\n',
        f"src/{pkg}/__main__.py": "import sys\n\nfrom .cli import main\n\nsys.exit(main())\n",
        f"src/{pkg}/safe.py": SAFE_PY,
        f"src/{pkg}/cli.py": CLI_PY.format(**values),
        "tests/__init__.py": "",
        f"tests/test_{pkg}.py": TEST_PY.format(**values),
        "pyproject.toml": PYPROJECT.format(**values),
        "README.md": README.format(**values),
        "SECURITY.md": SECURITY_MD,
        ".gitignore": "__pycache__/\n*.pyc\n.venv/\ndist/\nbuild/\n*.egg-info/\n",
        ".github/workflows/ci.yml": CI_YML,
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(f"created {root} ({len(files)} files)")
    print(f"next: cd {root} && PYTHONPATH=src python -m unittest discover -s tests -v")
    return 0


if __name__ == "__main__":
    sys.exit(main())
