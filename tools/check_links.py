#!/usr/bin/env python3
"""Check every external URL cited in skills, references and docs (stdlib only).

  python3 tools/check_links.py                    # all Markdown under skills/, docs/ and README.md
  python3 tools/check_links.py --json report.json skills/dfir

Each URL is tried with HEAD, then GET when HEAD is refused. Results:
  ok       2xx/3xx
  broken   404, 410, DNS failure or connection refused: fix these
  blocked  401/403/405/429/5xx or timeout: many sites refuse automated clients; check by hand
Exit 1 when any URL is broken. Duplicate URLs are checked once.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
URL_RE = re.compile(r"https?://[^\s<>()\"'`|]+")
TRAILING = ".,;:!?*_]}>"
SKIP_HOSTS = ("example.com", "example.org", "example.net", "example", "localhost", "127.0.0.1", "ORG.okta.com")
UA = "Mozilla/5.0 (X11; Linux x86_64) claude-blue-link-check/1.0"


def extract(paths):
    found = defaultdict(set)
    for base in paths:
        files = [base] if base.is_file() else sorted(base.rglob("*.md"))
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            in_code = False
            for line in text.splitlines():
                if line.lstrip().startswith("```"):
                    in_code = not in_code
                    continue
                if in_code:
                    continue  # URLs in code blocks are commands and placeholders, not citations
                for url in URL_RE.findall(re.sub(r"`[^`]*`", "", line)):  # skip inline code too
                    url = url.rstrip(TRAILING)
                    host = url.split("/")[2] if url.count("/") >= 2 else ""
                    if any(host == h or host.endswith("." + h) for h in SKIP_HOSTS) or "." not in host:
                        continue
                    found[url].add(path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path))
    return found


def probe(url, timeout):
    last = None
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": UA, "Accept": "*/*"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return "ok", resp.status
        except urllib.error.HTTPError as exc:
            exc.close()
            last = exc.code
            if exc.code in (404, 410) and method == "GET":
                return "broken", exc.code
            if exc.code in (404, 410, 405, 403, 400, 501):
                continue  # some servers reject HEAD only
            return "blocked", exc.code
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (socket.gaierror, ConnectionRefusedError)):
                return "broken", str(reason)
            last = str(reason)
        except (TimeoutError, socket.timeout):
            last = "timeout"
        except Exception as exc:  # noqa: BLE001 - report anything else as blocked
            last = f"{type(exc).__name__}: {exc}"
    if last in (404, 410):
        return "broken", last
    return "blocked", last


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", type=Path)
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--json", type=Path, help="write the full report here")
    args = ap.parse_args(argv)
    paths = [p.resolve() for p in args.paths] or [ROOT / "skills", ROOT / "docs", ROOT / "README.md"]
    urls = extract(paths)
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(probe, url, args.timeout): url for url in sorted(urls)}
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()
    counts = defaultdict(int)
    for url in sorted(results):
        status, detail = results[url]
        counts[status] += 1
        if status != "ok":
            print(f"{status.upper():8} {detail}  {url}  ({', '.join(sorted(urls[url])[:3])})")
    print(f"checked={len(results)} ok={counts['ok']} broken={counts['broken']} blocked={counts['blocked']}")
    if args.json:
        args.json.write_text(json.dumps({u: {"status": s, "detail": d, "files": sorted(urls[u])}
                                         for u, (s, d) in sorted(results.items())}, indent=2))
    return 1 if counts["broken"] else 0


if __name__ == "__main__":
    sys.exit(main())
