"""Scan pipeline: runs every engine and collects findings.

Usage:
    python -m core.pipeline <repo_path>            # readable table
    python -m core.pipeline <repo_path> --json     # full JSON
    python -m core.pipeline <repo_path> --offline  # use cached data only
"""
import argparse
import json
import logging
import sys
from typing import List, Optional

from core.finding import Finding
from engines.dependency_engine import DependencyEngine
# from engines.secrets_engine import SecretsEngine
# from engines.crypto_engine import CryptoEngine
# from engines.churn_engine import ChurnEngine


def get_engines(offline: bool = False):
    return [DependencyEngine(offline=offline)]  # add real engines here as you build them


def run_scan(repo_path: str, engines: Optional[list] = None) -> List[Finding]:
    engines = engines if engines is not None else get_engines()
    findings: List[Finding] = []
    for engine in engines:
        print(f"[+] Running {engine.name} engine...", file=sys.stderr)
        findings.extend(engine.scan(repo_path))
    return findings


def _ascii(s: str) -> str:
    return s.encode("ascii", "replace").decode("ascii")


def print_table(findings: List[Finding]) -> None:
    if not findings:
        print("No findings.")
        return
    findings = sorted(findings, key=lambda f: (-f.severity, -f.exploitability))
    print(f"\n{'#':>3}  {'SEV':>4}  {'EXPL':>5}  {'ENGINE':<11} {'LOCATION':<28} TITLE")
    print("-" * 110)
    for i, f in enumerate(findings, 1):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        if len(loc) > 28:
            loc = "..." + loc[-25:]
        title = _ascii(f.title)
        if len(title) > 60:
            title = title[:57] + "..."
        print(f"{i:>3}  {f.severity:>4.1f}  {f.exploitability:>5.2f}  {f.engine:<11} {loc:<28} {title}")
    print(f"\nTotal: {len(findings)} finding(s)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan a repository")
    ap.add_argument("path", nargs="?", default=".", help="repository to scan")
    ap.add_argument("--json", action="store_true", help="print full JSON instead of a table")
    ap.add_argument("--offline", action="store_true", help="use cached API data only")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    engines = get_engines(offline=args.offline)
    findings = run_scan(args.path, engines)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print_table(findings)
        for e in engines:
            if getattr(e, "stats", None):
                print(f"[{e.name}] {json.dumps(e.stats)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
