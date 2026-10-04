"""Scan pipeline: runs every engine and collects findings.

Usage:
    python -m core.pipeline <repo_path>            # readable table
    python -m core.pipeline <repo_path> --json     # full JSON
    python -m core.pipeline <repo_path> -o out.json  # full JSON saved as UTF-8 (recommended)
    python -m core.pipeline <repo_path> --offline     # dependency engine: cached data only
    python -m core.pipeline <repo_path> --no-history  # secrets engine: skip git-history scan
"""
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from core.dedup import deduplicate_findings
from core.finding import Finding
from core.suppression import filter_suppressions, save_baseline
from engines.bandit_engine import BanditEngine
from engines.dependency_engine import DependencyEngine
from engines.secrets_engine import SecretsEngine
from engines.semgrep_engine import SemgrepEngine
# from engines.crypto_engine import CryptoEngine
# from engines.churn_engine import ChurnEngine


def get_engines(
    offline: bool = False,
    scan_history: bool = True,
    run_bandit: bool = True,
    run_semgrep: bool = True,
    bandit_config: Optional[str] = None,
    semgrep_rules: Optional[str] = None,
    enabled_engines: Optional[List[str]] = None,
) -> list:
    all_engines = [
        DependencyEngine(offline=offline),
        SecretsEngine(scan_history=scan_history),
        BanditEngine(config_file=bandit_config),
        SemgrepEngine(rules_path=semgrep_rules),
        # CryptoEngine(), ChurnEngine()  <- added in later steps
    ]
    if enabled_engines is not None:
        selected = {e.strip().lower() for e in enabled_engines}
        return [e for e in all_engines if e.name.lower() in selected]

    active = []
    for e in all_engines:
        if e.name == "bandit" and not run_bandit:
            continue
        if e.name == "semgrep" and not run_semgrep:
            continue
        active.append(e)
    return active


def run_scan(
    repo_path: str,
    engines: Optional[list] = None,
    dedup: bool = True,
    baseline_path: Optional[str] = None,
    include_suppressed: bool = False,
) -> List[Finding]:
    engines = engines if engines is not None else get_engines()
    findings: List[Finding] = []
    for engine in engines:
        print(f"[+] Running {engine.name} engine...", file=sys.stderr)
        findings.extend(engine.scan(repo_path))

    if dedup and findings:
        raw_count = len(findings)
        findings = deduplicate_findings(findings)
        merged = raw_count - len(findings)
        if merged > 0:
            print(f"[+] Correlated & merged {merged} duplicate/overlapping finding(s)", file=sys.stderr)

    active, suppressed = filter_suppressions(
        findings,
        repo_path=repo_path,
        baseline_path=baseline_path,
        include_suppressed=include_suppressed,
    )
    if suppressed and not include_suppressed:
        print(f"[+] Filtered {len(suppressed)} suppressed finding(s)", file=sys.stderr)

    return active


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
        engine_label = f"{f.engine}*" if f.extra.get("corroborated") else f.engine
        print(f"{i:>3}  {f.severity:>4.1f}  {f.exploitability:>5.2f}  {engine_label:<11} {loc:<28} {title}")
    print(f"\nTotal: {len(findings)} finding(s)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan a repository")
    ap.add_argument("path", nargs="?", default=".", help="repository to scan")
    ap.add_argument("--json", action="store_true", help="print full JSON instead of a table")
    ap.add_argument("--offline", action="store_true", help="dependency engine: use cached API data only")
    ap.add_argument("--no-history", action="store_true", help="secrets engine: skip the git-history scan")
    ap.add_argument("--no-bandit", action="store_true", help="skip the Bandit security engine")
    ap.add_argument("--no-semgrep", action="store_true", help="skip the Semgrep security engine")
    ap.add_argument("--no-dedup", action="store_true", help="disable cross-tool finding deduplication")
    ap.add_argument("--baseline", metavar="FILE", help="path to baseline suppression JSON file")
    ap.add_argument("--make-baseline", metavar="FILE", help="record current findings into a baseline file")
    ap.add_argument("--include-suppressed", action="store_true", help="include suppressed findings in report")
    ap.add_argument("--bandit-config", metavar="FILE", help="path to custom Bandit YAML config file")
    ap.add_argument("--semgrep-rules", "--semgrep-config", metavar="PATH_OR_PRESET",
                    help="custom Semgrep rules file, directory, or preset (e.g., p/python)")
    ap.add_argument("--engines", metavar="LIST",
                    help="comma-separated list of engines to run (e.g. dependency,secrets,bandit,semgrep)")
    ap.add_argument("--output", "-o", metavar="FILE",
                    help="write full JSON to FILE (UTF-8). Use this instead of '>' in PowerShell, "
                         "which saves UTF-16 that many tools cannot read")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    enabled = [e.strip() for e in args.engines.split(",")] if args.engines else None
    engines = get_engines(
        offline=args.offline,
        scan_history=not args.no_history,
        run_bandit=not args.no_bandit,
        run_semgrep=not args.no_semgrep,
        bandit_config=args.bandit_config,
        semgrep_rules=args.semgrep_rules,
        enabled_engines=enabled,
    )
    findings = run_scan(
        args.path,
        engines=engines,
        dedup=not args.no_dedup,
        baseline_path=args.baseline,
        include_suppressed=args.include_suppressed,
    )

    if args.make_baseline:
        saved_count = save_baseline(findings, Path(args.make_baseline))
        print(f"[+] Wrote {saved_count} findings to baseline {args.make_baseline}", file=sys.stderr)
        return 0

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            json.dump([f.to_dict() for f in findings], fh, indent=2)
        print(f"[+] Wrote {len(findings)} findings to {args.output} (UTF-8)", file=sys.stderr)
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
