"""Command line: plan, apply (to a copy) and verify fixes.

  python -m remediation.run <repo> --scan scan.json                       # plan + patches only
  python -m remediation.run <repo> --scan scan.json --verify              # + re-scan the patched copy
  python -m remediation.run <repo> --scan scan.json --verify --test-cmd "pytest -q" --venv

Two kinds of fixes, applied to the same COPY of the project (the original is never modified):
  * library upgrades   -> dependency_upgrades.patch   (requirements*.txt version numbers)
  * code fixes         -> code_fixes.patch            (Bandit findings with an automatic fix; --no-code to skip)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .apply import apply_upgrades, make_workspace
from .code_fix import (CodeVerification, default_code_scan, not_automated, select_code_findings, verify_code)
from .code_patcher import CodePatchResult, apply_code_patches
from .plan import Plan, plan_upgrades
from .verify import default_scan, run_tests, verify


def _table(plan: Plan) -> str:
    rows = ["  PRIORITY  PACKAGE            CURRENT -> TARGET        RISK   FIXES  FILE:LINE"]
    for u in plan.upgrades:
        rows.append(f"  {u.max_risk_score:7.2f}   {u.package:<17} {u.current:>9} -> {u.target:<12} {u.risk:<6} "
                    f"{len(u.fixes):>5}  {u.file}:{u.line}")
    return "\n".join(rows)


def _top_level_requirements(ws: Path) -> List[str]:
    return sorted(p.name for p in Path(ws).glob("requirements*.txt"))


def build_report(plan: Plan, applied, verification, code: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "plan": plan.to_dict(),
        "applied": [e.upgrade.to_dict() for e in applied.applied] if applied else [],
        "skipped": [{"upgrade": e.upgrade.to_dict(), "reason": e.reason} for e in applied.skipped] if applied else [],
        "verification": verification.to_dict() if verification else None,
        "code": code,
    }


def build_code_report(res: Optional[CodePatchResult], ver: Optional[CodeVerification],
                      findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    edits = [e.to_dict() for e in res.edits] if res else []
    return {
        "applied": [e for e in edits if e["applied"]],
        "skipped": [e for e in edits if not e["applied"]],
        "not_automated": not_automated(findings),
        "verification": ver.to_dict() if ver else None,
    }


def main(argv: Optional[List[str]] = None, scan_fn: Optional[Callable[[str], Any]] = None,
         code_scan_fn: Optional[Callable[[str], Any]] = None) -> int:
    ap = argparse.ArgumentParser(prog="remediation.run", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", help="the scanned repository (never modified)")
    ap.add_argument("--scan", required=True, help="JSON from: python -m core.pipeline <repo> -o scan.json")
    ap.add_argument("--out", default="remediation_out", help="output folder (default remediation_out)")
    ap.add_argument("--allow-major", action="store_true", help="also apply major-version jumps (risky)")
    ap.add_argument("--no-code", action="store_true", help="do not generate code fixes (libraries only)")
    ap.add_argument("--verify", action="store_true", help="re-scan the patched copy (libraries need network)")
    ap.add_argument("--offline", action="store_true", help="use cached vulnerability data only when verifying")
    ap.add_argument("--test-cmd", help='run the project\'s tests on the patched copy, e.g. "pytest -q"')
    ap.add_argument("--venv", action="store_true", help="build a fresh virtualenv from the upgraded requirements "
                                                        "before running tests (needed for a 'verified' status)")
    ap.add_argument("--timeout", type=int, default=900, help="seconds allowed per setup/test step")
    args = ap.parse_args(argv)

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"Error: {repo} is not a directory", file=sys.stderr)
        return 2
    try:
        findings = json.loads(Path(args.scan).read_text(encoding="utf-8"))
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error reading {args.scan}: {exc}", file=sys.stderr)
        return 2

    plan = plan_upgrades(findings, allow_major=args.allow_major)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print(f"Dependency upgrades to apply: {len(plan.upgrades)}")
    if plan.upgrades:
        print(_table(plan))
    if plan.needs_review:
        print(f"\nNeeds manual review (major version jump, not applied): {len(plan.needs_review)}")
        for u in plan.needs_review:
            print(f"  {u.package} {u.current} -> {u.target}  ({len(u.fixes)} fixes)  {u.file}:{u.line}")
    if plan.no_fix:
        print(f"\nNo known fixed version: {len(plan.no_fix)}")
        for n in plan.no_fix:
            print(f"  {n['package']}=={n['current']}  {n['file']}:{n['line']}  ({len(n['vulns'])} vulnerabilities)")

    ws = make_workspace(repo, out / "workspace")
    applied = apply_upgrades(ws, plan.upgrades)
    for e in applied.skipped:
        print(f"[skipped] {e.upgrade.package}: {e.reason}")
    if applied.diff:
        (out / "dependency_upgrades.patch").write_text(applied.diff, encoding="utf-8", newline="\n")
        print(f"\n[+] Library patch written to {out / 'dependency_upgrades.patch'}")

    code_res: Optional[CodePatchResult] = None
    if not args.no_code:
        todo = select_code_findings(findings)
        manual = not_automated(findings)
        print(f"\nCode fixes (Bandit): {len(todo)} finding(s) have an automatic fix; "
              f"{sum(manual.values())} are explained only")
        if todo:
            code_res = apply_code_patches(ws, todo, out / "workspace_final")
            for e in code_res.edits:
                print(f"  {e.test_id:<5} {e.tier:<12} {e.file}:{e.line:<5} "
                      f"{'applied' if e.applied else 'skipped: ' + (e.reason or e.status)}")
            if code_res.diff:
                (out / "code_fixes.patch").write_text(code_res.diff, encoding="utf-8", newline="\n")
                print(f"[+] Code patch written to {out / 'code_fixes.patch'}  "
                      f"({len(code_res.applied)} edit(s); 'needs_review' fixes need a human look)")

    final_ws = code_res.workspace if code_res else ws
    applied.workspace = final_ws          # re-scan and tests must see the library AND the code fixes together

    verification = code_ver = None
    if args.verify or args.test_cmd:
        fn = scan_fn or (lambda p: default_scan(p, offline=args.offline))
        verification = verify(applied, findings, fn, test_cmd=args.test_cmd, use_venv=args.venv, timeout=args.timeout)
        v = verification
        print(f"\nLibrary verification: {v.status.upper()}")
        print(f"  vulnerabilities resolved: {len(v.resolved)}   still present: {len(v.remaining)}   "
              f"newly introduced: {len(v.introduced)}")
        for m in v.messages:
            print(f"  - {m}")
        if code_res and code_res.applied:
            tests = v.tests if (applied.applied and v.tests.command) else None
            if tests is None and args.test_cmd:
                tests = run_tests(final_ws, args.test_cmd, _top_level_requirements(final_ws), args.venv, args.timeout)
            code_ver = verify_code(code_res, repo, code_scan_fn or default_code_scan, tests, args.venv)
            print(f"\nCode verification: {code_ver.status.upper()}")
            print(f"  confirmed gone: {len(code_ver.confirmed)}   still present: {len(code_ver.remaining)}   "
                  f"newly introduced: {len(code_ver.introduced)}")
            for m in code_ver.messages:
                print(f"  - {m}")

    code_report = build_code_report(code_res, code_ver, findings) if not args.no_code else None
    (out / "report.json").write_text(json.dumps(build_report(plan, applied, verification, code_report), indent=2),
                                     encoding="utf-8", newline="\n")
    print(f"[+] Report written to {out / 'report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
