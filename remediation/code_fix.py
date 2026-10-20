"""Code remediation: connect Roshan's AST patcher to the plan -> apply -> verify flow.

select_code_findings()  which scanner findings have an automatic code fix
verify_code()           re-scan the ORIGINAL and the PATCHED copy with the same scanner, so the comparison is
                        like for like: every targeted finding must be gone and nothing new may appear.

Status meanings (same spirit as the library flow, nothing is over-claimed):
  verified         re-scan clean AND the project's tests passed in a fresh venv
  scan_only        re-scan clean; tests not run (or run in the current environment). Not proven safe
  needs_review     a targeted finding is still reported, a new one appeared, or a patched file no longer parses
  tests_failed     the project's tests failed with the fixes applied
  scan_unavailable the scanner could not run (for example Bandit is not installed): fixes are NOT confirmed
  nothing_applied  no code edit was applied
"""
from __future__ import annotations

import ast
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .code_patcher import CodePatchResult, _extract_file, _extract_test_id, can_auto_patch
from .verify import TestOutcome

ScanFn = Callable[[str], Iterable[Any]]


def _engine(f: Any) -> str:
    return f.get("engine", "") if isinstance(f, dict) else getattr(f, "engine", "")


def select_code_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Bandit findings whose rule has an automatic fix (mechanical or needs_review tier)."""
    return [f for f in findings if _engine(f) == "bandit" and can_auto_patch(f)]


def not_automated(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """Bandit rules we only explain (no automatic fix), with how many findings each has."""
    c = Counter(_extract_test_id(f) or "UNKNOWN" for f in findings if _engine(f) == "bandit" and not can_auto_patch(f))
    return dict(sorted(c.items(), key=lambda kv: -kv[1]))


def _norm(path: str) -> str:
    p = (path or "").replace("\\", "/")
    return p[2:] if p.startswith("./") else p


def count_by_rule(findings: Iterable[Any]) -> Counter:
    return Counter((_norm(_extract_file(f)), _extract_test_id(f)) for f in findings
                   if _engine(f) == "bandit" and _extract_test_id(f))


def default_code_scan(path: str) -> List[Any]:
    from engines.bandit_engine import BanditEngine
    eng = BanditEngine()
    found = eng.scan(path)
    st = getattr(eng, "stats", {}) or {}
    if st.get("skipped"):
        raise RuntimeError("Bandit is not installed, so the fixes could not be re-scanned")
    if st.get("parse_error"):
        raise RuntimeError("Bandit output could not be read")
    return list(found)


@dataclass
class CodeVerification:
    status: str
    confirmed: List[str] = field(default_factory=list)      # one entry per (file, rule), e.g. 'B113 a.py x2'
    remaining: List[str] = field(default_factory=list)
    confirmed_count: int = 0                                 # number of FINDINGS confirmed gone
    remaining_count: int = 0
    introduced: List[str] = field(default_factory=list)
    syntax_errors: List[str] = field(default_factory=list)
    tests: TestOutcome = field(default_factory=TestOutcome)
    messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def verify_code(result: CodePatchResult, original_repo: Path, scan_fn: ScanFn,
                tests: Optional[TestOutcome] = None, fresh_venv: bool = False) -> CodeVerification:
    done = result.applied
    if not done:
        return CodeVerification("nothing_applied", messages=["No code edit could be applied; see the skipped list."])

    v = CodeVerification("scan_only")
    for rel in sorted({_norm(e.file) for e in done}):
        try:
            ast.parse((Path(result.workspace) / rel).read_bytes())
        except (SyntaxError, ValueError, OSError) as exc:
            v.syntax_errors.append(f"{rel}: {exc}")
    try:
        before = count_by_rule(scan_fn(str(original_repo)))
        after = count_by_rule(scan_fn(str(result.workspace)))
    except Exception as exc:                      # scanner missing or crashed: never claim success
        v.status = "needs_review" if v.syntax_errors else "scan_unavailable"
        v.messages.append(f"Re-scan not possible: {exc}. The fixes are NOT confirmed.")
        return v

    targeted = Counter((_norm(e.file), e.test_id) for e in done)
    for key, n in sorted(targeted.items()):
        label = f"{key[1]} {key[0]}" + (f" x{n}" if n > 1 else "")
        if after[key] <= before[key] - n:
            v.confirmed.append(label)
            v.confirmed_count += n
        else:
            v.remaining.append(label)
            v.remaining_count += n
    for key in sorted(after):
        if after[key] > before[key]:
            v.introduced.append(f"{key[1]} {key[0]} (+{after[key] - before[key]})")

    if v.remaining:
        v.messages.append(f"{len(v.remaining)} fixed finding(s) are still reported after the patch.")
    if v.introduced:
        v.messages.append(f"{len(v.introduced)} new finding(s) appeared after the patch.")
    if v.syntax_errors:
        v.messages.append("A patched file no longer parses.")
    if v.remaining or v.introduced or v.syntax_errors:
        v.status = "needs_review"

    if tests is not None:
        v.tests = tests
        if not tests.ran:
            v.messages.append(f"Tests did not run: {tests.error}")
        elif not tests.passed:
            v.status = "tests_failed"
            v.messages.append("The project's tests FAILED with the code fixes applied.")
        elif not fresh_venv:
            v.messages.append("Tests passed in the current environment only. Re-run with --venv for a full check.")
        elif v.status == "scan_only":
            v.status = "verified"
    else:
        v.messages.append("No tests were run (use --test-cmd and --venv). The fixes are not proven safe.")
    return v
