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
import copy
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .code_patcher import CodePatchResult, _extract_file
from .more_fixes import SECRET_ID, patcher_id, select_secret_findings, source_rule
from .verify import TestOutcome

ScanFn = Callable[[str], Iterable[Any]]


ENGINES = ("bandit", "semgrep", "crypto", "secrets")


def _engine(f: Any) -> str:
    return f.get("engine", "") if isinstance(f, dict) else getattr(f, "engine", "")


def select_code_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Bandit, Semgrep and crypto findings that have an automatic fix, normalised to the patcher's rule id.

    A copy of each finding gets extra.test_id (the patcher id) plus extra.source_engine / source_rule, so one
    finding is fixed once even when two engines reported it on the same line.
    """
    out, seen = [], set()
    for f in findings:
        if _engine(f) not in ("bandit", "semgrep", "crypto"):
            continue
        pid = patcher_id(f)
        if not pid:
            continue
        key = (_norm(_extract_file(f)), f.get("line"), pid)
        if key in seen:
            continue
        seen.add(key)
        eng, rule = source_rule(f)
        g = copy.deepcopy(f)
        g["extra"] = dict(g.get("extra") or {}, test_id=pid, source_engine=eng, source_rule=rule)
        out.append(g)
    return out


def edit_sources(code_findings: Iterable[Dict[str, Any]], secret_findings: Iterable[Dict[str, Any]] = ()) -> Dict:
    """(file, line, patcher id) -> (engine, rule) of the finding each edit was made for."""
    m: Dict = {}
    for f in code_findings:
        x = f["extra"]
        m[(_norm(_extract_file(f)), int(f.get("line") or 0), x["test_id"])] = (x["source_engine"], x["source_rule"])
    for f in secret_findings:
        m[(_norm(_extract_file(f)), int(f.get("line") or 0), SECRET_ID)] = source_rule(f)
    return m


def not_automated(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """Findings (all four code engines) that we only explain, grouped as 'engine rule' with a count."""
    fixable = {id(f) for f in select_secret_findings(findings)}
    c: Counter = Counter()
    for f in findings:
        eng = _engine(f)
        if eng not in ENGINES or (eng != "secrets" and patcher_id(f)):
            continue
        if eng == "secrets" and id(f) in fixable:
            continue
        c[f"{eng} {source_rule(f)[1] or 'unknown'}"] += 1
    return dict(sorted(c.items(), key=lambda kv: -kv[1]))


def _norm(path: str) -> str:
    p = (path or "").replace("\\", "/")
    return p[2:] if p.startswith("./") else p


def count_by_rule(findings: Iterable[Any]) -> Counter:
    """Counts per (engine, file, rule) for the four code engines."""
    c: Counter = Counter()
    for f in findings:
        eng = _engine(f)
        if eng in ENGINES:
            rule = source_rule(f)[1]
            if rule:
                c[(eng, _norm(_extract_file(f)), rule)] += 1
    return c


def default_code_scan(path: str, engines: Iterable[str] = ("bandit",)) -> List[Any]:
    """Run the named engines on a folder. An engine that cannot run raises, so a fix is never confirmed by silence."""
    out: List[Any] = []
    for name in engines:
        if name == "bandit":
            from engines.bandit_engine import BanditEngine as E
            eng = E()
        elif name == "semgrep":
            from engines.semgrep_engine import SemgrepEngine as E
            eng = E()
        elif name == "crypto":
            from engines.crypto_engine import CryptoEngine as E
            eng = E()
        elif name == "secrets":
            from engines.secrets_engine import SecretsEngine as E
            eng = E(scan_history=False)
        else:
            continue
        found = eng.scan(path)
        st = getattr(eng, "stats", {}) or {}
        if st.get("skipped"):
            raise RuntimeError(f"{name} is not available ({st.get('note', 'not installed')}), so the fixes could "
                               "not be re-scanned")
        if st.get("parse_error"):
            raise RuntimeError(f"{name} output could not be read")
        out.extend(found)
    return out


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
                tests: Optional[TestOutcome] = None, fresh_venv: bool = False,
                sources: Optional[Dict] = None) -> CodeVerification:
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

    sources = sources or {}
    targeted = Counter()
    for e in done:
        eng, rule = sources.get((_norm(e.file), e.line, e.test_id), ("bandit", e.test_id))
        targeted[(eng, _norm(e.file), rule)] += 1
    for key, n in sorted(targeted.items()):
        label = f"{key[0]} {key[2]} {key[1]}" + (f" x{n}" if n > 1 else "")
        if after[key] <= before[key] - n:
            v.confirmed.append(label)
            v.confirmed_count += n
        else:
            v.remaining.append(label)
            v.remaining_count += n
    for key in sorted(after):
        if after[key] > before[key]:
            v.introduced.append(f"{key[0]} {key[2]} {key[1]} (+{after[key] - before[key]})")

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
