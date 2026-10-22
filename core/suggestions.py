"""Code suggestion generator for GitHub PR reviews.

Generates native GitHub ```suggestion diff blocks for instant one-click
commit remediation in pull request reviews.
"""
from __future__ import annotations

import ast
import difflib
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.finding import Finding


@dataclass
class CodeSuggestion:
    file: str
    line: int
    end_line: Optional[int]
    replacement: str
    explanation: str

    def to_markdown(self) -> str:
        """Render suggestion as a GitHub Markdown review comment with ```suggestion block."""
        return (
            f"> 🛡️ **SCIP Recommendation**: {self.explanation}\n\n"
            f"```suggestion\n"
            f"{self.replacement}\n"
            f"```"
        )


def _extract_target_version(fix_hint: str) -> Optional[str]:
    """Extract recommended version from fix hint string (e.g. 'Upgrade pillow from 6.2.0 to 10.0.1 or later.')."""
    if not fix_hint:
        return None
    match = re.search(r"(?:to|>=)\s*([0-9]+(?:\.[0-9a-zA-Z]+)+)", fix_hint)
    if match:
        return match.group(1)
    return None


# --------------------------------------------------------------------------- verified suggestions
# Suggestions built from the real file and the same AST patchers that remediation/ uses, so a suggested line is exactly
# what the verified patch would write (indentation, comments, markers and multi-line calls preserved). Evidence is NOT used:
# Bandit's evidence is a numbered multi-line snippet, which is not a replaceable source line.

def _as_dict(f: Any) -> Dict[str, Any]:
    return f if isinstance(f, dict) else f.to_dict()


def _read_inside(root: Path, rel: str) -> Optional[str]:
    base = root.resolve()
    try:
        p = (base / rel).resolve()
        p.relative_to(base)
        return p.read_bytes().decode("utf-8")
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _dependency_suggestions(dicts: List[Dict[str, Any]], root: Path) -> List[CodeSuggestion]:
    from remediation.apply import _edit_line
    from remediation.plan import plan_upgrades
    out: List[CodeSuggestion] = []
    for u in plan_upgrades(dicts).upgrades:                       # major jumps are not suggested for one-click merge
        text = _read_inside(root, u.file)
        lines = text.splitlines(keepends=True) if text else []
        if not 1 <= u.line <= len(lines):
            continue
        new, _ = _edit_line(lines[u.line - 1], u)
        if new is None:
            continue
        out.append(CodeSuggestion(
            file=u.file.replace("\\", "/"), line=u.line, end_line=u.line, replacement=new.rstrip("\r\n"),
            explanation=f"Upgrade `{u.package}` {u.current} to `{u.target}`: fixes {len(u.fixes)} known "
                        f"vulnerabilit{'y' if len(u.fixes) == 1 else 'ies'} ({u.risk} update). Run your tests after merging."))
    return out


def _code_suggestions(dicts: List[Dict[str, Any]], root: Path) -> List[CodeSuggestion]:
    from remediation.code_fix import select_code_findings
    from remediation.code_patcher import RULE_PATCHERS, patch_file_content
    by_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for f in select_code_findings(dicts):
        by_file[str(f["file"]).replace("\\", "/")].append(f)
    out: List[CodeSuggestion] = []
    for rel, fs in sorted(by_file.items()):
        text = _read_inside(root, rel)
        if text is None:
            continue
        new, records = patch_file_content(text, fs, rel)
        if new == text:
            continue
        a, b = text.splitlines(keepends=True), new.splitlines(keepends=True)
        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
            if tag == "insert" and i1 >= 1:                           # a suggestion can only replace lines:
                i1, i2, j1 = i1 - 1, i1, j1 - 1                         # replace the previous line by itself + the new ones
            elif tag != "replace":
                continue
            recs = [r for r in records if r.applied and i1 + 1 <= r.line <= i2 + (1 if tag == "insert" else 0)] or \
                [r for r in records if r.applied]
            desc = " ".join(dict.fromkeys(RULE_PATCHERS[r.test_id].description for r in recs if r.test_id in RULE_PATCHERS))
            note = " ".join(dict.fromkeys(r.review_note for r in recs if r.tier == "needs_review" and r.review_note))
            out.append(CodeSuggestion(
                file=rel, line=i1 + 1, end_line=i2,
                replacement="".join(b[j1:j2]).rstrip("\r\n").replace("\r\n", "\n"),
                explanation=(desc or "Apply the recommended security fix.") + (f" **Review before accepting:** {note}" if note else "")))
    return out


def generate_suggestions(findings: Iterable[Any], repo_path: Any) -> List[CodeSuggestion]:
    """Verified one-click suggestions for dependency pins and for Bandit/Semgrep/crypto findings with an AST fix.

    One suggestion per pinned line (the lowest version that fixes every CVE on it) and one per changed line range.
    Secrets are never suggested: a suggestion would have to contain the value, and the change needs `import os` and
    a rotation of the secret, which a single line cannot express.
    """
    root = Path(repo_path)
    dicts = [_as_dict(f) for f in findings]
    return _dependency_suggestions(dicts, root) + _code_suggestions(dicts, root)


def _looks_like_source_line(evidence: str) -> bool:
    """True only for one clean line of Python. Bandit's numbered snippets ('28 29 app.run(...)') are rejected."""
    ev = (evidence or "").strip()
    if not ev or "\n" in ev or ev.endswith("..."):
        return False
    try:
        ast.parse(ev)
    except SyntaxError:
        return False
    return True


def generate_code_suggestion(finding: Finding, repo_path: Optional[str] = None) -> Optional[CodeSuggestion]:
    """Generate a high-confidence CodeSuggestion for a finding if an exact fix can be formulated.

    With a repo_path the verified AST patchers are used. Without one, only a clean one-line evidence can be edited.
    """
    if not finding.line or finding.line < 1:
        return None
    if repo_path:
        for s in generate_suggestions([finding], repo_path):
            if s.line <= finding.line <= (s.end_line or s.line):
                return s
    if finding.engine == "bandit" and not _looks_like_source_line(finding.evidence):
        return finding.extra.get("suggested_fix") and CodeSuggestion(
            file=finding.file.replace("\\", "/"), line=finding.line,
            end_line=finding.extra.get("end_line", finding.line), replacement=str(finding.extra["suggested_fix"]),
            explanation=finding.fix_hint or "Apply recommended security remediation.") or None

    # 1. Dependency Engine: Requirements upgrade suggestions
    if finding.engine == "dependency" and finding.file.endswith(("requirements.txt", "requirements.in", ".txt")):
        target_version = _extract_target_version(finding.fix_hint)
        package = finding.extra.get("package")
        if not package and "==" in finding.evidence:
            package = finding.evidence.split("==")[0].strip()

        if package and target_version:
            # Match existing syntax style (>= or ==)
            rel_path = finding.file.replace("\\", "/")
            return CodeSuggestion(
                file=rel_path,
                line=finding.line,
                end_line=finding.line,
                replacement=f"{package}>={target_version}",
                explanation=f"Upgrade `{package}` to `{target_version}` or later to remediate {finding.cwe or 'vulnerability'}.",
            )

    # 2. Bandit AST Patcher suggestions
    if finding.engine == "bandit":
        test_id = finding.extra.get("test_id")
        rel_path = finding.file.replace("\\", "/")

        # B201: Flask app debug=True -> debug=False
        if test_id == "B201" and finding.evidence and "debug=True" in finding.evidence:
            replacement = finding.evidence.replace("debug=True", "debug=False")
            return CodeSuggestion(
                file=rel_path,
                line=finding.line,
                end_line=finding.line,
                replacement=replacement,
                explanation="Disable Flask debug mode in production to prevent arbitrary code execution and console access.",
            )

        # B506: yaml.load -> yaml.safe_load
        if test_id == "B506" and finding.evidence and "yaml.load(" in finding.evidence:
            replacement = finding.evidence.replace("yaml.load(", "yaml.safe_load(")
            return CodeSuggestion(
                file=rel_path,
                line=finding.line,
                end_line=finding.line,
                replacement=replacement,
                explanation="Use `yaml.safe_load()` instead of `yaml.load()` to prevent arbitrary object deserialization.",
            )

        # B501: requests verify=False -> verify=True
        if test_id == "B501" and finding.evidence and "verify=False" in finding.evidence:
            replacement = finding.evidence.replace("verify=False", "verify=True")
            return CodeSuggestion(
                file=rel_path,
                line=finding.line,
                end_line=finding.line,
                replacement=replacement,
                explanation="Enable TLS certificate verification (`verify=True`) to prevent man-in-the-middle attacks.",
            )

        # B113: requests call without timeout
        if test_id == "B113" and finding.evidence:
            ev = finding.evidence.strip()
            # If requests.get(...) or requests.post(...) ends with ')'
            if ev.endswith(")") and "timeout=" not in ev:
                # Add timeout parameter
                replacement = ev[:-1] + ", timeout=10)"
                return CodeSuggestion(
                    file=rel_path,
                    line=finding.line,
                    end_line=finding.line,
                    replacement=replacement,
                    explanation="Add an explicit timeout (`timeout=10`) to prevent unhandled network hangs.",
                )

    # 3. Direct suggested_fix in extra metadata
    if finding.extra.get("suggested_fix"):
        return CodeSuggestion(
            file=finding.file.replace("\\", "/"),
            line=finding.line,
            end_line=finding.extra.get("end_line", finding.line),
            replacement=str(finding.extra["suggested_fix"]),
            explanation=finding.fix_hint or "Apply recommended security remediation.",
        )

    return None
