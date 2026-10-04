"""Inline and baseline false-positive suppression handler.

Supports inline comments (# nosec, # nosemgrep, # scip:ignore, # gitleaks:allow)
as well as repository-level baseline suppression files (.scip-baseline.json).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from core.finding import Finding

log = logging.getLogger("scip.suppression")

# Generic and specific suppression comment regexes
INLINE_SUPPRESSION_RE = re.compile(
    r"#\s*(?:"
    r"nosec(?::\s*([A-Za-z0-9_-]+))?|"
    r"nosemgrep(?::\s*([A-Za-z0-9._-]+))?|"
    r"scip:ignore(?::\s*([A-Za-z0-9._-]+))?|"
    r"gitleaks:allow|"
    r"pragma:\s*allowlist\s*secret|"
    r"pragma:\s*no-audit|"
    r"noqa(?::\s*([A-Za-z0-9_-]+))?"
    r")",
    re.IGNORECASE,
)


def compute_finding_fingerprint(f: Finding) -> str:
    """Compute a deterministic hash fingerprint for a finding."""
    norm_file = f.file.replace("\\", "/").lower()
    line_str = str(f.line or 0)
    cwe_str = str(f.cwe or "")
    payload = f"{norm_file}:{line_str}:{cwe_str}:{f.title}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def load_baseline(baseline_path: Path | str) -> Set[str]:
    """Load baseline suppression fingerprints from a JSON file."""
    path = Path(baseline_path)
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {item.get("fingerprint") for item in data if isinstance(item, dict) and "fingerprint" in item}
        if isinstance(data, dict):
            return set(data.get("fingerprints", []))
    except (OSError, ValueError) as e:
        log.warning("Could not read baseline file %s: %s", path, e)
    return set()


def save_baseline(findings: List[Finding], baseline_path: Path | str) -> int:
    """Save current findings into a baseline suppression file."""
    path = Path(baseline_path)
    entries = []
    for f in findings:
        entries.append({
            "fingerprint": compute_finding_fingerprint(f),
            "file": f.file,
            "line": f.line,
            "cwe": f.cwe,
            "title": f.title,
            "engine": f.engine,
            "severity": f.severity,
        })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    return len(entries)


def _check_inline_suppression(lines: List[str], line_num: int, f: Finding) -> Optional[str]:
    """Check if the source file contains a suppression marker on or near the finding line."""
    if not (1 <= line_num <= len(lines)):
        return None

    # Check the exact line and immediately preceding/succeeding lines
    candidates = [line_num - 1]
    if line_num - 2 >= 0:
        candidates.append(line_num - 2)

    finding_tokens = {
        (f.cwe or "").lower(),
        f.engine.lower(),
        str(f.extra.get("test_id", "")).lower(),
        str(f.extra.get("check_id", "")).lower(),
    }
    finding_tokens.discard("")

    for idx in candidates:
        text = lines[idx]
        m = INLINE_SUPPRESSION_RE.search(text)
        if not m:
            continue

        # Check if an identifier was specified in the suppression tag (e.g. # nosec: B506)
        matched_groups = [g for g in m.groups() if g]
        if not matched_groups:
            # Universal inline suppression
            return f"Inline suppression ({m.group(0).strip()}) at line {idx + 1}"

        specific_id = matched_groups[0].lower()
        if any(specific_id in token or token in specific_id for token in finding_tokens):
            return f"Inline targeted suppression for '{specific_id}' at line {idx + 1}"

    return None


def filter_suppressions(
    findings: List[Finding],
    repo_path: str,
    baseline_path: Optional[str] = None,
    include_suppressed: bool = False,
) -> Tuple[List[Finding], List[Finding]]:
    """Partition findings into active and suppressed findings based on inline comments and baseline.

    Args:
        findings: List of input findings.
        repo_path: Root path of the scanned repository.
        baseline_path: Path to baseline JSON file, if any.
        include_suppressed: If True, suppressed findings are kept in active list with metadata.

    Returns:
        (active_findings, suppressed_findings)
    """
    root = Path(repo_path).resolve()
    baseline_fps = load_baseline(Path(baseline_path).resolve()) if baseline_path else set()

    # Cache file contents to avoid re-reading the same file repeatedly
    file_cache: Dict[str, Optional[List[str]]] = {}

    def get_file_lines(rel_file: str) -> Optional[List[str]]:
        if rel_file not in file_cache:
            p = root / rel_file
            if not p.exists() or not p.is_file():
                file_cache[rel_file] = None
            else:
                try:
                    file_cache[rel_file] = p.read_text(encoding="utf-8-sig", errors="replace").splitlines()
                except OSError:
                    file_cache[rel_file] = None
        return file_cache[rel_file]

    active: List[Finding] = []
    suppressed: List[Finding] = []

    for f in findings:
        suppression_reason: Optional[str] = None

        # 1. Check baseline file
        fp = compute_finding_fingerprint(f)
        if fp in baseline_fps:
            suppression_reason = f"Suppressed by baseline ({fp})"

        # 2. Check inline source code suppression
        if not suppression_reason and f.line:
            lines = get_file_lines(f.file)
            if lines:
                suppression_reason = _check_inline_suppression(lines, f.line, f)

        if suppression_reason:
            f.extra["suppressed"] = True
            f.extra["suppression_reason"] = suppression_reason
            suppressed.append(f)
            if include_suppressed:
                active.append(f)
        else:
            f.extra["suppressed"] = False
            active.append(f)

    return active, suppressed
