"""Inline comment and baseline suppression handler.

Supports scoped inline comments (# nosec, # nosec B506, # nosemgrep, # scip:ignore, # gitleaks:allow)
as well as repository-level baseline suppression files (.scip-baseline.json).

Marker Scoping:
- # nosec, # noqa: Bandit only
- # nosemgrep: Semgrep only
- # gitleaks:allow, # pragma: allowlist secret: Secrets only
- # scip:ignore: Any engine (dependency findings require targeted vuln_id/alias)
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from core.finding import Finding
from core.taxonomy import normalize_cwe

log = logging.getLogger("scip.suppression")


def _clean_evidence_for_fingerprint(f: Finding) -> str:
    """Clean and isolate the flagged line(s) from finding evidence.

    Only strips Bandit-style line prefixes ('23 data = ...') for Bandit findings.
    Leaves other engine snippets (e.g. Semgrep '100 )') unaltered.
    """
    ev = f.evidence or ""
    if f.engine == "bandit":
        flagged_lines = set(f.extra.get("line_range") or ([f.line] if f.line else []))
        cleaned_lines = []
        has_numbered_lines = False

        for raw_l in ev.splitlines():
            m = re.match(r"^\s*(\d+)\s+(.*)$", raw_l)
            if m:
                has_numbered_lines = True
                line_no = int(m.group(1))
                line_content = m.group(2).strip()
                if flagged_lines:
                    if line_no in flagged_lines:
                        cleaned_lines.append(line_content)
                else:
                    cleaned_lines.append(line_content)
            else:
                cleaned_lines.append(raw_l.strip())

        if has_numbered_lines and cleaned_lines:
            text = "\n".join(cleaned_lines)
        else:
            lines = [re.sub(r"^\s*\d+\s+", "", l).strip() for l in ev.splitlines()]
            text = "\n".join(lines)
    else:
        text = ev

    return "".join(text.split())[:200]


def compute_finding_fingerprint(f: Finding, occurrence: int = 0) -> str:
    """Compute a stable, deterministic hash fingerprint for a finding.

    Uses normalized file path, normalized rule/CWE ID, normalized code evidence,
    and an occurrence index to differentiate duplicate lines in the same file.

    Note:
        norm_file is lowercased for cross-platform baseline stability between Windows and macOS.
    """
    norm_file = f.file.replace("\\", "/").strip().lower()

    if f.engine == "dependency" or f.extra.get("vuln_id"):
        rule_id = str(f.extra.get("vuln_id") or f.title).strip().lower()
    elif f.engine == "secrets" and f.extra.get("fingerprint"):
        rule_id = str(f.extra["fingerprint"]).strip().lower()
    else:
        rule_id = str(f.extra.get("test_id") or f.extra.get("check_id") or f.cwe or f.title).strip().lower()

    norm_evidence = _clean_evidence_for_fingerprint(f)
    payload = f"{norm_file}:{rule_id}:{norm_evidence}:{occurrence}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def load_baseline(baseline_path: Path | str) -> Tuple[Set[str], int]:
    """Load baseline suppression fingerprints and format version from a JSON file.

    Returns:
        (fingerprints_set, version_int)

    Raises:
        FileNotFoundError: If baseline_path does not exist.
    """
    path = Path(baseline_path)
    if not path.exists():
        raise FileNotFoundError(f"Baseline file does not exist: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            log.info("Loaded legacy v1 baseline from %s", path)
            fps = set()
            for item in data:
                if isinstance(item, str):
                    fps.add(item)
                elif isinstance(item, dict) and "fingerprint" in item:
                    fps.add(item["fingerprint"])
            return fps, 1
        if isinstance(data, dict):
            version = int(data.get("version", 2))
            fps = set(data.get("fingerprints", []))
            for item in data.get("findings", []):
                if isinstance(item, dict) and "fingerprint" in item:
                    fps.add(item["fingerprint"])
            return fps, version
    except (OSError, ValueError) as e:
        log.warning("Could not read baseline file %s: %s", path, e)
    return set(), 2


def save_baseline(findings: List[Finding], baseline_path: Path | str) -> int:
    """Save current findings into a version 2 baseline suppression file."""
    path = Path(baseline_path)
    entries = []
    counts: Dict[Tuple[str, str, str], int] = defaultdict(int)

    for f in findings:
        norm_file = f.file.replace("\\", "/").strip().lower()
        if f.engine == "dependency" or f.extra.get("vuln_id"):
            rule_id = str(f.extra.get("vuln_id") or f.title).strip().lower()
        elif f.engine == "secrets" and f.extra.get("fingerprint"):
            rule_id = str(f.extra["fingerprint"]).strip().lower()
        else:
            rule_id = str(f.extra.get("test_id") or f.extra.get("check_id") or f.cwe or f.title).strip().lower()
        norm_evidence = _clean_evidence_for_fingerprint(f)

        key = (norm_file, rule_id, norm_evidence)
        occurrence = counts[key]
        counts[key] += 1

        fp = compute_finding_fingerprint(f, occurrence=occurrence)
        entries.append({
            "fingerprint": fp,
            "occurrence": occurrence,
            "file": f.file,
            "line": f.line,
            "rule": rule_id,
            "cwe": f.cwe,
            "title": f.title,
            "engine": f.engine,
            "severity": f.severity,
        })

    data = {
        "version": 2,
        "fingerprints": [e["fingerprint"] for e in entries],
        "findings": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(entries)


def _get_finding_tokens(f: Finding) -> Set[str]:
    """Collect all normalized rule identifiers representing a finding for targeted suppression.

    Note: Engine names (e.g. 'SECRETS', 'BANDIT') are explicitly excluded to prevent
    conversational text like '# scip:ignore: secrets rotated' from matching engine names.
    """
    tokens = set()
    if f.cwe:
        norm = normalize_cwe(f.cwe)
        if norm:
            tokens.add(norm.upper())
        tokens.add(f.cwe.strip().upper())
    if f.extra.get("test_id"):
        tokens.add(str(f.extra["test_id"]).strip().upper())
    if f.extra.get("check_id"):
        cid = str(f.extra["check_id"]).strip()
        tokens.add(cid.upper())
        tokens.add(cid.split(".")[-1].upper())
    if f.extra.get("vuln_id"):
        tokens.add(str(f.extra["vuln_id"]).strip().upper())
    for alias in f.extra.get("aliases", []):
        tokens.add(str(alias).strip().upper())
    if f.extra.get("rule"):
        tokens.add(str(f.extra["rule"]).strip().upper())
    if f.extra.get("secret_type"):
        tokens.add(str(f.extra["secret_type"]).strip().upper())
    for r in f.extra.get("all_rules", []):
        tokens.add(str(r).strip().upper())
        tokens.add(str(r).strip().split(".")[-1].upper())
    for src in f.extra.get("sources", []):
        if isinstance(src, dict):
            if src.get("rule"):
                sr = str(src["rule"]).strip()
                tokens.add(sr.upper())
                tokens.add(sr.split(".")[-1].upper())
            if src.get("cwe"):
                sc = normalize_cwe(src["cwe"])
                if sc:
                    tokens.add(sc.upper())
    return tokens


def _is_valid_rule_id(tok: str) -> bool:
    """Validate whether a token is a legitimate rule or vulnerability ID shape.

    Disqualifies filenames (e.g. 'utils.py') and version numbers (e.g. 'v1.2').
    Requires canonical prefixes (CWE-, B###, CVE-, GHSA-), known namespaces
    (scip., bandit., semgrep., rules.), or multi-segment dotted rule paths (>= 3 segments).
    """
    tok_low = tok.lower()
    # Reject common source file extensions
    if any(tok_low.endswith(ext) for ext in (".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml", ".go", ".rb", ".md", ".txt", ".sh")):
        return False
    # Reject version strings (e.g. v1.2, 1.0.0)
    if re.match(r"^v?\d+(?:\.\d+)+$", tok_low):
        return False
    # Accept standard vulnerability IDs
    if re.match(r"^(?:CWE-\d+|B\d{3}|CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)$", tok, re.IGNORECASE):
        return True
    # Accept known rule namespaces or hierarchical dotted rule identifiers with at least 3 segments
    if any(tok_low.startswith(p) for p in ("scip.", "bandit.", "semgrep.", "rules.")):
        return True
    if tok.count(".") >= 2 and re.match(r"^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+){2,}$", tok):
        return True
    return False


def _parse_suppression_comment(comment_text: str) -> List[Tuple[str, Set[str], List[str]]]:
    """Parse inline comment text for suppression directives with strictly ID-shaped tokens."""
    directives = []

    # 1. Bandit: # nosec [optional IDs]
    m_nosec = re.search(r"#\s*nosec(?::|\b)(.*)$", comment_text, re.IGNORECASE)
    if m_nosec:
        rest = m_nosec.group(1)
        ids = [t.upper() for t in re.findall(r"\b(B\d{3}|CWE-\d+)\b", rest, re.IGNORECASE)]
        directives.append(("nosec", {"bandit"}, ids))

    # Targeted noqa: # noqa: B506 (bare # noqa is ignored)
    m_noqa = re.search(r"#\s*noqa:\s*(.*)$", comment_text, re.IGNORECASE)
    if m_noqa:
        rest = m_noqa.group(1)
        ids = [t.upper() for t in re.findall(r"\b(B\d{3}|CWE-\d+)\b", rest, re.IGNORECASE)]
        if ids:
            directives.append(("noqa", {"bandit"}, ids))

    # 2. Semgrep: # nosemgrep [optional dotted rule IDs or CWEs]
    # Hyphenated words without dots (e.g. 'false-positive') and filenames (e.g. 'utils.py') are not rule IDs
    m_nosemgrep = re.search(r"#\s*nosemgrep(?::|\b)(.*)$", comment_text, re.IGNORECASE)
    if m_nosemgrep:
        rest = m_nosemgrep.group(1)
        raw_tokens = re.findall(r"\b(CWE-\d+|[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\b", rest, re.IGNORECASE)
        ids = [t.upper() for t in raw_tokens if _is_valid_rule_id(t)]
        directives.append(("nosemgrep", {"semgrep"}, ids))

    # 3. Secrets:
    if re.search(r"#\s*(?:gitleaks:allow|pragma:\s*allowlist\s*secret|pragma:\s*no-audit)\b", comment_text, re.IGNORECASE):
        directives.append(("secrets", {"secrets"}, []))

    # 4. Universal: # scip:ignore [optional ID-shaped tokens]
    m_scip = re.search(r"#\s*scip:ignore(?::|\b)(.*)$", comment_text, re.IGNORECASE)
    if m_scip:
        rest = m_scip.group(1)
        raw_tokens = re.findall(
            r"\b(CVE-\d{4}-\d+|GHSA-[a-z0-9-]+|CWE-\d+|B\d{3}|[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\b",
            rest,
            re.IGNORECASE,
        )
        ids = [t.upper() for t in raw_tokens if _is_valid_rule_id(t)]
        directives.append(("scip:ignore", {"bandit", "semgrep", "secrets", "dependency", "crypto", "churn", "dummy"}, ids))

    return directives


def _check_inline_suppression(lines: List[str], line_nums: List[int], f: Finding) -> Optional[str]:
    """Check if any line in line_nums (or an immediately preceding comment line) contains a valid suppression directive."""
    finding_tokens = _get_finding_tokens(f)
    finding_engines = set(f.extra.get("corroborating_engines") or [f.engine])

    for l_num in line_nums:
        if not (1 <= l_num <= len(lines)):
            continue

        line_idx = l_num - 1
        candidates = [line_idx]

        # Only check previous line if it is a pure comment line (e.g. comment directly above statement)
        if line_idx - 1 >= 0 and lines[line_idx - 1].strip().startswith("#"):
            candidates.append(line_idx - 1)

        for idx in candidates:
            text = lines[idx]
            directives = _parse_suppression_comment(text)
            for marker, target_engines, targeted_ids in directives:
                # 1. Marker must target at least one of this finding's engine(s)
                if not bool(finding_engines & target_engines):
                    continue

                # 2. For multi-engine clusters: single engine marker must NOT suppress the entire cluster
                if len(finding_engines) > 1 and not finding_engines.issubset(target_engines):
                    continue

                # 3. For dependency findings, ONLY accept targeted IDs (vuln_id or aliases)
                if f.engine == "dependency" or f.extra.get("vuln_id"):
                    if not targeted_ids:
                        continue
                    dep_ids = {str(f.extra.get("vuln_id", "")).upper()}
                    for a in f.extra.get("aliases", []):
                        dep_ids.add(str(a).upper())
                    if any(tid in dep_ids for tid in targeted_ids):
                        return f"Inline targeted suppression for dependency ({', '.join(targeted_ids)}) at line {idx + 1}"
                    continue

                # 4. For code findings:
                if not targeted_ids:
                    # Bare marker (e.g. # nosec for Bandit, # nosemgrep for Semgrep)
                    return f"Inline suppression ({marker}) at line {idx + 1}"

                # Targeted marker: match against finding tokens
                matched = [tid for tid in targeted_ids if tid in finding_tokens]
                if matched:
                    return f"Inline targeted suppression for '{matched[0]}' at line {idx + 1}"

    return None


def filter_suppressions(
    findings: List[Finding],
    repo_path: str,
    baseline_path: Optional[str | Path] = None,
    include_suppressed: bool = False,
) -> Tuple[List[Finding], List[Finding]]:
    """Partition findings into active and suppressed findings based on scoped inline comments and baseline.

    Args:
        findings: List of input findings.
        repo_path: Root path of the scanned repository.
        baseline_path: Path to baseline JSON file, if any.
        include_suppressed: If True, suppressed findings are kept in active list with metadata.

    Returns:
        (active_findings, suppressed_findings)
    """
    root = Path(repo_path).resolve()
    if baseline_path:
        baseline_fps, baseline_version = load_baseline(Path(baseline_path).resolve())
    else:
        baseline_fps, baseline_version = set(), 2

    file_cache: Dict[str, Optional[List[str]]] = {}

    def get_file_lines(rel_file: str) -> Optional[List[str]]:
        if rel_file not in file_cache:
            p = root / rel_file
            if not p.exists() or not p.is_file():
                file_cache[rel_file] = None
            else:
                try:
                    raw = p.read_text(encoding="utf-8-sig", errors="replace")
                    file_cache[rel_file] = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
                except OSError:
                    file_cache[rel_file] = None
        return file_cache[rel_file]

    active: List[Finding] = []
    suppressed: List[Finding] = []
    counts: Dict[Tuple[str, str, str], int] = defaultdict(int)

    for f in findings:
        suppression_reason: Optional[str] = None

        # 1. Check baseline file
        norm_file = f.file.replace("\\", "/").strip().lower()
        if f.engine == "dependency" or f.extra.get("vuln_id"):
            rule_id = str(f.extra.get("vuln_id") or f.title).strip().lower()
        elif f.engine == "secrets" and f.extra.get("fingerprint"):
            rule_id = str(f.extra["fingerprint"]).strip().lower()
        else:
            rule_id = str(f.extra.get("test_id") or f.extra.get("check_id") or f.cwe or f.title).strip().lower()
        norm_evidence = _clean_evidence_for_fingerprint(f)

        key = (norm_file, rule_id, norm_evidence)
        occurrence = counts[key]
        counts[key] += 1

        fp = compute_finding_fingerprint(f, occurrence=occurrence)
        matched_baseline = fp in baseline_fps
        # Only fall back to occurrence 0 if loaded baseline was legacy v1 format
        if not matched_baseline and baseline_version == 1:
            matched_baseline = compute_finding_fingerprint(f, occurrence=0) in baseline_fps

        if matched_baseline:
            suppression_reason = f"Suppressed by baseline ({fp})"

        # 2. Check inline source code suppression (only for findings in current working tree)
        if not suppression_reason and f.line and f.extra.get("in_working_tree", True) is not False:
            lines = get_file_lines(f.file)
            if lines:
                line_range = f.extra.get("line_range") or [f.line]
                suppression_reason = _check_inline_suppression(lines, line_range, f)

        # Deep copy via clone() to avoid mutating caller's objects
        f_copy = f.clone()

        if suppression_reason:
            f_copy.extra["suppressed"] = True
            f_copy.extra["suppression_reason"] = suppression_reason
            suppressed.append(f_copy)
            if include_suppressed:
                active.append(f_copy)
        else:
            f_copy.extra["suppressed"] = False
            active.append(f_copy)

    return active, suppressed
