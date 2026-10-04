"""Cross-tool finding deduplication and alert correlation.

Identifies findings from multiple engines (e.g. Bandit, Semgrep, DependencyEngine)
that point to the same code location and vulnerability class, merging them into
a single high-fidelity, corroborated finding.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from core.finding import Finding
from core.taxonomy import is_compatible_cwe, normalize_cwe

log = logging.getLogger("scip.dedup")


def _norm_path(path: str) -> str:
    """Normalize file path to POSIX relative form without leading dots or slashes."""
    p = path.replace("\\", "/").strip()
    while p.startswith("./") or p.startswith("/"):
        p = p[2:] if p.startswith("./") else p[1:]
    return p.lower()


def _extract_keywords(text: str) -> Set[str]:
    """Extract lower-case security keywords for similarity heuristics."""
    kw = {"yaml", "pickle", "md5", "sha1", "des", "rc4", "ssl", "tls", "sql",
          "exec", "eval", "shell", "subprocess", "ssrf", "xss", "csrf", "timeout",
          "mktemp", "cryptography", "jwt", "password", "secret", "token"}
    low = text.lower()
    return {k for k in kw if k in low}


def _are_duplicates(f1: Finding, f2: Finding) -> bool:
    """Determine whether two findings refer to the same root vulnerability."""
    # Must refer to the same file
    if _norm_path(f1.file) != _norm_path(f2.file):
        return False

    # Check line proximity
    l1, l2 = f1.line, f2.line
    if l1 is not None and l2 is not None:
        # Check line ranges if available in extra
        r1 = set(f1.extra.get("line_range", [l1]))
        r2 = set(f2.extra.get("line_range", [l2]))
        lines_overlap = bool(r1 & r2) or abs(l1 - l2) <= 1
        if not lines_overlap:
            return False
    elif l1 != l2:
        # One is file-level (None) and one is line-level: do not blindly merge
        return False

    # Check CWE compatibility
    if is_compatible_cwe(f1.cwe, f2.cwe):
        return True

    # Check keyword overlap in title/description
    kw1 = _extract_keywords(f"{f1.title} {f1.description}")
    kw2 = _extract_keywords(f"{f2.title} {f2.description}")
    if kw1 and kw2 and bool(kw1 & kw2):
        return True

    return False


def _merge_pair(base: Finding, incoming: Finding) -> Finding:
    """Merge incoming finding into base finding, elevating confidence and details."""
    # Determine canonical engine and corroborators
    engines = list(base.extra.get("corroborating_engines", [base.engine]))
    if incoming.engine not in engines:
        engines.append(incoming.engine)

    # Highest severity & exploitability
    max_sev = max(base.severity, incoming.severity)
    max_exploit = max(base.exploitability, incoming.exploitability)

    # Corroboration bonus: +0.3 severity boost if corroborated by distinct engines (max 10.0)
    if len(engines) > 1 and not base.extra.get("corroborated"):
        max_sev = min(10.0, round(max_sev + 0.3, 1))

    # Pick the most specific CWE (prefer specific over generic CWE-20)
    canonical_cwe = base.cwe
    if incoming.cwe and (not base.cwe or base.cwe == "CWE-20"):
        canonical_cwe = incoming.cwe

    # Pick best description and fix hint
    desc = base.description if len(base.description) >= len(incoming.description) else incoming.description
    fix = base.fix_hint if len(base.fix_hint) >= len(incoming.fix_hint) else incoming.fix_hint
    evidence = base.evidence or incoming.evidence

    # Preferred title
    title = base.title
    if "unknown" in title.lower() and incoming.title:
        title = incoming.title

    sources = list(base.extra.get("sources", [base.to_dict()]))
    sources.append(incoming.to_dict())

    merged_extra = dict(base.extra)
    merged_extra.update({
        "corroborating_engines": sorted(engines),
        "corroborated": len(engines) > 1,
        "sources_count": len(sources),
        "sources": sources,
    })

    return Finding(
        engine=base.engine if base.severity >= incoming.severity else incoming.engine,
        title=title,
        file=base.file,
        line=base.line or incoming.line,
        cwe=normalize_cwe(canonical_cwe),
        severity=max_sev,
        description=desc,
        evidence=evidence,
        fix_hint=fix,
        exploitability=max_exploit,
        reachable=base.reachable if base.reachable is not None else incoming.reachable,
        blast_radius=max(base.blast_radius, incoming.blast_radius),
        churn=max(base.churn, incoming.churn),
        code_health_penalty=max(base.code_health_penalty, incoming.code_health_penalty),
        risk_score=max(base.risk_score, incoming.risk_score),
        explanation=base.explanation or incoming.explanation,
        extra=merged_extra,
    )


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate and correlate findings across multiple scanning engines.

    Merges findings that point to the same code location and vulnerability class,
    recording corroborating engines in `finding.extra['corroborating_engines']`.
    """
    if not findings:
        return []

    # Group findings by normalized file path for fast localized comparisons
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_file[_norm_path(f.file)].append(f)

    deduped: List[Finding] = []

    for file_path, file_findings in by_file.items():
        clusters: List[Finding] = []

        for candidate in file_findings:
            matched = False
            for i, cluster in enumerate(clusters):
                if _are_duplicates(cluster, candidate):
                    clusters[i] = _merge_pair(cluster, candidate)
                    matched = True
                    break
            if not matched:
                # Initialize source metadata on standalone finding
                candidate.extra.setdefault("corroborating_engines", [candidate.engine])
                candidate.extra.setdefault("corroborated", False)
                clusters.append(candidate)

        deduped.extend(clusters)

    # Sort in standard SCIP presentation order
    deduped.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.line or 0))
    return deduped
