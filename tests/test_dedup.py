"""Tests for finding deduplication and alert correlation."""
from core.dedup import (
    _are_duplicates,
    _extract_keywords,
    _merge_pair,
    _norm_path,
    deduplicate_findings,
)
from core.finding import Finding


def test_norm_path():
    assert _norm_path("app\\main.py") == "app/main.py"
    assert _norm_path("./src/app.py") == "src/app.py"
    assert _norm_path("/root/test.py") == "root/test.py"


def test_extract_keywords():
    kw = _extract_keywords("Use of unsafe yaml load and eval injection")
    assert "yaml" in kw
    assert "eval" in kw
    assert "sql" not in kw


def test_are_duplicates_same_line_same_cwe():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506: Use of unsafe yaml load",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=5.5,
    )
    f2 = Finding(
        engine="semgrep",
        title="Semgrep unsafe-load: Use of unsafe yaml",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=8.5,
    )
    assert _are_duplicates(f1, f2) is True


def test_are_duplicates_different_file():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=5.5,
    )
    f2 = Finding(
        engine="semgrep",
        title="Semgrep unsafe-load",
        file="other.py",
        line=11,
        cwe="CWE-502",
        severity=8.5,
    )
    assert _are_duplicates(f1, f2) is False


def test_are_duplicates_different_lines():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=5.5,
    )
    f2 = Finding(
        engine="semgrep",
        title="Semgrep unsafe-load",
        file="app.py",
        line=95,
        cwe="CWE-502",
        severity=8.5,
    )
    assert _are_duplicates(f1, f2) is False


def test_are_duplicates_keyword_match():
    f1 = Finding(
        engine="bandit",
        title="Call to requests without timeout",
        file="client.py",
        line=20,
        cwe="CWE-400",
        severity=4.5,
    )
    f2 = Finding(
        engine="custom",
        title="HTTP request has no timeout set",
        file="client.py",
        line=20,
        cwe=None,
        severity=5.0,
    )
    assert _are_duplicates(f1, f2) is True


def test_deduplicate_findings_merges_and_boosts():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506: Use of unsafe yaml load",
        file="app.py",
        line=11,
        cwe="CWE-20",
        severity=5.5,
        exploitability=0.4,
        description="Short desc",
        fix_hint="Use safe_load",
    )
    f2 = Finding(
        engine="semgrep",
        title="Semgrep unsafe-load: Use of unsafe yaml",
        file="app.py",
        line=11,
        cwe="CWE-502",
        severity=8.5,
        exploitability=0.75,
        description="Longer description with remediation details",
        fix_hint="Replace yaml.load with yaml.safe_load",
    )
    f3 = Finding(
        engine="bandit",
        title="Bandit B113: Call to requests without timeout",
        file="app.py",
        line=16,
        cwe="CWE-400",
        severity=4.5,
        exploitability=0.2,
    )

    merged = deduplicate_findings([f1, f2, f3])
    assert len(merged) == 2

    top = merged[0]
    assert top.line == 11
    # Severity should be max(5.5, 8.5) + 0.3 corroboration bonus = 8.8
    assert top.severity == 8.8
    assert top.exploitability == 0.75
    assert top.cwe == "CWE-502"
    assert top.extra["corroborated"] is True
    assert set(top.extra["corroborating_engines"]) == {"bandit", "semgrep"}
    assert top.extra["sources_count"] == 2

    # Second finding is untouched
    second = merged[1]
    assert second.line == 16
    assert second.extra["corroborated"] is False
    assert second.severity == 4.5
