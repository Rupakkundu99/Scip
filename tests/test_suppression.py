"""Tests for inline comment suppression and baseline file handling."""
from pathlib import Path
import pytest

from core.finding import Finding
from core.suppression import (
    _get_finding_tokens,
    compute_finding_fingerprint,
    filter_suppressions,
    load_baseline,
    save_baseline,
)


def test_compute_finding_fingerprint():
    f1 = Finding(engine="bandit", title="SQL Injection", file="models/user.py", line=10, cwe="CWE-89")
    f2 = Finding(engine="bandit", title="SQL Injection", file="models\\user.py", line=10, cwe="CWE-89")
    # Windows path and posix path must yield identical deterministic fingerprint
    assert compute_finding_fingerprint(f1) == compute_finding_fingerprint(f2)


def test_inline_universal_suppression(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "import yaml\n"
        "def load(data):\n"
        "    return yaml.load(data)  # nosec\n",
        encoding="utf-8",
    )
    f = Finding(
        engine="bandit",
        title="Bandit B506: Use of unsafe yaml load",
        file="app.py",
        line=3,
        cwe="CWE-502",
        extra={"test_id": "B506"},
    )

    active, suppressed = filter_suppressions([f], repo_path=str(tmp_path))
    assert len(active) == 0
    assert len(suppressed) == 1
    assert "Inline suppression" in suppressed[0].extra["suppression_reason"]


def test_inline_targeted_suppression(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "import yaml\n"
        "def load(data):\n"
        "    return yaml.load(data)  # nosec: B506\n",
        encoding="utf-8",
    )
    # Finding for B506 is suppressed
    f_match = Finding(
        engine="bandit",
        title="Bandit B506: Use of unsafe yaml load",
        file="app.py",
        line=3,
        cwe="CWE-502",
        extra={"test_id": "B506"},
    )
    active, suppressed = filter_suppressions([f_match], repo_path=str(tmp_path))
    assert len(active) == 0
    assert len(suppressed) == 1

    # Finding for different rule (e.g. B101) on same line is NOT suppressed
    f_other = Finding(
        engine="bandit",
        title="Bandit B101: assert used",
        file="app.py",
        line=3,
        cwe="CWE-703",
        extra={"test_id": "B101"},
    )
    active2, suppressed2 = filter_suppressions([f_other], repo_path=str(tmp_path))
    assert len(active2) == 1
    assert len(suppressed2) == 0


def test_inline_scip_ignore_cwe(tmp_path):
    src = tmp_path / "crypto.py"
    src.write_text(
        "import hashlib\n"
        "# scip:ignore: CWE-327\n"
        "h = hashlib.md5(b'data').hexdigest()\n",
        encoding="utf-8",
    )
    f = Finding(
        engine="semgrep",
        title="Semgrep weak-hash",
        file="crypto.py",
        line=3,
        cwe="CWE-327",
    )
    active, suppressed = filter_suppressions([f], repo_path=str(tmp_path))
    assert len(active) == 0
    assert len(suppressed) == 1


def test_baseline_save_and_filter(tmp_path):
    baseline_file = tmp_path / ".scip-baseline.json"
    f1 = Finding(engine="bandit", title="Known Legacy Issue", file="legacy.py", line=42, cwe="CWE-89")
    f2 = Finding(engine="bandit", title="New Issue", file="new_code.py", line=10, cwe="CWE-78")

    # Save baseline containing f1 only
    count = save_baseline([f1], baseline_file)
    assert count == 1
    assert baseline_file.exists()

    fps, version = load_baseline(baseline_file)
    assert len(fps) == 1
    assert version == 2

    active, suppressed = filter_suppressions([f1, f2], repo_path=str(tmp_path), baseline_path=str(baseline_file))
    assert len(active) == 1
    assert active[0].title == "New Issue"
    assert len(suppressed) == 1
    assert suppressed[0].title == "Known Legacy Issue"
    assert "baseline" in suppressed[0].extra["suppression_reason"]


def test_include_suppressed_flag(tmp_path):
    src = tmp_path / "main.py"
    src.write_text("eval(cmd)  # nosec\n", encoding="utf-8")
    f = Finding(engine="bandit", title="Eval", file="main.py", line=1, cwe="CWE-95")

    active, suppressed = filter_suppressions(
        [f],
        repo_path=str(tmp_path),
        include_suppressed=True,
    )
    assert len(active) == 1
    assert active[0].extra["suppressed"] is True
    assert len(suppressed) == 1


def test_marker_engine_scoping_nosec_does_not_suppress_secrets(tmp_path):
    src = tmp_path / "settings.py"
    src.write_text('API_KEY = "sk_live_1234567890abcdef" # nosec B105\n', encoding="utf-8")

    f_secret = Finding(
        engine="secrets",
        title="Secret detected",
        file="settings.py",
        line=1,
        cwe="CWE-798",
        extra={"rule": "stripe-api-key"},
    )
    f_bandit = Finding(
        engine="bandit",
        title="Bandit B105: hardcoded password",
        file="settings.py",
        line=1,
        cwe="CWE-259",
        extra={"test_id": "B105"},
    )

    # Bandit finding must be suppressed; Secrets finding must NOT be suppressed
    active, suppressed = filter_suppressions([f_secret, f_bandit], repo_path=str(tmp_path))
    assert len(active) == 1
    assert active[0].engine == "secrets"
    assert len(suppressed) == 1
    assert suppressed[0].engine == "bandit"


def test_dependency_suppression_rules(tmp_path):
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        "django==4.2 # nosec\n"
        "requests==2.25.0 # scip:ignore\n"
        "flask==1.0 # scip:ignore: CVE-2024-53908\n",
        encoding="utf-8",
    )

    # 1. Bare # nosec cannot suppress dependency CVEs
    f1 = Finding(engine="dependency", title="CVE-2023-1111", file="requirements.txt", line=1, extra={"vuln_id": "CVE-2023-1111"})
    active1, suppressed1 = filter_suppressions([f1], repo_path=str(tmp_path))
    assert len(active1) == 1
    assert len(suppressed1) == 0

    # 2. Bare # scip:ignore cannot suppress dependency CVEs
    f2 = Finding(engine="dependency", title="CVE-2023-2222", file="requirements.txt", line=2, extra={"vuln_id": "CVE-2023-2222"})
    active2, suppressed2 = filter_suppressions([f2], repo_path=str(tmp_path))
    assert len(active2) == 1
    assert len(suppressed2) == 0

    # 3. Targeted # scip:ignore: CVE-2024-53908 DOES suppress matching CVE
    f3 = Finding(engine="dependency", title="CVE-2024-53908", file="requirements.txt", line=3, extra={"vuln_id": "CVE-2024-53908"})
    active3, suppressed3 = filter_suppressions([f3], repo_path=str(tmp_path))
    assert len(active3) == 0
    assert len(suppressed3) == 1


def test_nosec_conversational_and_multiple_ids(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "def f1():\n"
        "    yaml.load(d) # nosec - reviewed\n"
        "def f2():\n"
        "    yaml.load(d) # nosec reviewed\n"
        "def f3():\n"
        "    yaml.load(d) # nosec B101,B506\n",
        encoding="utf-8",
    )

    # # nosec - reviewed suppresses B506
    f1 = Finding(engine="bandit", title="Bandit B506", file="app.py", line=2, extra={"test_id": "B506"})
    active1, suppressed1 = filter_suppressions([f1], repo_path=str(tmp_path))
    assert len(suppressed1) == 1

    # # nosec reviewed suppresses B506
    f2 = Finding(engine="bandit", title="Bandit B506", file="app.py", line=4, extra={"test_id": "B506"})
    active2, suppressed2 = filter_suppressions([f2], repo_path=str(tmp_path))
    assert len(suppressed2) == 1

    # # nosec B101,B506 suppresses B506
    f3 = Finding(engine="bandit", title="Bandit B506", file="app.py", line=6, extra={"test_id": "B506"})
    active3, suppressed3 = filter_suppressions([f3], repo_path=str(tmp_path))
    assert len(suppressed3) == 1

    # # nosec B101,B506 does NOT suppress B307
    f4 = Finding(engine="bandit", title="Bandit B307", file="app.py", line=6, extra={"test_id": "B307"})
    active4, suppressed4 = filter_suppressions([f4], repo_path=str(tmp_path))
    assert len(active4) == 1
    assert len(suppressed4) == 0


def test_noqa_bare_dropped_targeted_honored(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "eval(cmd) # noqa\n"
        "yaml.load(d) # noqa: B506\n",
        encoding="utf-8",
    )

    # Bare # noqa does not suppress security findings
    f1 = Finding(engine="bandit", title="Bandit B307", file="app.py", line=1, extra={"test_id": "B307"})
    active1, suppressed1 = filter_suppressions([f1], repo_path=str(tmp_path))
    assert len(active1) == 1
    assert len(suppressed1) == 0

    # Targeted # noqa: B506 suppresses B506
    f2 = Finding(engine="bandit", title="Bandit B506", file="app.py", line=2, extra={"test_id": "B506"})
    active2, suppressed2 = filter_suppressions([f2], repo_path=str(tmp_path))
    assert len(active2) == 0
    assert len(suppressed2) == 1


def test_previous_line_comment_only(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "# nosec B506\n"
        "yaml.load(d)\n"
        "x = foo() # nosec\n"
        "eval(cmd)\n",
        encoding="utf-8",
    )

    # Pure comment on line 1 suppresses line 2
    f1 = Finding(engine="bandit", title="Bandit B506", file="app.py", line=2, extra={"test_id": "B506"})
    active1, suppressed1 = filter_suppressions([f1], repo_path=str(tmp_path))
    assert len(suppressed1) == 1

    # Line 3 is code with trailing # nosec; it must NOT suppress line 4
    f2 = Finding(engine="bandit", title="Bandit B307", file="app.py", line=4, extra={"test_id": "B307"})
    active2, suppressed2 = filter_suppressions([f2], repo_path=str(tmp_path))
    assert len(active2) == 1
    assert len(suppressed2) == 0


def test_bandit_line_number_stripping_and_stability():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506",
        file="app.py",
        line=10,
        extra={"test_id": "B506", "line_range": [10]},
        evidence="10 yaml.load(stream)\n",
    )
    f2 = Finding(
        engine="bandit",
        title="Bandit B506",
        file="app.py",
        line=85,
        extra={"test_id": "B506", "line_range": [85]},
        evidence="85 yaml.load(stream)\n",
    )
    # Different line numbers with same rule and code content produce identical fingerprint
    assert compute_finding_fingerprint(f1) == compute_finding_fingerprint(f2)


def test_duplicate_lines_occurrence_index():
    f1 = Finding(
        engine="bandit",
        title="Bandit B506",
        file="app.py",
        line=10,
        extra={"test_id": "B506"},
        evidence="yaml.load(stream)",
    )
    f2 = Finding(
        engine="bandit",
        title="Bandit B506",
        file="app.py",
        line=20,
        extra={"test_id": "B506"},
        evidence="yaml.load(stream)",
    )
    # Same content at different occurrences yields distinct fingerprints
    fp1 = compute_finding_fingerprint(f1, occurrence=0)
    fp2 = compute_finding_fingerprint(f2, occurrence=1)
    assert fp1 != fp2


def test_nosemgrep_false_positive_suppresses(tmp_path):
    # Free-text comment like '# nosemgrep: false-positive' contains no dotted rule ID or CWE,
    # so it must be treated as a bare # nosemgrep and successfully suppress the finding.
    src = tmp_path / "app.py"
    src.write_text("yaml.load(d) # nosemgrep: false-positive\n", encoding="utf-8")

    f = Finding(
        engine="semgrep",
        title="Unsafe YAML",
        file="app.py",
        line=1,
        cwe="CWE-502",
        extra={"check_id": "scip.python.yaml.unsafe-load"},
    )
    active, suppressed = filter_suppressions([f], repo_path=str(tmp_path))
    assert len(active) == 0
    assert len(suppressed) == 1
    assert "nosemgrep" in suppressed[0].extra["suppression_reason"]


def test_scip_ignore_comment_bare_suppression_and_no_engine_name_targeting(tmp_path):
    # Free-text comment '# scip:ignore: secrets rotated' contains no ID-shaped tokens,
    # so it acts as a universal bare suppression rather than selectively targeting the 'SECRETS' engine.
    src = tmp_path / "creds.py"
    src.write_text('API_KEY = "sk_live_1234567890" # scip:ignore: secrets rotated\n', encoding="utf-8")

    f_sec = Finding(
        engine="secrets",
        title="Secret detected",
        file="creds.py",
        line=1,
        cwe="CWE-798",
        extra={"rule": "stripe-api-key"},
    )
    f_ban = Finding(
        engine="bandit",
        title="Bandit B105",
        file="creds.py",
        line=1,
        cwe="CWE-259",
        extra={"test_id": "B105"},
    )
    active, suppressed = filter_suppressions([f_sec, f_ban], repo_path=str(tmp_path))
    # Both findings on the line are suppressed because it acts as a bare suppression
    assert len(active) == 0
    assert len(suppressed) == 2

    # Engine names are excluded from finding tokens; only rule/CWE identifiers can be targeted
    tokens = _get_finding_tokens(f_sec)
    assert "SECRETS" not in tokens
    assert "stripe-api-key".upper() in tokens


def test_v2_baseline_occurrence_isolation(tmp_path):
    import json
    f1 = Finding(engine="bandit", title="Issue", file="app.py", line=10, cwe="CWE-89", evidence="sql.run()")
    f2 = Finding(engine="bandit", title="Issue", file="app.py", line=20, cwe="CWE-89", evidence="sql.run()")

    fp0 = compute_finding_fingerprint(f1, occurrence=0)
    fp1 = compute_finding_fingerprint(f2, occurrence=1)

    # Save v2 baseline containing only occurrence 0
    base_v2 = tmp_path / "base_v2.json"
    base_v2.write_text(json.dumps({"version": 2, "fingerprints": [fp0]}), encoding="utf-8")

    # In v2, occurrence 1 must NOT match occurrence 0
    active, suppressed = filter_suppressions([f1, f2], repo_path=str(tmp_path), baseline_path=str(base_v2))
    assert len(active) == 1
    assert active[0].line == 20
    assert len(suppressed) == 1
    assert suppressed[0].line == 10

    # In legacy v1 (list format), occurrence 1 falls back to occurrence 0
    base_v1 = tmp_path / "base_v1.json"
    base_v1.write_text(json.dumps([fp0]), encoding="utf-8")
    active_v1, suppressed_v1 = filter_suppressions([f1, f2], repo_path=str(tmp_path), baseline_path=str(base_v1))
    assert len(active_v1) == 0
    assert len(suppressed_v1) == 2


def test_load_baseline_missing_file_raises(tmp_path):
    missing_file = tmp_path / "does_not_exist.json"
    with pytest.raises(FileNotFoundError):
        load_baseline(missing_file)


def test_comment_filenames_and_versions_treated_as_bare_suppression(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "yaml.load(d) # nosemgrep: see utils.py\n"
        "eval(cmd) # scip:ignore: v1.2\n",
        encoding="utf-8",
    )

    f1 = Finding(
        engine="semgrep",
        title="YAML",
        file="app.py",
        line=1,
        cwe="CWE-502",
        extra={"check_id": "scip.python.yaml.unsafe-load"},
    )
    f2 = Finding(
        engine="bandit",
        title="Eval",
        file="app.py",
        line=2,
        cwe="CWE-95",
        extra={"test_id": "B307"},
    )

    active, suppressed = filter_suppressions([f1, f2], repo_path=str(tmp_path))
    assert len(active) == 0
    assert len(suppressed) == 2


def test_suppression_formfeed_and_crlf_line_numbering(tmp_path):
    src = tmp_path / "formfeed.py"
    # Formfeed on line 2 must not shift line 3 in split('\n')
    src.write_bytes(b"x = 1\r\n\x0cy = 2\r\nz = eval(cmd) # nosec\r\n")

    f = Finding(
        engine="bandit",
        title="Eval",
        file="formfeed.py",
        line=3,
        cwe="CWE-95",
        extra={"test_id": "B307"},
    )
    active, suppressed = filter_suppressions([f], repo_path=str(tmp_path))
    assert len(active) == 0
    assert len(suppressed) == 1
