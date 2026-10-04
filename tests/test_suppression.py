"""Tests for inline comment suppression and baseline file handling."""
from pathlib import Path

from core.finding import Finding
from core.suppression import (
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

    fps = load_baseline(baseline_file)
    assert len(fps) == 1

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
