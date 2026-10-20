"""Tests for connecting the code patcher to the remediation flow (select, verify by re-scan, CLI)."""
import json
from pathlib import Path

import pytest

from remediation.code_fix import (count_by_rule, not_automated, select_code_findings, verify_code)
from remediation.code_patcher import apply_code_patches
from remediation.run import main
from remediation.verify import TestOutcome as Outcome

APP = 'from flask import Flask\napp = Flask(__name__)\nif __name__ == "__main__":\n    app.run(debug=True)\n'


def bf(tid="B201", file="app.py", line=4, **kw):
    return {"engine": "bandit", "file": file, "line": line, "title": f"Bandit {tid}: x", "extra": {"test_id": tid}, **kw}


def repo(tmp_path, reqs=None):
    r = tmp_path / "repo"
    r.mkdir(parents=True)
    (r / "app.py").write_text(APP, encoding="utf-8")
    if reqs:
        (r / "requirements.txt").write_text(reqs, encoding="utf-8")
    return r


def fake_scan(path):
    """Pretends to be Bandit: reports B201 while app.py still contains debug=True."""
    text = (Path(path) / "app.py").read_text(encoding="utf-8")
    return [bf()] if "debug=True" in text else []


def patched(tmp_path):
    r = repo(tmp_path)
    return r, apply_code_patches(r, [bf()], tmp_path / "ws")


# ------------------------------------------------------------------ selection
def test_only_fixable_bandit_findings_are_selected_and_the_rest_are_counted():
    fs = [bf("B201"), bf("B113", line=9), bf("B311", line=2), bf("B311", line=3),
          {"engine": "semgrep", "file": "a.py", "line": 1, "extra": {"test_id": "B201"}}]
    assert [f["extra"]["test_id"] for f in select_code_findings(fs)] == ["B201", "B113"]
    assert not_automated(fs) == {"B311": 2}


def test_count_by_rule_normalises_paths():
    assert count_by_rule([bf(file="./app.py"), bf(file="app.py")])[("app.py", "B201")] == 2


# ------------------------------------------------------------------ verification
def test_clean_rescan_confirms_the_fix_but_is_not_called_verified_without_tests(tmp_path):
    r, res = patched(tmp_path)
    v = verify_code(res, r, fake_scan)
    assert v.status == "scan_only" and v.confirmed == ["B201 app.py"] and not v.remaining and not v.introduced
    assert any("not proven safe" in m for m in v.messages)


def test_confirmed_count_counts_findings_not_file_rule_groups(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "net.py").write_text('import requests\nr1 = requests.get("http://x")\nr2 = requests.get("http://y")\n', encoding="utf-8")
    res = apply_code_patches(r, [bf("B113", "net.py", 2), bf("B113", "net.py", 3)], tmp_path / "ws")

    def scan(path):
        lines = (Path(path) / "net.py").read_text(encoding="utf-8").splitlines()
        return [bf("B113", "net.py", i + 1) for i, l in enumerate(lines) if "requests." in l and "timeout" not in l]
    v = verify_code(res, r, scan)
    assert v.confirmed == ["B113 net.py x2"] and v.confirmed_count == 2 and v.remaining_count == 0


def test_a_fix_that_does_not_remove_the_finding_needs_review(tmp_path):
    r, res = patched(tmp_path)
    v = verify_code(res, r, lambda p: [bf()])
    assert v.status == "needs_review" and v.remaining == ["B201 app.py"] and v.remaining_count == 1 and not v.confirmed


def test_a_new_finding_after_the_patch_needs_review(tmp_path):
    r, res = patched(tmp_path)

    def scan(path):
        return fake_scan(path) + ([bf("B113", line=9)] if "ws" in str(path) else [])
    v = verify_code(res, r, scan)
    assert v.status == "needs_review" and v.introduced == ["B113 app.py (+1)"]


def test_unavailable_scanner_never_confirms_a_fix(tmp_path):
    r, res = patched(tmp_path)

    def boom(path):
        raise RuntimeError("Bandit is not installed")
    v = verify_code(res, r, boom)
    assert v.status == "scan_unavailable" and not v.confirmed and "NOT confirmed" in v.messages[0]


def test_a_patched_file_that_no_longer_parses_is_flagged(tmp_path):
    r, res = patched(tmp_path)
    (res.workspace / "app.py").write_text("def broken(:\n", encoding="utf-8")
    v = verify_code(res, r, lambda p: [])
    assert v.status == "needs_review" and "app.py" in v.syntax_errors[0]


def test_nothing_applied_status(tmp_path):
    r = repo(tmp_path)
    res = apply_code_patches(r, [bf(line=99)], tmp_path / "ws")
    assert verify_code(res, r, fake_scan).status == "nothing_applied"


@pytest.mark.parametrize("ran,passed,fresh,expected", [
    (True, True, True, "verified"), (True, True, False, "scan_only"),
    (True, False, True, "tests_failed"), (False, False, True, "scan_only")])
def test_tests_decide_between_verified_scan_only_and_tests_failed(tmp_path, ran, passed, fresh, expected):
    r, res = patched(tmp_path)
    t = Outcome(ran=ran, passed=passed, fresh_venv=fresh, command="pytest", error="" if ran else "timeout")
    assert verify_code(res, r, fake_scan, t, fresh).status == expected


# ------------------------------------------------------------------ CLI
def run_cli(tmp_path, findings, extra=(), repo_dir=None, **kw):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(findings), encoding="utf-8")
    out = tmp_path / "out"
    code = main([str(repo_dir), "--scan", str(scan), "--out", str(out), *extra], **kw)
    return code, out, json.loads((out / "report.json").read_text(encoding="utf-8"))


def depf():
    return {"engine": "dependency", "file": "requirements.txt", "line": 1, "risk_score": 50,
            "title": "CVE-1: django==4.2 - x", "evidence": "django==4.2",
            "extra": {"package": "django", "version": "4.2", "vuln_id": "CVE-1", "fixed_version": "4.2.16"}}


def test_cli_applies_library_and_code_fixes_together_without_touching_the_original(tmp_path):
    r = repo(tmp_path, "django==4.2\n")
    before = (r / "app.py").read_bytes(), (r / "requirements.txt").read_bytes()
    code, out, rep = run_cli(tmp_path, [depf(), bf(), bf("B311", line=2)], ["--verify"], r,
                             scan_fn=lambda p: [], code_scan_fn=fake_scan)
    assert code == 0 and ((r / "app.py").read_bytes(), (r / "requirements.txt").read_bytes()) == before
    assert "+django==4.2.16" in (out / "dependency_upgrades.patch").read_text(encoding="utf-8")
    assert "+    app.run(debug=False)" in (out / "code_fixes.patch").read_text(encoding="utf-8")
    final = out / "workspace_final"
    assert "django==4.2.16" in (final / "requirements.txt").read_text(encoding="utf-8")
    assert "debug=False" in (final / "app.py").read_text(encoding="utf-8")
    c = rep["code"]
    assert c["applied"][0]["test_id"] == "B201" and c["applied"][0]["tier"] == "mechanical"
    assert c["not_automated"] == {"B311": 1} and c["verification"]["status"] == "scan_only"
    assert rep["verification"]["status"] == "scan_only"


def test_cli_code_only_project_needs_no_network_and_no_library_scan(tmp_path):
    r = repo(tmp_path)

    def must_not_run(path):
        raise AssertionError("library re-scan must not run when no library was upgraded")
    code, out, rep = run_cli(tmp_path, [bf()], ["--verify"], r, scan_fn=must_not_run, code_scan_fn=fake_scan)
    assert code == 0 and rep["verification"]["status"] == "nothing_applied"
    assert rep["code"]["verification"]["confirmed"] == ["B201 app.py"] and not (out / "dependency_upgrades.patch").exists()


def test_cli_plan_only_writes_code_patch_without_verifying(tmp_path):
    r = repo(tmp_path)
    code, out, rep = run_cli(tmp_path, [bf()], [], r)
    assert (out / "code_fixes.patch").exists() and rep["code"]["verification"] is None


def test_cli_no_code_flag_skips_code_fixes(tmp_path):
    r = repo(tmp_path)
    code, out, rep = run_cli(tmp_path, [bf()], ["--no-code"], r)
    assert rep["code"] is None and not (out / "code_fixes.patch").exists()


def test_cli_reports_unconfirmed_fixes_when_bandit_is_missing(tmp_path, capsys):
    r = repo(tmp_path)

    def missing(path):
        raise RuntimeError("Bandit is not installed")
    code, out, rep = run_cli(tmp_path, [bf()], ["--verify"], r, scan_fn=lambda p: [], code_scan_fn=missing)
    assert rep["code"]["verification"]["status"] == "scan_unavailable"
    assert "SCAN_UNAVAILABLE" in capsys.readouterr().out
