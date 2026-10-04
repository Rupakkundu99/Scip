"""Tests for BanditEngine."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.finding import Finding
from engines.bandit_engine import (
    BanditEngine,
    _calculate_severity,
    _rel_path,
)


# --------------------------------------------------------------------------- #
# Unit tests: Helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "sev,conf,expected",
    [
        ("HIGH", "HIGH", 8.5),
        ("HIGH", "MEDIUM", 8.0),
        ("HIGH", "LOW", 7.5),
        ("MEDIUM", "HIGH", 5.5),
        ("MEDIUM", "MEDIUM", 5.0),
        ("MEDIUM", "LOW", 4.5),
        ("LOW", "HIGH", 3.0),
        ("LOW", "MEDIUM", 2.5),
        ("LOW", "LOW", 2.0),
    ],
)
def test_calculate_severity(sev, conf, expected):
    assert _calculate_severity(sev, conf) == expected


def test_rel_path(tmp_path):
    sub = tmp_path / "app" / "main.py"
    assert _rel_path(str(sub), tmp_path) == "app/main.py"


# --------------------------------------------------------------------------- #
# Unit tests: Finding generation from canned Bandit JSON
# --------------------------------------------------------------------------- #
CANNED_BANDIT_OUTPUT = {
    "errors": [],
    "metrics": {
        "_totals": {"loc": 25, "nosec": 0},
        "app.py": {"loc": 25, "nosec": 0},
    },
    "results": [
        {
            "code": "11 yaml.load(data, Loader=yaml.Loader)\n",
            "col_offset": 4,
            "end_col_offset": 40,
            "filename": "app.py",
            "issue_confidence": "HIGH",
            "issue_cwe": {"id": 20, "link": "https://cwe.mitre.org/data/definitions/20.html"},
            "issue_severity": "MEDIUM",
            "issue_text": "Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().",
            "line_number": 11,
            "line_range": [11],
            "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b506_yaml_load.html",
            "test_id": "B506",
            "test_name": "yaml_load",
        },
        {
            "code": "15 hashlib.md5(b'test').hexdigest()\n",
            "col_offset": 4,
            "end_col_offset": 35,
            "filename": "crypto.py",
            "issue_confidence": "HIGH",
            "issue_cwe": {"id": 327, "link": "https://cwe.mitre.org/data/definitions/327.html"},
            "issue_severity": "HIGH",
            "issue_text": "Use of weak MD5 hash function.",
            "line_number": 15,
            "line_range": [15],
            "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b303_md5.html",
            "test_id": "B303",
            "test_name": "hash_func",
        },
    ],
}


def test_parse_canned_bandit_output(tmp_path):
    engine = BanditEngine()
    raw_stdout = "[main] INFO Running...\n" + json.dumps(CANNED_BANDIT_OUTPUT)
    findings = engine._parse_output(raw_stdout, tmp_path)

    assert len(findings) == 2
    # Sorted by severity desc
    assert findings[0].engine == "bandit"
    assert findings[0].file == "crypto.py"
    assert findings[0].line == 15
    assert findings[0].cwe == "CWE-327"
    assert findings[0].severity == 8.5
    assert "B303" in findings[0].title
    assert "hashlib.sha256" in findings[0].fix_hint

    assert findings[1].file == "app.py"
    assert findings[1].cwe == "CWE-20"
    assert findings[1].severity == 5.5
    assert "yaml.safe_load" in findings[1].fix_hint
    assert engine.stats["findings_count"] == 2


def test_bandit_empty_output(tmp_path):
    engine = BanditEngine()
    findings = engine._parse_output("", tmp_path)
    assert findings == []
    assert engine._parse_output("no json here", tmp_path) == []


def test_bandit_no_py_files(tmp_path):
    engine = BanditEngine()
    findings = engine.scan(str(tmp_path))
    assert findings == []
    assert engine.stats.get("files_scanned") == 0


def test_bandit_target_not_found():
    engine = BanditEngine()
    findings = engine.scan("non_existent_dir_12345")
    assert findings == []
    assert "Directory does not exist" in engine.stats.get("errors", [])


# --------------------------------------------------------------------------- #
# Integration-level test on synthetic Python file
# --------------------------------------------------------------------------- #
def test_bandit_real_scan_synthetic(tmp_path):
    py_file = tmp_path / "vuln.py"
    py_file.write_text(
        "import yaml\n"
        "def bad(data):\n"
        "    return yaml.load(data, Loader=yaml.Loader)\n",
        encoding="utf-8",
    )
    engine = BanditEngine(tests=["B506"])
    findings = engine.scan(str(tmp_path))

    assert len(findings) >= 1
    f = findings[0]
    assert f.engine == "bandit"
    assert f.file == "vuln.py"
    assert f.line == 3
    assert "B506" in f.title
    assert "yaml.safe_load" in f.fix_hint
    assert engine.stats["findings_count"] >= 1


def test_bandit_handles_timeout(tmp_path):
    (tmp_path / "sample.py").write_text("print('hello')", encoding="utf-8")
    engine = BanditEngine(timeout=1)
    with patch("subprocess.run", side_effect=pytest.importorskip("subprocess").TimeoutExpired(cmd="bandit", timeout=1)):
        findings = engine.scan(str(tmp_path))
        assert findings == []
        assert any("Timed out" in e for e in engine.stats.get("errors", []))
