"""Tests for SemgrepEngine."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from engines.semgrep_engine import (
    SemgrepEngine,
    _extract_cwe,
    _rel_path,
)


# --------------------------------------------------------------------------- #
# Unit tests: Helpers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "raw,expected",
    [
        ({"cwe": ["CWE-502: Deserialization of Untrusted Data"]}, "CWE-502"),
        ({"cwe": ["CWE-89: SQL Injection", "CWE-20"]}, "CWE-89"),
        ({"cwe": "CWE-327"}, "CWE-327"),
        ({"cwe": "CWE-78: Command Injection"}, "CWE-78"),
        ({"cwe": []}, None),
        ({}, None),
    ],
)
def test_extract_cwe(raw, expected):
    assert _extract_cwe(raw) == expected


def test_rel_path(tmp_path):
    sub = tmp_path / "models" / "user.py"
    assert _rel_path(str(sub), tmp_path) == "models/user.py"


# --------------------------------------------------------------------------- #
# Unit tests: Parsing canned Semgrep JSON
# --------------------------------------------------------------------------- #
CANNED_SEMGREP_OUTPUT = {
    "version": "1.179.0",
    "results": [
        {
            "check_id": "scip.python.yaml.unsafe-load",
            "path": "app.py",
            "start": {"line": 11, "col": 16, "offset": 240},
            "end": {"line": 11, "col": 75, "offset": 299},
            "extra": {
                "message": "Use of unsafe yaml.load() allows arbitrary object deserialization.",
                "metadata": {
                    "cwe": ["CWE-502: Deserialization of Untrusted Data"],
                    "confidence": "HIGH",
                    "fix": "yaml.safe_load(data)",
                },
                "severity": "ERROR",
                "lines": "yaml.load(data, Loader=yaml.Loader)",
                "fingerprint": "abc123fingerprint",
            },
        },
        {
            "check_id": "scip.python.crypto.weak-hash",
            "path": "crypto.py",
            "start": {"line": 20, "col": 5, "offset": 400},
            "end": {"line": 20, "col": 25, "offset": 420},
            "extra": {
                "message": "Use of weak hashing algorithm MD5.",
                "metadata": {
                    "cwe": ["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"],
                    "confidence": "HIGH",
                },
                "severity": "WARNING",
                "lines": "hashlib.md5(b'token')",
                "fingerprint": "def456fingerprint",
            },
        },
    ],
    "paths": {"scanned": ["app.py", "crypto.py"]},
    "skipped_rules": [],
}


def test_parse_canned_semgrep_output(tmp_path):
    engine = SemgrepEngine()
    banner = "Scanning 2 files...\n✅ Scan completed.\n"
    raw_stdout = banner + json.dumps(CANNED_SEMGREP_OUTPUT)

    findings = engine._parse_output(raw_stdout, tmp_path)
    assert len(findings) == 2

    # Sorted by severity desc
    assert findings[0].engine == "semgrep"
    assert findings[0].file == "app.py"
    assert findings[0].line == 11
    assert findings[0].severity == 8.5
    assert findings[0].cwe == "CWE-502"
    assert "unsafe-load" in findings[0].title
    assert "Suggested fix: yaml.safe_load(data)" in findings[0].fix_hint
    assert findings[0].evidence == "yaml.load(data, Loader=yaml.Loader)"

    assert findings[1].file == "crypto.py"
    assert findings[1].line == 20
    assert findings[1].severity == 5.5
    assert findings[1].cwe == "CWE-327"
    assert engine.stats["findings_count"] == 2
    assert engine.stats["files_scanned"] == 2


def test_semgrep_not_available(tmp_path):
    engine = SemgrepEngine()
    with patch.object(engine, "is_available", return_value=False):
        findings = engine.scan(str(tmp_path))
        assert findings == []
        assert engine.stats["skipped"] is True
        assert "not found" in engine.stats.get("note", "").lower()


def test_semgrep_empty_target():
    engine = SemgrepEngine()
    findings = engine.scan("non_existent_folder_abc")
    assert findings == []
    assert "Directory does not exist" in engine.stats.get("errors", [])


# --------------------------------------------------------------------------- #
# Integration-level test: custom user rules and default rules
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not SemgrepEngine().is_available(), reason="Semgrep not installed")
def test_semgrep_user_custom_rules(tmp_path):
    # User provides their own custom ruleset
    custom_rule = tmp_path / "custom_rule.yaml"
    custom_rule.write_text(
        "rules:\n"
        "  - id: custom.dangerous.eval\n"
        "    pattern: eval(...)\n"
        "    message: 'Custom rule: eval is strictly forbidden.'\n"
        "    languages: [python]\n"
        "    severity: ERROR\n"
        "    metadata:\n"
        "      cwe: ['CWE-95']\n",
        encoding="utf-8",
    )

    code_file = tmp_path / "target.py"
    code_file.write_text("def run(cmd):\n    eval(cmd)\n", encoding="utf-8")

    engine = SemgrepEngine(rules_path=str(custom_rule))
    findings = engine.scan(str(tmp_path))

    assert len(findings) >= 1
    f = findings[0]
    assert f.engine == "semgrep"
    assert f.cwe == "CWE-95"
    assert "eval" in f.title.lower()
    assert f.line == 2


def test_semgrep_populates_line_range(tmp_path):
    engine = SemgrepEngine()
    canned = {
        "results": [
            {
                "check_id": "scip.test.rule",
                "path": "app.py",
                "start": {"line": 10},
                "end": {"line": 14},
                "extra": {"message": "Test finding", "severity": "WARNING"},
            }
        ],
        "paths": {"scanned": ["app.py"]},
        "skipped_rules": [],
    }
    findings = engine._parse_output(canned, tmp_path)
    assert len(findings) == 1
    assert findings[0].extra["line_range"] == [10, 11, 12, 13, 14]


def test_semgrep_non_json_records_error(tmp_path):
    engine = SemgrepEngine()
    from unittest.mock import MagicMock
    mock_proc = MagicMock(returncode=2, stdout="Fatal semgrep error", stderr="")
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run", return_value=mock_proc):
        findings = engine.scan(str(tmp_path))
        assert findings == []
        assert len(engine.stats["errors"]) >= 1
        assert "no JSON" in engine.stats["errors"][0]


def test_semgrep_include_suppressed_passes_flag(tmp_path):
    from unittest.mock import MagicMock
    engine = SemgrepEngine(include_suppressed=True)
    with patch.object(engine, "is_available", return_value=True), patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='{"results": [], "errors": []}', stderr="")
        engine.scan(str(tmp_path))
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "--disable-nosem" in cmd
