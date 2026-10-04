"""Bandit static security analysis engine for Python.

Scans Python code for common security issues (AST-based analysis), such as
insecure cryptography, unsafe deserialization (yaml/pickle), command injection,
and dangerous built-ins.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.finding import Finding
from engines.base import Engine

log = logging.getLogger("scip.bandit")

DEFAULT_CONFIG = Path(__file__).resolve().parent / "configs" / "bandit_default.yaml"
TIMEOUT = 60

# Severity and confidence multipliers for composite 0-10 score
SEV_MAP = {"HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.5}
CONF_ADJUST = {"HIGH": 0.5, "MEDIUM": 0.0, "LOW": -0.5}

COMMON_FIX_HINTS: Dict[str, str] = {
    "B506": "Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution.",
    "B301": "Pickle is insecure for untrusted inputs. Use json, protocol buffers, or cryptographic signing.",
    "B303": "Use a secure cryptographic hash (e.g. hashlib.sha256()) instead of MD5/SHA1.",
    "B304": "Avoid weak ciphers (e.g. DES, ARC4). Use AES-GCM or ChaCha20-Poly1305 from cryptography library.",
    "B305": "Avoid weak cipher modes. Use authenticated cipher modes like AES-GCM.",
    "B113": "Add a timeout parameter to requests call (e.g., requests.get(url, timeout=10)).",
    "B501": "Do not set verify=False on HTTPS requests. Ensure valid certificates are trusted.",
    "B602": "Avoid shell=True in subprocess calls. Pass arguments as a list and validate input.",
    "B603": "Ensure arguments passed to subprocess are strictly validated or use an allowlist.",
    "B608": "Use parameterized SQL queries with placeholders instead of string formatting or concatenation.",
    "B324": "Specify usedforsecurity=False if hashing with MD5/SHA1 strictly for non-cryptographic checksums.",
    "B377": "Use tempfile.NamedTemporaryFile() or mkstemp() instead of deprecated, race-prone mktemp().",
}


def _calculate_severity(issue_sev: str, issue_conf: str) -> float:
    base = SEV_MAP.get(issue_sev.upper(), 5.0)
    adjust = CONF_ADJUST.get(issue_conf.upper(), 0.0)
    return round(max(1.0, min(10.0, base + adjust)), 1)


def _rel_path(path: str, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


class BanditEngine(Engine):
    name = "bandit"

    def __init__(
        self,
        config_file: Optional[str] = None,
        tests: Optional[List[str]] = None,
        skips: Optional[List[str]] = None,
        severity_min: Optional[str] = None,
        confidence_min: Optional[str] = None,
        timeout: int = TIMEOUT,
    ):
        self.config_file = config_file or (str(DEFAULT_CONFIG) if DEFAULT_CONFIG.exists() else None)
        self.tests = tests
        self.skips = skips
        self.severity_min = severity_min
        self.confidence_min = confidence_min
        self.timeout = timeout
        self.stats: Dict[str, Any] = {}

    def scan(self, repo_path: str) -> List[Finding]:
        root = Path(repo_path).resolve()
        self.stats = {
            "engine": self.name,
            "target": str(root),
            "findings_count": 0,
            "skipped": False,
            "errors": [],
        }

        if not root.exists():
            log.warning("Target directory does not exist: %s", root)
            self.stats["errors"].append("Directory does not exist")
            return []

        # Check if there are any python files to scan
        py_files = list(root.glob("**/*.py"))
        if not py_files:
            log.info("No Python files found under %s", root)
            self.stats["files_scanned"] = 0
            return []

        cmd = [sys.executable, "-m", "bandit", "-r", str(root), "-f", "json"]

        if self.config_file and os.path.exists(self.config_file):
            cmd.extend(["-c", str(self.config_file)])
        if self.tests:
            cmd.extend(["-t", ",".join(self.tests)])
        if self.skips:
            cmd.extend(["-s", ",".join(self.skips)])
        if self.severity_min:
            flag = {"low": "-l", "medium": "-m", "high": "-h"}.get(self.severity_min.lower())
            if flag:
                cmd.append(flag)
        if self.confidence_min:
            flag = {"low": "-i", "medium": "-ii", "high": "-iii"}.get(self.confidence_min.lower())
            if flag:
                cmd.append(flag)

        log.info("Running Bandit: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("Bandit scan timed out after %ds on %s", self.timeout, root)
            self.stats["errors"].append(f"Timed out after {self.timeout}s")
            return []
        except Exception as e:
            log.warning("Failed to invoke Bandit: %s", e)
            self.stats["errors"].append(str(e))
            return []

        # Bandit returns code 0 (no issues) or 1 (issues found). Other codes indicate failure.
        if proc.returncode not in (0, 1):
            err_msg = proc.stderr.strip()[:300] or f"Exit code {proc.returncode}"
            log.warning("Bandit process exited with error: %s", err_msg)
            self.stats["errors"].append(err_msg)
            return []

        return self._parse_output(proc.stdout, root)

    def _parse_output(self, stdout: str, root: Path) -> List[Finding]:
        if not stdout or "{" not in stdout:
            return []

        json_start = stdout.find("{")
        json_end = stdout.rfind("}")
        if json_start == -1 or json_end == -1:
            return []

        try:
            data = json.loads(stdout[json_start : json_end + 1])
        except json.JSONDecodeError as e:
            log.warning("Failed to parse Bandit JSON output: %s", e)
            self.stats["errors"].append(f"JSON parse error: {e}")
            return []

        metrics = data.get("metrics", {})
        totals = metrics.get("_totals", {})
        self.stats.update(
            files_scanned=len(metrics) - 1 if "_totals" in metrics else len(metrics),
            loc=totals.get("loc", 0),
            nosec=totals.get("nosec", 0),
        )

        results = data.get("results", [])
        findings: List[Finding] = []

        for r in results:
            findings.append(self._make_finding(r, root))

        findings.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.line or 0))
        self.stats["findings_count"] = len(findings)
        return findings

    def _make_finding(self, r: Dict[str, Any], root: Path) -> Finding:
        test_id = r.get("test_id", "UNKNOWN")
        test_name = r.get("test_name", "")
        raw_text = r.get("issue_text", "")
        summary = raw_text.split(".")[0] if raw_text else test_name
        issue_sev = r.get("issue_severity", "MEDIUM")
        issue_conf = r.get("issue_confidence", "MEDIUM")

        severity = _calculate_severity(issue_sev, issue_conf)

        # CWE Extraction
        cwe_data = r.get("issue_cwe") or {}
        cwe_id = cwe_data.get("id")
        cwe_str = f"CWE-{cwe_id}" if cwe_id else None

        # File & Line
        raw_filename = r.get("filename", "")
        rel_file = _rel_path(raw_filename, root)
        line = r.get("line_number")

        # Exploitability heuristic based on severity and confidence
        exploit_base = {"HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15}.get(issue_sev.upper(), 0.3)
        exploit_conf = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5}.get(issue_conf.upper(), 0.7)
        exploitability = round(exploit_base * exploit_conf, 2)

        # Fix hint
        fix_hint = COMMON_FIX_HINTS.get(
            test_id,
            f"Review Bandit rule {test_id} ({r.get('more_info', '')}) and refactor the code to eliminate this pattern.",
        )

        # Evidence
        code_snippet = (r.get("code") or "").strip()

        return Finding(
            engine=self.name,
            title=f"Bandit {test_id}: {summary}",
            file=rel_file,
            line=line,
            cwe=cwe_str,
            severity=severity,
            description=raw_text,
            evidence=code_snippet,
            fix_hint=fix_hint,
            exploitability=exploitability,
            extra={
                "test_id": test_id,
                "test_name": test_name,
                "issue_severity": issue_sev,
                "issue_confidence": issue_conf,
                "line_range": r.get("line_range", []),
                "col_offset": r.get("col_offset"),
                "end_col_offset": r.get("end_col_offset"),
                "more_info": r.get("more_info", ""),
            },
        )
