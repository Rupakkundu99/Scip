"""Semgrep rule-driven static analysis engine for SCIP.

Scans source code using semantic pattern rules (bundled default rules or user-provided
rulesets) to detect OWASP Top 10 vulnerabilities, framework misconfigurations,
insecure deserialization, and injection patterns.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.finding import Finding
from engines.base import Engine

log = logging.getLogger("scip.semgrep")

DEFAULT_RULES = Path(__file__).resolve().parent / "rules" / "semgrep" / "default_rules.yaml"
TIMEOUT = 60

SEV_MAP = {
    "ERROR": 8.5,
    "WARNING": 5.5,
    "INFO": 2.5,
}

EXPLOIT_MAP = {
    "ERROR": 0.75,
    "WARNING": 0.40,
    "INFO": 0.15,
}


def _extract_cwe(metadata: Dict[str, Any]) -> Optional[str]:
    raw_cwe = metadata.get("cwe")
    if not raw_cwe:
        return None
    if isinstance(raw_cwe, list) and raw_cwe:
        target = str(raw_cwe[0])
    else:
        target = str(raw_cwe)
    m = re.search(r"CWE-(\d+)", target, re.I)
    return f"CWE-{m.group(1)}" if m else None


def _rel_path(path: str, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


class SemgrepEngine(Engine):
    name = "semgrep"

    def __init__(
        self,
        rules_path: Optional[str] = None,
        timeout: int = TIMEOUT,
        max_target_bytes: int = 1_000_000,
        exclude_dirs: Optional[List[str]] = None,
    ):
        """Initialize SemgrepEngine.

        Args:
            rules_path: Path to custom YAML rule file/dir, or Semgrep preset (e.g. 'p/python').
                        If None, uses SCIP default rules.
            timeout: Subprocess timeout in seconds.
            max_target_bytes: Max file size in bytes to analyze (skips larger files).
            exclude_dirs: Directories to exclude from scan.
        """
        self.rules_path = rules_path or (str(DEFAULT_RULES) if DEFAULT_RULES.exists() else None)
        self.timeout = timeout
        self.max_target_bytes = max_target_bytes
        self.exclude_dirs = exclude_dirs or [".git", "venv", ".venv", "node_modules", ".tox"]
        self.stats: Dict[str, Any] = {}

    def is_available(self) -> bool:
        """Check if semgrep executable is installed and reachable."""
        return shutil.which("semgrep") is not None

    def scan(self, repo_path: str) -> List[Finding]:
        root = Path(repo_path).resolve()
        self.stats = {
            "engine": self.name,
            "target": str(root),
            "rules_used": str(self.rules_path),
            "findings_count": 0,
            "skipped": False,
            "errors": [],
        }

        if not root.exists():
            log.warning("Target path does not exist: %s", root)
            self.stats["errors"].append("Directory does not exist")
            return []

        if not self.is_available():
            log.warning("Semgrep CLI is not installed or not in PATH. Skipping Semgrep engine.")
            self.stats.update(skipped=True, note="Semgrep CLI not found in PATH")
            return []

        if not self.rules_path:
            log.warning("No Semgrep rules specified and default rules not found.")
            self.stats.update(skipped=True, note="No rules configuration found")
            return []

        cmd = [
            "semgrep",
            "scan",
            "--config",
            str(self.rules_path),
            "--json",
            "--quiet",
            "--max-target-bytes",
            str(self.max_target_bytes),
        ]

        for exc in self.exclude_dirs:
            cmd.extend(["--exclude", exc])

        cmd.append(str(root))

        log.info("Running Semgrep with config: %s", self.rules_path)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("Semgrep scan timed out after %ds on %s", self.timeout, root)
            self.stats["errors"].append(f"Timed out after {self.timeout}s")
            return []
        except Exception as e:
            log.warning("Failed to execute Semgrep: %s", e)
            self.stats["errors"].append(str(e))
            return []

        # Semgrep returns 0 on success (with or without findings), or 1 on blocking findings depending on flags
        if proc.returncode not in (0, 1) and not proc.stdout:
            err = proc.stderr.strip()[:300] or f"Exit code {proc.returncode}"
            log.warning("Semgrep execution failed: %s", err)
            self.stats["errors"].append(err)
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
            log.warning("Failed to decode Semgrep JSON: %s", e)
            self.stats["errors"].append(f"JSON decode error: {e}")
            return []

        raw_results = data.get("results", [])
        paths_scanned = data.get("paths", {}).get("scanned", [])
        self.stats.update(
            files_scanned=len(paths_scanned),
            rules_skipped=len(data.get("skipped_rules", [])),
        )

        findings: List[Finding] = []
        for r in raw_results:
            findings.append(self._make_finding(r, root))

        findings.sort(key=lambda f: (-f.severity, -f.exploitability, f.file, f.line or 0))
        self.stats["findings_count"] = len(findings)
        return findings

    def _make_finding(self, r: Dict[str, Any], root: Path) -> Finding:
        check_id = r.get("check_id", "semgrep.rule")
        short_id = check_id.split(".")[-1]

        extra = r.get("extra", {})
        message = extra.get("message", "Semgrep security finding").strip()
        metadata = extra.get("metadata", {})
        raw_sev = extra.get("severity", "WARNING").upper()

        severity = SEV_MAP.get(raw_sev, 5.0)
        exploitability = EXPLOIT_MAP.get(raw_sev, 0.4)

        cwe = _extract_cwe(metadata)

        raw_path = r.get("path", "")
        rel_file = _rel_path(raw_path, root)
        start = r.get("start", {})
        line = start.get("line")

        # Summary title
        first_sentence = message.split(".")[0] if message else check_id
        title = f"Semgrep {short_id}: {first_sentence}"

        # Fix hint
        fix_content = extra.get("fix") or metadata.get("fix")
        if fix_content:
            fix_hint = f"Suggested fix: {fix_content}"
        else:
            fix_hint = f"Review rule {check_id} and refactor code to remediate this issue."

        # Evidence
        evidence = (extra.get("lines") or "").strip()

        return Finding(
            engine=self.name,
            title=title,
            file=rel_file,
            line=line,
            cwe=cwe,
            severity=severity,
            description=message,
            evidence=evidence,
            fix_hint=fix_hint,
            exploitability=exploitability,
            extra={
                "check_id": check_id,
                "rule_severity": raw_sev,
                "confidence": metadata.get("confidence", "MEDIUM"),
                "owasp": metadata.get("owasp"),
                "references": metadata.get("references", []),
                "fingerprint": extra.get("fingerprint"),
                "start": start,
                "end": r.get("end", {}),
            },
        )
