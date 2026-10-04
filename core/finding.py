"""Unified Finding schema - every engine outputs this."""
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    engine: str                      # "dependency" | "secrets" | "crypto" | "churn"
    title: str
    file: str
    line: Optional[int] = None
    cwe: Optional[str] = None        # e.g. "CWE-327"
    severity: float = 0.0            # CVSS-like, 0-10
    description: str = ""
    evidence: str = ""               # masked snippet / package@version
    fix_hint: str = ""
    # filled later by other stages
    exploitability: float = 0.0      # 0-1 (EPSS / KEV)
    reachable: Optional[bool] = None
    blast_radius: int = 0
    churn: float = 0.0               # 0-1
    code_health_penalty: float = 0.0 # 0-1
    risk_score: float = 0.0
    explanation: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
