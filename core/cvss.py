"""CVSS v3.x base score calculator.

OSV gives severity as a vector string (e.g. CVSS:3.1/AV:N/AC:L/...), not a number,
so we compute the 0-10 base score ourselves (formula from the FIRST CVSS v3.1 spec).
CVSS v4 vectors are not supported -> returns None (caller falls back to a label).
"""
import math
from typing import Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS 3.1 Roundup: smallest number, to 1 decimal, >= x (float-safe)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    try:
        parts = vector.strip().split("/")
        if not parts[0].startswith("CVSS:3"):
            return None
        m = dict(p.split(":", 1) for p in parts[1:])
        changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        if impact <= 0:
            return 0.0
        if changed:
            return _roundup(min(1.08 * (impact + exploitability), 10))
        return _roundup(min(impact + exploitability, 10))
    except (KeyError, ValueError, AttributeError):
        return None
