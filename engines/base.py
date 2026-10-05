"""Base class every detection engine inherits from."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
import json
from typing import Any, Dict, List, Optional, Union

from core.finding import Finding


def rel_path(path: Union[str, Path], root: Union[str, Path]) -> str:
    """Normalize path relative to root using POSIX separators."""
    root_resolved = Path(root).resolve()
    p = Path(path)
    if not p.is_absolute():
        p = root_resolved / p
    try:
        return p.resolve().relative_to(root_resolved).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


class Engine(ABC):
    name = "base"

    def is_available(self) -> bool:
        """Check if external binaries or dependencies required by this engine are available."""
        return True

    @staticmethod
    def _load_json(stdout: str) -> Optional[Dict[str, Any]]:
        """Extract and parse top-level JSON dictionary from process stdout."""
        if not stdout or "{" not in stdout:
            return None
        json_start = stdout.find("{")
        json_end = stdout.rfind("}")
        if json_start == -1 or json_end == -1 or json_start >= json_end:
            return None
        try:
            data = json.loads(stdout[json_start : json_end + 1])
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            return None
        return None

    @abstractmethod
    def scan(self, repo_path: str) -> List[Finding]:
        """Scan a repository and return a list of findings."""
        raise NotImplementedError
