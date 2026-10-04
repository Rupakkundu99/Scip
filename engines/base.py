"""Base class every detection engine inherits from."""
from abc import ABC, abstractmethod
from typing import List
from core.finding import Finding


class Engine(ABC):
    name = "base"

    @abstractmethod
    def scan(self, repo_path: str) -> List[Finding]:
        """Scan a repository and return a list of findings."""
        raise NotImplementedError
