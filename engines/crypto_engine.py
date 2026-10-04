"""TODO: crypto engine - see docs/ROADMAP.md"""
from typing import List
from core.finding import Finding
from engines.base import Engine


class CryptoEngine(Engine):
    name = "crypto"

    def scan(self, repo_path: str) -> List[Finding]:
        # TODO: implement
        return []
