"""Placeholder engine to prove the pipeline works. Delete later."""
from typing import List
from core.finding import Finding
from engines.base import Engine


class DummyEngine(Engine):
    name = "dummy"

    def scan(self, repo_path: str) -> List[Finding]:
        return [
            Finding(
                engine=self.name,
                title="Dummy finding (pipeline works)",
                file="example.py",
                line=1,
                severity=5.0,
                description="Replace this engine with real ones.",
            )
        ]
