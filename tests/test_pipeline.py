from core.finding import Finding
from core.pipeline import get_engines, run_scan
from engines.dummy_engine import DummyEngine


def test_pipeline_returns_findings():
    findings = run_scan(".", engines=[DummyEngine()])
    assert len(findings) >= 1
    assert findings[0].engine == "dummy"


def test_get_engines_defaults():
    engines = get_engines()
    names = [e.name for e in engines]
    assert "dependency" in names
    assert "secrets" in names
    assert "bandit" in names
    assert "semgrep" in names


def test_get_engines_disable_bandit_and_semgrep():
    engines = get_engines(run_bandit=False, run_semgrep=False)
    names = [e.name for e in engines]
    assert "bandit" not in names
    assert "semgrep" not in names
    assert "dependency" in names
    assert "secrets" in names


def test_get_engines_selective_list():
    engines = get_engines(enabled_engines=["bandit", "semgrep"])
    names = [e.name for e in engines]
    assert names == ["bandit", "semgrep"]


def test_pipeline_runs_multiple_engines():
    class MockEngine:
        def __init__(self, name):
            self.name = name

        def scan(self, path):
            return [
                Finding(
                    engine=self.name,
                    title=f"Finding from {self.name}",
                    file="test.py",
                    severity=5.0,
                )
            ]

    findings = run_scan(".", engines=[MockEngine("bandit"), MockEngine("semgrep")])
    assert len(findings) == 2
    assert {f.engine for f in findings} == {"bandit", "semgrep"}
