from core.pipeline import run_scan
from engines.dummy_engine import DummyEngine


def test_pipeline_returns_findings():
    findings = run_scan(".", engines=[DummyEngine()])
    assert len(findings) >= 1
    assert findings[0].engine == "dummy"
