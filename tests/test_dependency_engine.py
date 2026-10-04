"""Tests for the dependency engine. No real network: a fake session serves canned
OSV / EPSS / KEV responses (IDs below are made up on purpose)."""
import json
from pathlib import Path

import pytest

from core.cache import Cache
from engines.dependency_engine import (
    DependencyEngine,
    VulnInfo,
    collect_dependencies,
    extract_severity,
    merge_vulns,
    parse_osv_vuln,
    parse_requirement_line,
    pick_fixed_version,
)


# ----------------------------------------------------------------- parsing --
@pytest.mark.parametrize("line,expected", [
    ("flask==0.12.2", ("flask", "0.12.2")),
    ("Flask == 0.12.2", ("flask", "0.12.2")),
    ("PyYAML_Extra==3.13", ("pyyaml-extra", "3.13")),
    ("requests[security]==2.19.0", ("requests", "2.19.0")),
    ("django==2.2.0 ; python_version >= '3.6'", ("django", "2.2.0")),
    ("jinja2==2.10 --hash=sha256:abcdef", ("jinja2", "2.10")),
    ("numpy>=1.0", ("numpy", None)),
    ("pandas~=1.3", ("pandas", None)),
    ("six==1.*", ("six", None)),
    ("pkg @ https://example.com/pkg.zip", ("pkg", None)),
    ("flask", ("flask", None)),
])
def test_parse_requirement_line(line, expected):
    assert parse_requirement_line(line) == expected


@pytest.mark.parametrize("line", ["", "-e .", "--index-url https://x", "git+https://github.com/a/b",
                  "git+https://user@github.com/a/b.git#egg=b", "https://x.com/pkg.whl"])
def test_parse_requirement_line_ignores(line):
    assert parse_requirement_line(line) is None


def test_collect_requirements_with_comments_continuations_includes(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment\n"
        "flask==0.12.2  # inline comment\n"
        "\n"
        "-r extra.txt\n"
        "django==2.2.0 \\\n"
        "    --hash=sha256:abc\n"
        "numpy>=1.0\n",
        encoding="utf-8",
    )
    (tmp_path / "extra.txt").write_text("pyyaml==3.13\n", encoding="utf-8")
    deps = collect_dependencies(tmp_path)
    by_name = {d.name: d for d in deps}
    assert by_name["flask"].version == "0.12.2" and by_name["flask"].line == 2
    assert by_name["django"].version == "2.2.0" and by_name["django"].line == 5
    assert by_name["numpy"].version is None
    assert by_name["pyyaml"].version == "3.13"


def test_collect_skips_venv_and_finds_nested(tmp_path):
    (tmp_path / "venv" / "lib").mkdir(parents=True)
    (tmp_path / "venv" / "lib" / "requirements.txt").write_text("evil==1.0\n")
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "requirements-dev.txt").write_text("pytest==7.0.0\n")
    names = {d.name for d in collect_dependencies(tmp_path)}
    assert names == {"pytest"}


def test_pyproject_poetry_lock_and_pipfile_lock(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n  "flask==1.0",\n  "click>=7",\n]\n')
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "Jinja2"\nversion = "2.10"\n\n[[package]]\nname = "idna"\nversion = "2.8"\n')
    (tmp_path / "Pipfile.lock").write_text(json.dumps(
        {"default": {"urllib3": {"version": "==1.24.1"}}, "develop": {"pytest": {"version": "==6.0.0"}}}))
    got = {(d.name, d.version) for d in collect_dependencies(tmp_path)}
    assert ("flask", "1.0") in got
    assert ("click", None) in got
    assert ("jinja2", "2.10") in got and ("idna", "2.8") in got
    assert ("urllib3", "1.24.1") in got and ("pytest", "6.0.0") in got


# ------------------------------------------------------------- advisories --
def test_pick_fixed_version():
    assert pick_fixed_version(["0.12.3", "1.0"], "0.12.2") == "0.12.3"
    assert pick_fixed_version(["0.12.3", "1.0"], "0.12.3") == "1.0"
    assert pick_fixed_version(["0.12.3"], "2.0") is None
    assert pick_fixed_version([], "1.0") is None
    assert pick_fixed_version(["not-a-version"], "1.0") is None


def test_extract_severity_prefers_cvss_vector_then_label_then_none():
    v = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
         "database_specific": {"severity": "LOW"}}
    assert extract_severity(v) == (9.8, "cvss3")
    assert extract_severity({"database_specific": {"severity": "HIGH"}}) == (8.0, "label")
    assert extract_severity({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/..."}]}) == (None, "none")


def test_withdrawn_advisory_is_ignored():
    assert parse_osv_vuln({"id": "GHSA-x", "withdrawn": "2020-01-01T00:00:00Z"}, "flask") is None


def test_merge_vulns_dedupes_by_shared_alias_and_keeps_best_severity():
    ghsa = VulnInfo("GHSA-aaaa", {"CVE-2099-0001"}, "Bad thing", "", 8.0, "label", "CWE-79", ["1.1"])
    pysec = VulnInfo("PYSEC-1", {"CVE-2099-0001"}, "", "", None, "none", None, ["1.1", "2.0"])
    other = VulnInfo("GHSA-bbbb", set(), "Other", "", 5.5, "label", None, [])
    merged = merge_vulns([pysec, ghsa, other])
    assert len(merged) == 2
    main = next(m for m in merged if m.id == "CVE-2099-0001")
    assert main.cvss == 8.0 and main.cwe == "CWE-79" and main.summary == "Bad thing"
    assert {"GHSA-aaaa", "PYSEC-1"} <= main.aliases
    assert main.fixed == ["1.1", "2.0"]


# --------------------------------------------------------------- fake HTTP --
class FakeResp:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, osv_batch, vulns, epss=None, kev=None, fail=None):
        self.osv_batch, self.vulns = osv_batch, vulns
        self.epss, self.kev, self.fail = epss or {}, kev or [], fail or set()
        self.calls = []

    def _route(self, url, **kw):
        self.calls.append(url)
        for key in self.fail:
            if key in url:
                return FakeResp({}, 500)
        if url.endswith("/querybatch"):
            queries = kw["json"]["queries"]
            return FakeResp({"results": [self.osv_batch.get(
                f"{q['package']['name']}=={q['version']}", {}) for q in queries]})
        if "/vulns/" in url:
            vid = url.rsplit("/", 1)[1]
            return FakeResp(self.vulns[vid]) if vid in self.vulns else FakeResp({}, 404)
        if "first.org" in url:
            wanted = kw["params"]["cve"].split(",")
            return FakeResp({"data": [{"cve": c, "epss": str(self.epss[c]), "percentile": "0.9"}
                                      for c in wanted if c in self.epss]})
        if "cisa.gov" in url:
            return FakeResp({"vulnerabilities": [{"cveID": c} for c in self.kev]})
        return FakeResp({}, 404)

    def get(self, url, **kw):
        return self._route(url, **kw)

    def post(self, url, **kw):
        return self._route(url, **kw)


GHSA = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2099-0001"],
    "summary": "Denial of service in flask",
    "details": "Long details here.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    "database_specific": {"cwe_ids": ["CWE-400"], "severity": "HIGH"},
    "affected": [{"package": {"ecosystem": "PyPI", "name": "Flask"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}]}],
}
PYSEC = {
    "id": "PYSEC-0000-1",
    "aliases": ["CVE-2099-0001", "GHSA-aaaa-bbbb-cccc"],
    "details": "Same issue, PYSEC record.",
    "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}]}],
}


def make_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("flask==0.12.2\nsafe==1.0\nnumpy>=1.0\n")
    return repo


def make_session(**kw):
    return FakeSession(
        osv_batch={"flask==0.12.2": {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}, {"id": "PYSEC-0000-1"}]}},
        vulns={"GHSA-aaaa-bbbb-cccc": GHSA, "PYSEC-0000-1": PYSEC},
        epss={"CVE-2099-0001": 0.42}, **{"kev": ["CVE-1999-0000"], **kw})


def make_engine(tmp_path, session, **kw):
    return DependencyEngine(session=session, cache=Cache(tmp_path / "cache"), backoff=0, **kw)


# ------------------------------------------------------------------ engine --
def test_end_to_end_single_deduplicated_finding(tmp_path):
    repo = make_repo(tmp_path)
    engine = make_engine(tmp_path, make_session())
    findings = engine.scan(str(repo))

    assert len(findings) == 1                      # GHSA + PYSEC merged; 'safe' has none
    f = findings[0]
    assert f.engine == "dependency"
    assert f.file == "requirements.txt" and f.line == 1
    assert f.severity == 7.5 and f.cwe == "CWE-400"
    assert f.exploitability == 0.42
    assert "0.12.3" in f.fix_hint
    assert f.extra["package"] == "flask" and f.extra["fixed_version"] == "0.12.3"
    assert f.extra["kev"] is False and f.extra["severity_source"] == "cvss3"
    assert f.title.startswith("CVE-2099-0001: flask==0.12.2")
    assert engine.stats["dependencies_unpinned"] == 1
    assert engine.stats["vulnerabilities"] == 1


def test_kev_membership_forces_max_exploitability(tmp_path):
    repo = make_repo(tmp_path)
    engine = make_engine(tmp_path, make_session(kev=["CVE-2099-0001"]))
    f = engine.scan(str(repo))[0]
    assert f.exploitability == 1.0 and f.extra["kev"] is True
    assert engine.stats["kev_hits"] == 1


def test_second_run_uses_cache_not_network(tmp_path):
    repo = make_repo(tmp_path)
    s1 = make_session()
    make_engine(tmp_path, s1).scan(str(repo))
    assert len(s1.calls) > 0

    s2 = make_session()
    findings = make_engine(tmp_path, s2).scan(str(repo))
    assert s2.calls == []                          # everything came from cache
    assert len(findings) == 1


def test_offline_with_empty_cache_does_not_crash(tmp_path):
    repo = make_repo(tmp_path)
    s = make_session()
    engine = make_engine(tmp_path, s, offline=True)
    assert engine.scan(str(repo)) == []
    assert s.calls == []
    assert engine.stats["osv_errors"] == 1


def test_offline_after_online_run_still_finds_vulns(tmp_path):
    repo = make_repo(tmp_path)
    make_engine(tmp_path, make_session()).scan(str(repo))
    findings = make_engine(tmp_path, make_session(), offline=True).scan(str(repo))
    assert len(findings) == 1


def test_epss_and_kev_outage_degrades_gracefully(tmp_path):
    repo = make_repo(tmp_path)
    engine = make_engine(tmp_path, make_session(fail={"first.org", "cisa.gov"}))
    findings = engine.scan(str(repo))
    assert len(findings) == 1                      # still reported
    assert findings[0].exploitability == 0.0
    assert engine.stats["epss_available"] is False
    assert engine.stats["kev_available"] is False


def test_osv_outage_reports_error_and_no_findings(tmp_path):
    repo = make_repo(tmp_path)
    engine = make_engine(tmp_path, make_session(fail={"querybatch"}))
    assert engine.scan(str(repo)) == []
    assert engine.stats["osv_errors"] == 1


def test_repo_without_dependency_files(tmp_path):
    (tmp_path / "empty").mkdir()
    engine = make_engine(tmp_path, make_session())
    assert engine.scan(str(tmp_path / "empty")) == []
    assert engine.stats["dependencies_total"] == 0


def test_same_pin_in_two_files_gives_one_finding_with_both_locations(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "requirements-dev.txt").write_text("flask==0.12.2\n")
    f = make_engine(tmp_path, make_session()).scan(str(repo))
    assert len(f) == 1
    assert len(f[0].extra["locations"]) == 2
