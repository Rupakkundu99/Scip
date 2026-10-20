"""Tests for the dashboard backend: real HTTP, fake tools (so they are fast and need no network)."""
import json
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest

from api import server

SCAN = [{"engine": "bandit", "file": "a.py", "line": 3, "title": "x", "risk_score": 5, "severity": 4}]
WRITE = "import sys,json;p=sys.argv[1];json.dump(%s,open(p,'w'))"


@pytest.fixture
def srv(tmp_path, monkeypatch):
    (tmp_path / "dashboard").mkdir()
    (tmp_path / "dashboard" / "index.html").write_text("<html>SCIP page</html>", encoding="utf-8")
    (tmp_path / "test_repos" / "demo").mkdir(parents=True)
    (tmp_path / "evaluation" / "labels").mkdir(parents=True)
    monkeypatch.setattr(server, "ROOT", tmp_path)
    monkeypatch.setattr(server, "scan_argv",
                        lambda path, out, h, o: [sys.executable, "-c", WRITE % json.dumps(SCAN), str(out)])
    monkeypatch.setattr(server, "eval_argv",
                        lambda scan, labels, out: [sys.executable, "-c", WRITE % '{"coverage":{}}', str(out)])

    def rem(path, scan, outdir, o, v):
        code = ("import sys,json,pathlib;d=pathlib.Path(sys.argv[1]);d.mkdir(parents=True,exist_ok=True);"
                "(d/'report.json').write_text(json.dumps({'plan':{},'applied':[]}));"
                "(d/'dependency_upgrades.patch').write_text('+x');(d/'code_fixes.patch').write_text('+y')")
        return [sys.executable, "-c", code, str(outdir)]
    monkeypatch.setattr(server, "rem_argv", rem)
    s = server.make_server(0)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    s.base = f"http://127.0.0.1:{s.server_address[1]}"
    s.root = tmp_path
    yield s
    s.shutdown()


def call(base, path, body=None, headers=None, ctype="application/json"):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": ctype, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def jcall(*a, **k):
    code, data = call(*a, **k)
    return code, json.loads(data)


def wait(base, jid):
    for _ in range(100):
        code, j = jcall(base, f"/api/jobs/{jid}")
        if j["status"] != "running":
            return j
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_serves_page_health_and_project_list(srv):
    code, body = call(srv.base, "/")
    assert code == 200 and b"SCIP page" in body
    assert jcall(srv.base, "/api/health")[1] == {"ok": True}
    names = [p["name"] for p in jcall(srv.base, "/api/projects")[1]["projects"]]
    assert names == ["demo"]


def test_scan_job_end_to_end(srv):
    code, j = jcall(srv.base, "/api/scan", {"path": str(srv.root / "test_repos" / "demo")})
    assert code == 202
    assert wait(srv.base, j["job"])["status"] == "done"
    code, res = jcall(srv.base, f"/api/jobs/{j['job']}/result")
    assert code == 200 and res == SCAN


@pytest.mark.parametrize("body", [{}, {"path": ""}, {"path": "/definitely/not/here"}])
def test_scan_rejects_missing_or_bad_folder(srv, body):
    code, j = jcall(srv.base, "/api/scan", body)
    assert code == 400 and "folder" in j["error"]


def test_failed_tool_reports_failed_not_done(srv, monkeypatch):
    monkeypatch.setattr(server, "scan_argv", lambda *a: [sys.executable, "-c", "print('boom')"])
    jid = jcall(srv.base, "/api/scan", {"path": str(srv.root)})[1]["job"]
    j = wait(srv.base, jid)
    assert j["status"] == "failed" and "boom" in j["error"]
    assert jcall(srv.base, f"/api/jobs/{jid}/result")[0] == 409


def test_remediation_needs_a_finished_scan_then_returns_report_and_patch(srv):
    assert jcall(srv.base, "/api/remediate", {"scan_job": "nope"})[0] == 400
    sj = jcall(srv.base, "/api/scan", {"path": str(srv.root)})[1]["job"]
    wait(srv.base, sj)
    rj = jcall(srv.base, "/api/remediate", {"scan_job": sj})[1]["job"]
    assert wait(srv.base, rj)["status"] == "done"
    res = jcall(srv.base, f"/api/jobs/{rj}/result")[1]
    assert res["patch"] == "+x" and res["code_patch"] == "+y" and "plan" in res["report"]


def test_evaluation_needs_labels_for_that_project(srv):
    folder = srv.root / "test_repos" / "demo"
    sj = jcall(srv.base, "/api/scan", {"path": str(folder)})[1]["job"]
    wait(srv.base, sj)
    code, j = jcall(srv.base, "/api/evaluate", {"scan_job": sj})
    assert code == 404 and "no labels" in j["error"]
    (srv.root / "evaluation" / "labels" / "demo.yaml").write_text("repo: demo\n", encoding="utf-8")
    ej = jcall(srv.base, "/api/evaluate", {"scan_job": sj})[1]["job"]
    assert wait(srv.base, ej)["status"] == "done"
    assert jcall(srv.base, f"/api/jobs/{ej}/result")[1] == {"coverage": {}}


def test_security_checks(srv):
    assert jcall(srv.base, "/api/health", headers={"Host": "evil.example.com"})[0] == 403
    assert jcall(srv.base, "/api/scan", {"path": "."}, ctype="text/plain")[0] == 415
    assert jcall(srv.base, "/api/jobs/unknown")[0] == 404
    assert jcall(srv.base, "/api/jobs/..%2F..%2Fetc")[0] == 404
    assert call(srv.base, "/etc/passwd")[0] == 404
    code, _ = call(srv.base, "/api/scan", body=None)       # GET on a POST route
    assert code == 404
