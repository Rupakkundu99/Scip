"""Local backend for the dashboard (standard library only).

    python -m api            # then open http://127.0.0.1:8000

Serves dashboard/index.html and runs the real tools as background jobs:
  POST /api/scan       {path, history, offline}   -> core.pipeline
  POST /api/remediate  {scan_job, verify}         -> remediation.run (works on a copy; project untouched)
  POST /api/evaluate   {scan_job}                 -> evaluation.run (needs evaluation/labels/<folder>.yaml)
  GET  /api/jobs/<id>  status + log;   GET /api/jobs/<id>/result  the output
Safety: binds to 127.0.0.1 only, JSON requests only, Host header checked, tools run without a shell.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
JOBS: Dict[str, Dict[str, Any]] = {}
MAX_BODY = 100_000


def scan_argv(path: Path, out: Path, history: bool, offline: bool) -> List[str]:
    a = [sys.executable, "-m", "core.pipeline", str(path), "-o", str(out)]
    if not history:
        a.append("--no-history")
    if offline:
        a.append("--offline")
    return a


def rem_argv(path: Path, scan: Path, outdir: Path, offline: bool, verify: bool) -> List[str]:
    a = [sys.executable, "-m", "remediation.run", str(path), "--scan", str(scan), "--out", str(outdir)]
    if verify:
        a.append("--verify")
    if offline:
        a.append("--offline")
    return a


def eval_argv(scan: Path, labels: Path, out: Path) -> List[str]:
    return [sys.executable, "-m", "evaluation.run", "evaluate", "--scan", str(scan), "--labels", str(labels),
            "--json-out", str(out)]


def start_job(kind: str, argv: List[str], out: Path, path: str = "", offline: bool = False) -> str:
    jid = uuid.uuid4().hex[:12]
    job = {"id": jid, "kind": kind, "status": "running", "log": [], "error": "", "out": out, "path": path,
           "offline": offline}
    JOBS[jid] = job

    def run() -> None:
        env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
        try:
            p = subprocess.Popen(argv, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, encoding="utf-8", errors="replace", env=env)
            for line in p.stdout:
                job["log"].append(line.rstrip())
                del job["log"][:-400]
            p.wait()
        except OSError as exc:
            job["status"], job["error"] = "failed", str(exc)
            return
        if out.exists():
            job["status"] = "done"
        else:
            job["status"] = "failed"
            job["error"] = " | ".join(x for x in job["log"][-4:] if x) or "the tool produced no output"

    threading.Thread(target=run, daemon=True).start()
    return jid


def _projects() -> List[Dict[str, str]]:
    out = []
    for d in ("test_repos", "samples"):
        base = ROOT / d
        if base.is_dir():
            out += [{"name": p.name, "path": str(p)} for p in sorted(base.iterdir()) if p.is_dir()
                    and not p.name.startswith(".")]
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a) -> None:
        pass

    def _send(self, code: int, obj: Any = None, body: Optional[bytes] = None,
              ctype: str = "application/json") -> None:
        data = body if body is not None else json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _guard(self) -> bool:
        if self.headers.get("Host", "").split(":")[0] not in ("127.0.0.1", "localhost"):
            self._send(403, {"error": "forbidden host"})
            return False
        return True

    def _job(self, jid: str) -> Optional[Dict[str, Any]]:
        j = JOBS.get(jid)
        if j is None:
            self._send(404, {"error": "unknown job"})
        return j

    def do_GET(self) -> None:
        if not self._guard():
            return
        p = self.path.split("?")[0].rstrip("/")
        if p in ("", "/index.html"):
            page = ROOT / "dashboard" / "index.html"
            if page.exists():
                return self._send(200, body=page.read_bytes(), ctype="text/html; charset=utf-8")
            return self._send(404, {"error": "dashboard/index.html not found"})
        if p == "/api/health":
            return self._send(200, {"ok": True})
        if p == "/api/projects":
            return self._send(200, {"projects": _projects()})
        parts = p.split("/")
        if len(parts) >= 4 and parts[1] == "api" and parts[2] == "jobs":
            j = self._job(parts[3])
            if j is None:
                return
            if len(parts) == 4:
                return self._send(200, {"id": j["id"], "kind": j["kind"], "status": j["status"],
                                        "log": j["log"][-40:], "error": j["error"]})
            if len(parts) == 5 and parts[4] == "result":
                if j["status"] != "done":
                    return self._send(409, {"error": "job is not finished"})
                out: Path = j["out"]
                if j["kind"] == "remediate":
                    patch = out.parent / "dependency_upgrades.patch"
                    return self._send(200, {"report": json.loads(out.read_text(encoding="utf-8")),
                                            "patch": patch.read_text(encoding="utf-8") if patch.exists() else ""})
                return self._send(200, body=out.read_bytes())
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._guard():
            return
        if "application/json" not in self.headers.get("Content-Type", ""):
            return self._send(415, {"error": "JSON only"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > MAX_BODY:
                return self._send(413, {"error": "request too large"})
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, json.JSONDecodeError):
            return self._send(400, {"error": "invalid JSON"})
        p = self.path.split("?")[0].rstrip("/")
        tmp = Path(tempfile.mkdtemp(prefix="scip_"))

        if p == "/api/scan":
            raw = str(body.get("path", "")).strip().strip('"')
            folder = Path(raw).expanduser() if raw else None
            if folder is None or not folder.is_dir():
                return self._send(400, {"error": "that folder does not exist"})
            folder = folder.resolve()
            jid = start_job("scan", scan_argv(folder, tmp / "scan.json", bool(body.get("history", True)),
                                              bool(body.get("offline", False))), tmp / "scan.json",
                            str(folder), bool(body.get("offline", False)))
            return self._send(202, {"job": jid})

        if p in ("/api/remediate", "/api/evaluate"):
            src = JOBS.get(str(body.get("scan_job", "")))
            if src is None or src["kind"] != "scan" or src["status"] != "done":
                return self._send(400, {"error": "scan_job must be a finished scan"})
            if p == "/api/remediate":
                out = tmp / "rem"
                jid = start_job("remediate", rem_argv(Path(src["path"]), src["out"], out, src["offline"],
                                                      bool(body.get("verify", True))), out / "report.json")
                return self._send(202, {"job": jid})
            labels = ROOT / "evaluation" / "labels" / f"{Path(src['path']).name}.yaml"
            if not labels.exists():
                return self._send(404, {"error": f"no labels for this project (expected {labels.name} in "
                                                 "evaluation/labels). Create one with: python -m evaluation.run template"})
            out = tmp / "eval.json"
            return self._send(202, {"job": start_job("evaluate", eval_argv(src["out"], labels, out), out)})
        self._send(404, {"error": "not found"})


def make_server(port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main(argv: Optional[List[str]] = None) -> None:
    ap = argparse.ArgumentParser(prog="api", description="SCIP dashboard backend")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)
    srv = make_server(args.port)
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    print(f"SCIP dashboard running at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
