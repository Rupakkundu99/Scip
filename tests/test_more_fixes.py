"""Tests for fixes of the other engines: Semgrep/crypto aliases, https patcher, secrets -> environment variables."""
import json
from pathlib import Path

import pytest

from remediation.code_fix import count_by_rule, edit_sources, not_automated, select_code_findings, verify_code
from remediation.code_patcher import apply_code_patches
from remediation.more_fixes import SECRET_ID, apply_secret_fixes, select_secret_findings, source_rule
from remediation.run import main

SECRET = "s3cr3t-Value-9f2"


def sg(rule, line, file="a.py"):
    return {"engine": "semgrep", "file": file, "line": line, "title": f"Semgrep {rule}: x",
            "extra": {"check_id": f"scip.python.x.{rule}"}}


def cr(rule, line, file="a.py", **x):
    return {"engine": "crypto", "file": file, "line": line, "title": "t", "extra": {"rule": rule, **x}}


def sec(line, var, file="a.py", **x):
    return {"engine": "secrets", "file": file, "line": line, "title": "Hard-coded secret",
            "extra": {"rule": "hardcoded-secret", "variable": var, "in_working_tree": True, **x}}


def mkrepo(tmp_path, files):
    r = tmp_path / "repo"
    r.mkdir(parents=True)
    for name, text in files.items():
        (r / name).write_bytes(text.encode("utf-8"))
    return r


# ------------------------------------------------------------------ selection and aliases
def test_semgrep_and_crypto_findings_map_to_the_matching_patchers():
    fs = [sg("unsafe-load", 1), sg("unverified-ssl", 2), sg("weak-hash", 3), cr("weak-hash-md5", 4),
          cr("cleartext-http", 5), sg("subprocess-shell", 6), sg("formatted-query", 7)]
    ids = [f["extra"]["test_id"] for f in select_code_findings(fs)]
    assert ids == ["B506", "B501", "B303", "B303", "SCIP-HTTP"]
    assert not_automated(fs) == {"semgrep subprocess-shell": 1, "semgrep formatted-query": 1}


def test_password_hashing_is_never_auto_fixed_with_another_fast_hash():
    f = cr("weak-hash-md5", 1, context="password")
    assert select_code_findings([f]) == [] and not_automated([f]) == {"crypto weak-hash-md5": 1}
    assert select_code_findings([cr("weak-hash-md5", 1, context="checksum")])
    assert select_code_findings([cr("weak-hash-md5", 1)])               # older scans have no context


def test_the_same_line_reported_by_two_engines_is_fixed_once():
    b = {"engine": "bandit", "file": "a.py", "line": 1, "extra": {"test_id": "B506"}}
    assert len(select_code_findings([b, sg("unsafe-load", 1)])) == 1


def test_source_rule_reads_every_engine():
    assert source_rule(sg("unsafe-load", 1)) == ("semgrep", "unsafe-load")
    assert source_rule({"engine": "semgrep", "title": "Semgrep eval-exec: x", "extra": {}}) == ("semgrep", "eval-exec")
    assert source_rule(cr("cleartext-http", 1)) == ("crypto", "cleartext-http")
    assert source_rule(sec(1, "k")) == ("secrets", "hardcoded-secret")


# ------------------------------------------------------------------ applying them
CODE = ('import yaml, hashlib, requests\n'
        'cfg = yaml.load(open("c.yml"), yaml.Loader)\n'
        'h = hashlib.md5(b"x").hexdigest()\n'
        'r1 = requests.get("http://example.com/api")\n'
        'r2 = requests.get("http://127.0.0.1:5000/api")\n'
        'r3 = requests.get(url, verify=False)\n'
        'NS = "http://www.w3.org/2000/svg"\n')


def test_alias_fixes_are_applied_by_the_existing_patchers(tmp_path):
    r = mkrepo(tmp_path, {"a.py": CODE})
    fs = select_code_findings([sg("unsafe-load", 2), cr("weak-hash-md5", 3), cr("cleartext-http", 4),
                               cr("cleartext-http", 5), sg("unverified-ssl", 6), cr("cleartext-http", 7)])
    res = apply_code_patches(r, fs, tmp_path / "ws")
    new = (res.workspace / "a.py").read_text(encoding="utf-8")
    assert "yaml.safe_load(" in new and "hashlib.sha256(" in new and 'requests.get("https://example.com/api")' in new
    assert "verify=True" in new
    assert "http://127.0.0.1:5000/api" in new and 'NS = "http://www.w3.org/2000/svg"' in new     # untouched
    skipped = {e.line: e.reason for e in res.skipped}
    assert "local or private" in skipped[5] and 7 in skipped
    assert (r / "a.py").read_text(encoding="utf-8") == CODE


# ------------------------------------------------------------------ secrets
def test_secret_literals_become_environment_variables_and_values_never_reach_records(tmp_path):
    src = ('"""Doc."""\r\nfrom __future__ import annotations\r\n\r\n@deco\r\ndef f():\r\n    return 1\r\n\r\n'
           f'SECRET_KEY = "{SECRET}"\r\nCONF = {{"password": "pw-1", "n": 1}}\r\nx = connect(user="bob", password="pw-2")\r\n')
    r = mkrepo(tmp_path, {"a.py": src})
    fs = [sec(8, "SECRET_KEY"), sec(9, "password"), sec(10, "password")]
    res = apply_secret_fixes(r, fs)                    # patches in place: pass a copy in real use
    new = (r / "a.py").read_bytes().decode()
    assert 'SECRET_KEY = os.environ["SECRET_KEY"]' in new and "pw-1" not in new and "pw-2" not in new
    assert new.index("import os") > new.index("from __future__") and new.index("import os") < new.index("@deco")
    assert "\r\n" in new and "\n" not in new.replace("\r\n", "")                        # CRLF preserved
    assert sorted(res.env_names) == ["PASSWORD", "PASSWORD_2", "SECRET_KEY"]            # different values, own names
    raw = json.dumps([e.to_dict() for e in res.edits])
    assert not any(v in raw for v in (SECRET, "pw-1", "pw-2"))
    assert all(e.applied and e.tier == "needs_review" and "ROTATE" in e.review_note for e in res.edits)
    assert SECRET in res.diff                                                            # the real patch must contain it
    assert (r / ".env.example").read_text(encoding="utf-8").splitlines() == ["PASSWORD=", "PASSWORD_2=", "SECRET_KEY="]
    compile(new, "a.py", "exec")


def test_existing_import_os_and_env_example_are_not_duplicated(tmp_path):
    r = mkrepo(tmp_path, {"a.py": f'import os\nTOKEN = "{SECRET}"\n', ".env.example": "TOKEN=\nOTHER=1\n"})
    res = apply_secret_fixes(r, [sec(2, "TOKEN")])
    assert (r / "a.py").read_text(encoding="utf-8").count("import os") == 1
    assert (r / ".env.example").read_text(encoding="utf-8") == "TOKEN=\nOTHER=1\n"
    assert res.edits[0].applied


@pytest.mark.parametrize("code,reason", [
    ('KEY = "a" + "b"\n', "no simple"),
    ('KEY = f"{x}abc"\n', "no simple"),
    ('KEY = ""\n', "no simple"),
    ("def broken(:\n", "does not parse")])
def test_secrets_that_cannot_be_fixed_safely_are_skipped_with_a_reason(tmp_path, code, reason):
    r = mkrepo(tmp_path, {"a.py": code})
    res = apply_secret_fixes(r, [sec(1, "KEY")])
    assert not res.edits[0].applied and reason in res.edits[0].reason
    assert (r / "a.py").read_text(encoding="utf-8") == code and not (r / ".env.example").exists()


def test_only_current_python_non_test_secrets_are_selected():
    fs = [sec(1, "a"), sec(1, "a", file="a.js"), sec(1, "a", in_working_tree=False),
          sec(1, "a", is_test_file=True), {"engine": "bandit", "file": "a.py", "line": 1}]
    assert [f["file"] for f in select_secret_findings(fs)] == ["a.py"] and len(select_secret_findings(fs)) == 1
    assert not_automated(fs)["secrets hardcoded-secret"] == 3


# ------------------------------------------------------------------ verification and CLI
def test_verification_confirms_semgrep_and_secret_fixes_using_the_source_engine(tmp_path):
    r = mkrepo(tmp_path, {"a.py": f'import yaml\nKEY = "{SECRET}"\ncfg = yaml.load(f, yaml.Loader)\n'})
    code = select_code_findings([sg("unsafe-load", 3)])
    secrets = [sec(2, "KEY")]
    cres = apply_code_patches(r, code, tmp_path / "ws")
    sres = apply_secret_fixes(cres.workspace, secrets)
    from remediation.code_patcher import CodePatchResult
    both = CodePatchResult(workspace=cres.workspace, diff=cres.diff, edits=cres.edits + sres.edits)

    def scan(path):
        t = (Path(path) / "a.py").read_text(encoding="utf-8")
        return ([sg("unsafe-load", 3)] if "yaml.load(" in t else []) + ([sec(2, "KEY")] if SECRET in t else [])
    v = verify_code(both, r, scan, sources=edit_sources(code, secrets))
    assert v.status == "scan_only" and v.confirmed_count == 2 and not v.remaining and not v.introduced
    assert sorted(v.confirmed) == ["secrets hardcoded-secret a.py", "semgrep unsafe-load a.py"]


def test_cli_fixes_all_engines_on_one_copy_and_keeps_secrets_out_of_the_report(tmp_path, capsys):
    r = mkrepo(tmp_path, {"app.py": f'import yaml\nKEY = "{SECRET}"\ncfg = yaml.load(f, yaml.Loader)\n'})
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps([sg("unsafe-load", 3, "app.py"), sec(2, "KEY", "app.py")]), encoding="utf-8")
    out = tmp_path / "out"

    def fake(path):
        t = (Path(path) / "app.py").read_text(encoding="utf-8")
        return ([sg("unsafe-load", 3, "app.py")] if "yaml.load(" in t else []) + (
            [sec(2, "KEY", "app.py")] if SECRET in t else [])
    assert main([str(r), "--scan", str(scan), "--out", str(out), "--verify"], scan_fn=lambda p: [],
                code_scan_fn=fake) == 0
    final = (out / "workspace_final" / "app.py").read_text(encoding="utf-8")
    assert "yaml.safe_load(" in final and 'os.environ["KEY"]' in final and SECRET not in final
    assert (r / "app.py").read_text(encoding="utf-8").count(SECRET) == 1                   # original untouched
    sp = (out / "secret_fixes.patch").read_text(encoding="utf-8")
    assert sp.startswith("# CONTAINS SECRET VALUES") and SECRET in sp
    assert SECRET in (out / "code_fixes.patch").read_text(encoding="utf-8")        # local file stays exact (context line)
    shown = (out / "code_fixes.display.patch").read_text(encoding="utf-8")         # what the dashboard receives
    assert SECRET not in shown and "********" in shown and "safe_load" in shown
    assert SECRET not in (out / "report.json").read_text(encoding="utf-8")
    assert SECRET not in capsys.readouterr().out
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))["code"]
    assert rep["verification"]["confirmed_count"] == 2 and "Rotate" in rep["warnings"][0]
    assert {e["source_engine"] for e in rep["applied"]} == {"semgrep", "secrets"}


def test_a_secret_in_the_context_of_a_code_fix_is_masked_in_every_report_record(tmp_path):
    from remediation.more_fixes import collect_secret_values, redact
    r = mkrepo(tmp_path, {"a.py": f'import requests\nr = requests.get(u, headers={{"X-Key": "{SECRET}"}})\n'})
    vals = collect_secret_values(r, [sec(2, "X-Key")])
    assert vals == [SECRET] and SECRET not in redact(f"-  x = '{SECRET}'", vals)
    fs = select_code_findings([{"engine": "bandit", "file": "a.py", "line": 2, "extra": {"test_id": "B113"}}])
    res = apply_code_patches(r, fs, tmp_path / "ws")
    from remediation.run import build_code_report
    rep = build_code_report(res, None, [], edit_sources(fs), vals)
    assert SECRET in res.edits[0].original and SECRET not in json.dumps(rep) and "********" in rep["applied"][0]["original"]


def test_non_bandit_patchers_are_well_formed_and_do_not_collide_with_bandit_ids():
    from remediation.code_patcher import RULE_PATCHERS
    extra = {k: v for k, v in RULE_PATCHERS.items() if k.startswith("SCIP-")}
    assert "SCIP-HTTP" in extra
    for k, v in extra.items():
        assert v.tier in ("mechanical", "needs_review") and v.review_note and v.description
    assert not any(k.startswith("SCIP-") for k in ("B101", "B113", "B201"))
