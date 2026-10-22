"""PR suggestions are built from the real files and the AST patchers, never from Bandit's numbered evidence."""
import ast
import json
from unittest.mock import MagicMock, patch

from core.finding import Finding
from core.suggestions import generate_code_suggestion, generate_suggestions
from scripts.github_pr_bot import run_pr_bot

NUMBERED = "28 29     app.run(debug=True, host='0.0.0.0')"          # how the Bandit engine really records evidence


def bandit(tid, line, file="app.py", evidence=NUMBERED):
    return Finding(engine="bandit", title=tid, file=file, line=line, severity=5.0, evidence=evidence,
                   extra={"test_id": tid})


def dep(vid, fixed, line=1, pkg="django", ver="4.2", file="requirements.txt"):
    return Finding(engine="dependency", title=f"{vid}: {pkg}=={ver}", file=file, line=line, severity=7.0,
                   evidence=f"{pkg}=={ver}", extra={"package": pkg, "version": ver, "vuln_id": vid, "fixed_version": fixed})


def repo(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_bytes(text.encode("utf-8"))
    return tmp_path


def apply(text, s):
    lines = text.splitlines(keepends=True)
    lines[s.line - 1:(s.end_line or s.line)] = [s.replacement + "\n"]
    return "".join(lines)


def test_numbered_bandit_evidence_gives_a_clean_indented_line(tmp_path):
    src = 'from flask import Flask\napp = Flask(__name__)\nif __name__ == "__main__":\n    app.run(debug=True, host="0.0.0.0")\n'
    r = repo(tmp_path, {"app.py": src})
    s = generate_suggestions([bandit("B201", 4)], r)
    assert [(x.line, x.replacement) for x in s] == [(4, '    app.run(debug=False, host="0.0.0.0")')]
    ast.parse(apply(src, s[0]))


def test_multiline_call_becomes_a_multiline_suggestion_that_still_parses(tmp_path):
    src = 'import requests\nr = requests.get(\n    "https://example.com/x",\n    params={"a": 1},\n)\n'
    r = repo(tmp_path, {"a.py": src})
    s = generate_suggestions([bandit("B113", 2, "a.py")], r)
    assert len(s) == 1 and "timeout=10" in s[0].replacement
    assert s[0].replacement.startswith('    params={"a": 1},')                  # an insertion: previous line + new line
    patched = apply(src, s[0])
    ast.parse(patched)
    assert patched.count("\n") == src.count("\n") + 1 and patched.index("timeout=10") < patched.index(")\n")


def test_one_dependency_suggestion_per_pin_with_the_highest_fix_and_the_line_preserved(tmp_path):
    r = repo(tmp_path, {"requirements.txt": "pillow[x]==9.4.0 ; python_version>'3'\ndjango==4.2  # web\n"})
    fs = [dep("A", "4.2.5", 2), dep("B", "4.2.16", 2), dep("C", "5.0", 2, "pillow", "9.4.0")]
    s = generate_suggestions(fs, r)
    assert [(x.line, x.replacement) for x in s] == [(2, "django==4.2.16  # web")]       # one per pin, not '>=' and no lost comment
    assert "2 known vulnerabilities" in s[0].explanation


def test_major_jumps_are_not_offered_for_one_click_merge(tmp_path):
    r = repo(tmp_path, {"requirements.txt": "django==3.2.18\n"})
    assert generate_suggestions([dep("A", "5.2", 1, "django", "3.2.18")], r) == []


def test_secrets_and_unfixable_rules_get_no_suggestion(tmp_path):
    r = repo(tmp_path, {"a.py": 'KEY = "s3cr3t-value"\nx = random.random()\n'})
    fs = [Finding(engine="secrets", title="s", file="a.py", line=1, severity=6.0, extra={"rule": "hardcoded-secret"}),
          bandit("B311", 2, "a.py")]
    assert generate_suggestions(fs, r) == []


def test_paths_outside_the_repo_are_ignored(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("app.run(debug=True)\n", encoding="utf-8")
    inner = tmp_path / "repo"
    inner.mkdir()
    assert generate_suggestions([bandit("B201", 1, "../outside.py")], inner) == []


def test_legacy_single_finding_function_rejects_numbered_evidence_without_a_repo():
    assert generate_code_suggestion(bandit("B201", 29)) is None                       # was: '28 29 app.run(debug=False...)'
    clean = bandit("B201", 29, evidence="app.run(host='0.0.0.0', debug=True)")
    assert "debug=False" in generate_code_suggestion(clean).replacement               # Roshan's clean-evidence path still works


def test_legacy_function_uses_the_real_file_when_a_repo_is_given(tmp_path):
    src = 'if True:\n    app.run(debug=True)\n'
    r = repo(tmp_path, {"app.py": src})
    s = generate_code_suggestion(bandit("B201", 2), str(r))
    assert s.replacement == "    app.run(debug=False)"


@patch("scripts.github_pr_bot.GitHubClient")
def test_bot_posts_verified_suggestions_once_per_line(mock_client_cls, tmp_path):
    client = MagicMock()
    mock_client_cls.return_value = client
    client.get_pr_comments.return_value = []
    r = repo(tmp_path, {"app.py": 'if True:\n    app.run(debug=True)\n', "requirements.txt": "django==4.2  # web\n"})
    fs = [bandit("B201", 2), dep("A", "4.2.5"), dep("B", "4.2.16")]
    ff = tmp_path / "findings.json"
    ff.write_text(json.dumps([f.to_dict() for f in fs]), encoding="utf-8")
    assert run_pr_bot(token="t", repo="o/r", pr_number=1, commit_sha="abc", findings_file=ff, enable_comment=True,
                      enable_suggestions=True, repo_path=r) == 0
    comments = client.submit_pull_review.call_args.kwargs["comments"]
    bodies = {c["path"]: c["body"] for c in comments}
    assert len(comments) == 2 and "    app.run(debug=False)" in bodies["app.py"] and "```suggestion" in bodies["app.py"]
    assert "django==4.2.16  # web" in bodies["requirements.txt"] and "28 29" not in json.dumps(comments)
