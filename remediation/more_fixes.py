"""Fixes for the other engines (Semgrep, crypto, secrets), built on the Bandit patcher's machinery.

1. ALIASES: a Semgrep or crypto finding that means the same thing as a Bandit rule reuses Roshan's AST patcher.
2. SCIP-HTTP: a new call patcher in the same style ('http://' to 'https://' for non-local hosts).
3. apply_secret_fixes(): hard-coded string -> os.environ["NAME"], plus .env.example. Secret VALUES never appear in
   any record or report: the real patch (which must contain the old value to be applicable) goes to a local file only.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .code_patcher import (RULE_PATCHERS, CodeEditRecord, PatchStatus, PatchTier, RulePatcher, _extract_file,
                           _extract_line, _extract_test_id, format_unified_diff, get_node_span, safe_resolve_target,
                           split_python_lines)

SECRET_ID = "SCIP-SECRET"
ALIASES: Dict[Tuple[str, str], str] = {
    ("semgrep", "unsafe-load"): "B506",          # yaml.load -> yaml.safe_load
    ("semgrep", "unverified-ssl"): "B501",       # verify=False -> verify=True
    ("semgrep", "weak-hash"): "B303",            # hashlib.md5/sha1 -> sha256
    ("crypto", "weak-hash-md5"): "B303",
    ("crypto", "weak-hash-sha1"): "B303",
    ("crypto", "cleartext-http"): "SCIP-HTTP",   # defined below
}


def _attr(f: Any, name: str, default: Any = "") -> Any:
    return f.get(name, default) if isinstance(f, dict) else getattr(f, name, default)


def _extra(f: Any) -> Dict[str, Any]:
    return _attr(f, "extra", None) or {}


def source_rule(f: Any) -> Tuple[str, str]:
    """(engine, rule) of any finding: Bandit test id, Semgrep rule name, crypto/secrets rule."""
    eng = str(_attr(f, "engine"))
    if eng == "bandit":
        return eng, _extract_test_id(f)
    x = _extra(f)
    if eng == "semgrep":
        cid = str(x.get("check_id") or "")
        if cid:
            return eng, cid.rsplit(".", 1)[-1]
        m = re.match(r"\s*Semgrep\s+([\w.-]+):", str(_attr(f, "title")))
        return eng, m.group(1) if m else ""
    return eng, str(x.get("rule") or "")


def patcher_id(f: Any) -> str:
    """Id of the RULE_PATCHERS entry that can fix this finding, or ''."""
    eng, rule = source_rule(f)
    if eng == "crypto" and rule.startswith("weak-hash") and _extra(f).get("context") == "password":
        return ""     # sha256 is also a fast hash: passwords need Argon2/bcrypt/scrypt, which is a design change
    pid = rule if eng == "bandit" else ALIASES.get((eng, rule), "")
    return pid if pid in RULE_PATCHERS else ""


# ---------------------------------------------------------------- SCIP-HTTP patcher
_LOCAL = re.compile(r"^(localhost|127\.|0\.0\.0\.0|::1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|.*\.(local|internal|localdomain)$)",
                    re.I)


def _http_consts(call: ast.Call) -> List[ast.Constant]:
    vals = list(call.args) + [k.value for k in call.keywords]
    return [v for v in vals if isinstance(v, ast.Constant) and isinstance(v.value, str)
            and v.value.lower().startswith("http://")]


def _patch_http(src: str, call: ast.Call) -> Tuple[Optional[str], str]:
    why = "no http:// URL argument found"
    for c in _http_consts(call):
        host = c.value[7:].split("/", 1)[0].split("?", 1)[0]
        host = host.rsplit("@", 1)[-1].split(":", 1)[0] if not host.startswith("[") else "::1"
        if _LOCAL.match(host):
            why = f"{host} is a local or private address; HTTPS may not be available there"
            continue
        s, e = get_node_span(src, c)
        i = src[s:e].lower().find("http://")
        if i >= 0:
            return src[:s + i] + "https://" + src[s + i + 7:], ""
    return None, why


RULE_PATCHERS["SCIP-HTTP"] = RulePatcher(
    test_id="SCIP-HTTP", tier=PatchTier.NEEDS_REVIEW.value,
    description="Use https:// instead of http:// in a network call to a public host.",
    patch_fn=_patch_http, call_filter=lambda c: bool(_http_consts(c)),
    review_note="Check that the server supports HTTPS with a valid certificate.")


# ---------------------------------------------------------------- secrets
@dataclass
class SecretFixResult:
    workspace: Path
    diff: str = ""
    edits: List[CodeEditRecord] = field(default_factory=list)
    env_names: List[str] = field(default_factory=list)


def select_secret_findings(findings: Iterable[Any]) -> List[Dict[str, Any]]:
    """Secrets present in the current files (history-only findings have nothing to patch)."""
    return [f for f in findings if _attr(f, "engine") == "secrets" and _extra(f).get("in_working_tree") is not False
            and str(_attr(f, "file")).endswith(".py") and not _extra(f).get("is_test_file")]


def collect_secret_values(repo: Path, findings: Iterable[Any]) -> List[str]:
    """String values of every hard-coded secret in the ORIGINAL project (Python files), longest first.

    Used only to mask them in anything shown or reported: patch context lines and 'before' lines can contain a
    neighbouring secret even when that secret is not the one being fixed.
    """
    vals = set()
    by_file: Dict[str, List[int]] = {}
    for f in findings:
        if _attr(f, "engine") == "secrets" and str(_attr(f, "file")).endswith(".py") and _extract_line(f):
            by_file.setdefault(str(_attr(f, "file")).replace("\\", "/"), []).append(_extract_line(f))
    for rel, lines in by_file.items():
        try:
            tree = ast.parse((Path(repo) / rel).read_bytes().decode("utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for ln in lines:
            for c, _ in _literals_on_line(tree, ln):
                if len(c.value) >= 4:
                    vals.add(c.value)
    return sorted(vals, key=len, reverse=True)


def redact(text: str, values: Iterable[str]) -> str:
    for v in values:
        text = text.replace(v, "********")
    return text


def _literals_on_line(tree: ast.AST, line: int) -> List[Tuple[ast.Constant, str]]:
    found: List[Tuple[ast.Constant, str]] = []

    def add(value: Any, hint: Optional[str]) -> None:
        if (isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value
                and getattr(value, "lineno", 0) == line and getattr(value, "end_lineno", line) == line and hint):
            found.append((value, hint))
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                sl = getattr(t, "slice", None)
                sl = getattr(sl, "value", sl)                       # py3.8 ast.Index
                hint = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else (
                    sl.value if isinstance(t, ast.Subscript) and isinstance(sl, ast.Constant) else None)
                add(n.value, str(hint) if hint else None)
        elif isinstance(n, ast.keyword):
            add(n.value, n.arg)
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    add(v, k.value)
    return found


def _env_name(hint: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", hint).strip("_").upper() or "SECRET"


def _import_os_offset(text: str, tree: ast.Module) -> Optional[int]:
    for n in tree.body:
        if isinstance(n, ast.Import) and any(a.name == "os" and not a.asname for a in n.names):
            return None
    first = None
    for i, n in enumerate(tree.body):
        is_doc = i == 0 and isinstance(n, ast.Expr) and isinstance(getattr(n, "value", None), ast.Constant) \
            and isinstance(n.value.value, str)
        if is_doc or (isinstance(n, ast.ImportFrom) and n.module == "__future__"):
            continue
        first = n
        break
    if first is None:
        return len(text)
    line = min([first.lineno] + [d.lineno for d in getattr(first, "decorator_list", [])])
    return sum(len(l) for l in split_python_lines(text)[:line - 1])


def apply_secret_fixes(workspace: Path, findings: Iterable[Any]) -> SecretFixResult:
    ws = Path(workspace)
    res = SecretFixResult(workspace=ws)
    used: Dict[str, str] = {}          # env name -> digest of the value it replaced (digest only, never the value)
    by_file: Dict[str, List[Any]] = {}
    for f in findings:
        by_file.setdefault(str(_attr(f, "file")).replace("\\", "/"), []).append(f)
    note = ("Set this environment variable before running. ROTATE the secret: it is still valid and remains in "
            "the git history.")

    def rec(rel: str, f: Any, status: str, why: str = "", **kw: str) -> None:
        res.edits.append(CodeEditRecord(file=rel, line=_extract_line(f) or 0, test_id=SECRET_ID,
                                        tier=PatchTier.NEEDS_REVIEW.value, status=status, reason=why, **kw))

    diffs: List[str] = []
    for rel, fs in sorted(by_file.items()):
        target, err = safe_resolve_target(ws, rel)
        if not target or not target.exists():
            for f in fs:
                rec(rel, f, PatchStatus.FILE_NOT_FOUND.value, err or "file not found in the copy")
            continue
        text = target.read_bytes().decode("utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            for f in fs:
                rec(rel, f, PatchStatus.SYNTAX_ERROR.value, f"original does not parse: {exc}")
            continue
        edits: List[Tuple[int, int, str]] = []
        pending: List[CodeEditRecord] = []
        for f in sorted(fs, key=lambda x: -(_extract_line(x) or 0)):
            line = _extract_line(f) or 0
            lits = _literals_on_line(tree, line)
            want = str(_extra(f).get("variable") or "").lower()
            lits.sort(key=lambda t: 0 if t[1].lower() == want else 1)
            if not lits:
                rec(rel, f, PatchStatus.PATTERN_NOT_FOUND.value,
                    "no simple 'name = \"literal\"', keyword or dict value on this line; move it by hand")
                continue
            const, hint = lits[0]
            s, e = get_node_span(text, const)
            digest = hashlib.sha256(const.value.encode()).hexdigest()
            name = base = _env_name(hint)
            n = 1
            while used.get(name, digest) != digest:
                n += 1
                name = f"{base}_{n}"
            used[name] = digest
            ls = text.rfind("\n", 0, s) + 1
            le = text.find("\n", e)
            le = len(text) if le < 0 else le
            before = text[ls:le].rstrip("\r")
            lit = text[s:e]
            edits.append((s, e, f'os.environ["{name}"]'))
            pending.append(CodeEditRecord(
                file=rel, line=line, test_id=SECRET_ID, tier=PatchTier.NEEDS_REVIEW.value,
                status=PatchStatus.APPLIED.value, original=before.replace(lit, "'********'"),
                patched=before.replace(lit, f'os.environ["{name}"]'), review_note=f"{name}: {note}"))
        if not edits:
            continue
        new = text
        for s, e, repl in sorted(edits, reverse=True):
            new = new[:s] + repl + new[e:]
        off = _import_os_offset(new, ast.parse(new))
        if off is not None:
            nl = "\r\n" if "\r\n" in new else "\n"
            new = new[:off] + "import os" + nl + new[off:]
        try:
            ast.parse(new)
        except SyntaxError as exc:
            for p in pending:
                p.status, p.reason, p.patched = PatchStatus.SYNTAX_ERROR.value, f"patched file would not parse: {exc}", ""
            res.edits.extend(pending)
            continue
        target.write_bytes(new.encode("utf-8"))
        diffs.append(format_unified_diff(text, new, rel))
        res.edits.extend(pending)

    names = sorted(used)
    res.env_names = names
    if names:
        ex = ws / ".env.example"
        old = ex.read_bytes().decode("utf-8") if ex.exists() else None
        have = {l.split("=", 1)[0].strip() for l in (old or "").splitlines()}
        add = [n for n in names if n not in have]
        if add:
            nl = "\r\n" if old and "\r\n" in old else "\n"
            new_ex = (old if old is None or old.endswith(("\n", "\r\n")) or not old else old + nl) or ""
            new_ex += "".join(f"{n}={nl}" for n in add)
            ex.write_bytes(new_ex.encode("utf-8"))
            diffs.append("".join(difflib.unified_diff(
                (old or "").splitlines(keepends=True), new_ex.splitlines(keepends=True),
                "a/.env.example" if old is not None else "/dev/null", "b/.env.example")))
    res.diff = "\n".join(d for d in diffs if d)
    return res
