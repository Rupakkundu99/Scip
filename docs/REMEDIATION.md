# Remediation (slice 1: dependency upgrades)

SCIP turns dependency findings into a **reviewed, verified upgrade patch**. It never edits your repository.

## How it works

1. **Plan** (`remediation/plan.py`). For each pinned line such as `Django==4.2`, take every vulnerability found on it
   and choose the *lowest version that fixes all of them* (the highest of the per-CVE fixed versions).
   * `patch`/`minor` jumps are planned automatically.
   * `major` jumps (for example 3.x -> 4.x) are listed as **needs manual review** and not applied unless `--allow-major`.
   * Pins with no known fixed version are listed under **no known fix**, never hidden.
2. **Apply to a copy** (`remediation/apply.py`). The repo is copied to `remediation_out/workspace` (without `.git`,
   virtualenvs or caches). Only the version number on `name==version` lines of `requirements*.txt` is changed;
   comments, extras, markers and line endings are kept. Hash-pinned lines, unexpected lines and other file
   types are skipped with a reason. The output is `dependency_upgrades.patch`.
3. **Verify** (`remediation/verify.py`):
   * **Re-scan** the patched copy: targeted vulnerabilities must be gone and no new ones may appear.
   * **Tests** (optional): run your test command inside a *fresh virtualenv built from the upgraded requirements*.

| Status | Meaning |
|---|---|
| `verified` | re-scan clean **and** your tests passed in a fresh venv with the upgraded packages |
| `scan_only` | re-scan clean, but no tests (or tests ran against the OLD installed packages). Not proven safe |
| `needs_review` | some vulnerabilities remain, or the new version has its own advisories |
| `tests_failed` | your tests failed with the upgraded packages |
| `nothing_applied` | no edit was safe to make |

## Commands

```
python -m core.pipeline <repo> -o scan.json
python -m remediation.run <repo> --scan scan.json                     # plan + patch only
python -m remediation.run <repo> --scan scan.json --verify            # + re-scan the patched copy (needs network)
python -m remediation.run <repo> --scan scan.json --verify --test-cmd "pytest -q" --venv
git apply remediation_out/dependency_upgrades.patch                   # after you have read the patch
```

## Honest limits

* Only `requirements*.txt` pins are edited automatically (pyproject, Poetry and Pipfile locks are reported, not edited).
* `verified` means "scan clean and your own tests pass". It is only as strong as your test suite; a project with no
  tests can reach `scan_only` at best.
* The target version is the highest *fixed* version OSV lists; the new version may have new advisories, which is why the
  re-scan checks for introduced vulnerabilities.
* Fixes for secrets and code patterns (weak hash, `debug=True`) are not automated yet; see the roadmap.


## Code fixes (Bandit)

`python -m remediation.run` also applies Roshan's syntax-aware code patcher (`remediation/code_patcher.py`) to Bandit
findings that have an automatic fix, on the same copy of the project as the library upgrades. Output: `code_fixes.patch`.
Use `--no-code` to skip it.

| Tier | Meaning |
|---|---|
| `mechanical` | safe by construction (for example `debug=True` to `debug=False`) |
| `needs_review` | a human must read it (for example the value of an added `timeout=`) |

Findings whose rule has no automatic fix (weak random, MD5, `/tmp` paths and others) are listed as "explained only".

**Re-scan check** (`--verify`): Bandit scans the ORIGINAL and the PATCHED copy with the same settings. Every fixed finding
must be gone, nothing new may appear, and every patched file must still parse. If Bandit cannot run, the status is
`scan_unavailable` and the fixes are reported as NOT confirmed. Statuses: `verified` (re-scan clean and tests passed in a
fresh venv), `scan_only`, `needs_review`, `tests_failed`, `scan_unavailable`, `nothing_applied`.


### Fixes for Semgrep, crypto and secrets findings

| Finding | Fix | Tier |
|---|---|---|
| Semgrep `unsafe-load` | `yaml.load` to `yaml.safe_load` (reuses the Bandit B506 patcher) | per patcher |
| Semgrep `unverified-ssl` | `verify=False` to `verify=True` (B501 patcher) | per patcher |
| Semgrep `weak-hash`, crypto `weak-hash-md5/sha1` | `hashlib.md5/sha1` to `sha256` (B303 patcher), only for checksum or general use | needs_review |
| crypto `cleartext-http` | `http://` to `https://` for public hosts; local and private addresses are skipped with a reason | needs_review |
| secrets (current Python files) | the literal becomes `os.environ["NAME"]`, `import os` is added, names go into `.env.example` | needs_review |

Not auto-fixed (explained only): password hashing with MD5/SHA-1 (SHA-256 is also a fast hash; use Argon2, bcrypt or scrypt),
Semgrep SQL injection, `shell=True`, `eval`, `tempfile.mktemp`, and secrets that only exist in git history or non-Python files.

**Secrets are handled with extra care.** A patch must contain the old value to be applicable, so it is written only to
`secret_fixes.patch`, a local file marked as containing secrets. Reports, the dashboard and `code_fixes.display.patch`
mask every secret value, including a neighbouring secret that appears as patch context. After applying, **rotate the
secret**: it is still valid and remains in git history.


## Pull-request suggestions

The PR bot's one-click suggestions (`core/suggestions.py`) are built from the real file with the same AST patchers, so a suggested
line is exactly what the verified patch would write (indentation, comments, markers and multi-line calls preserved). They are not
built from `finding.evidence`: Bandit's evidence is a numbered multi-line snippet that cannot be pasted back into the code.

* Library pins: one suggestion per pinned line, to the lowest version that fixes every CVE on it. Major jumps and secrets get none.
* A fix that adds a line (for example `timeout=10,` in a multi-line call) is offered as the previous line plus the new line.
* A suggestion is only offered where the patcher produced a change; GitHub also requires the line to be part of the PR diff.
