# Contributing

## Setup
```bash
git clone <repo-url>
cd scip
python -m venv venv
venv\Scripts\activate            # Windows   (Linux/macOS: source venv/bin/activate)
pip install -r requirements.txt
pytest                           # everything should pass before you start
```
Scan targets are not stored in the repo. Get them with `scripts\clone_test_repos.bat`
(or `bash scripts/clone_test_repos.sh`).

## Workflow
1. **Never push directly to `main`.** Make a branch per task: `git switch -c step-4-crypto-engine`
2. Commit small and often, with a message that says what and why.
3. Run `pytest` before you push. A change without a test is not finished.
4. Push the branch and open a **Pull Request**; one teammate reviews, then merge.
5. After merging, `git switch main && git pull`.

## Rules
- **Never commit real secrets**, tokens, passwords, `.env` files or personal data. If you do, tell the
  team immediately and rotate the credential: deleting the commit is not enough (git keeps history).
- Test fixtures that need token-shaped strings must build them at runtime (see `tests/fake_secrets.py`);
  GitHub blocks pushes that contain realistic-looking tokens, even fake ones.
- Save scan results with `python -m core.pipeline <repo> -o out.json` (UTF-8). Do not use `>` in
  PowerShell (it writes UTF-16). Do not commit raw scan output without checking it first.
- Keep every engine returning `Finding` objects (`core/finding.py`).
