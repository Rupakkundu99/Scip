"""Builds a small git repo full of FAKE secrets for demoing / testing the secrets engine.

    python scripts/make_secrets_demo.py

Creates test_repos/secrets_demo/ (git-ignored, so it never gets pushed to GitHub) with
three commits:
  1. adds config with an AWS key, a DB password URL and a private key file
  2. "fixes" it by switching to environment variables and deleting the key file
     -> the secrets are gone from the files but STILL in history
  3. adds a settings file with a hard-coded Django-style SECRET_KEY and a GitHub token
     -> these remain in the current files

Also includes lines that must NOT be flagged (placeholders, env lookups).
All secrets are random, fake, and generated at runtime.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests import fake_secrets as fs  # noqa: E402

DEST = ROOT / "test_repos" / "secrets_demo"
ENV = {**os.environ, "GIT_AUTHOR_NAME": "Demo Dev", "GIT_AUTHOR_EMAIL": "dev@example.org",
       "GIT_COMMITTER_NAME": "Demo Dev", "GIT_COMMITTER_EMAIL": "dev@example.org"}


def git(*args):
    subprocess.run(["git", "-C", str(DEST), "-c", "commit.gpgsign=false", *args],
                   check=True, capture_output=True, env=ENV)


def write(rel, text):
    p = DEST / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def main():
    if DEST.exists():
        shutil.rmtree(DEST, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    DEST.mkdir(parents=True)
    git("init", "-q")

    # --- commit 1: secrets committed by mistake --------------------------------
    write("app/config.py",
          "# Production configuration\n"
          f'AWS_ACCESS_KEY_ID = "{fs.aws_access_key_id(101)}"\n'
          f'AWS_SECRET_ACCESS_KEY = "{fs.aws_secret_key(102)}"\n'
          f'DATABASE_URL = "postgres://admin:{fs.strong_password(103)[:12]}@db.prod.internal:5432/shop"\n')
    write("deploy/id_rsa", fs.private_key_pem(104))
    write("app/main.py", "from app import config\n\n\ndef run():\n    print('starting')\n")
    git("add", "-A"); git("commit", "-q", "-m", "Initial commit")

    # --- commit 2: 'fix' - move to env vars, delete key. History still has them -
    write("app/config.py",
          "import os\n\n"
          'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n'
          'AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]\n'
          'DATABASE_URL = os.environ.get("DATABASE_URL")\n')
    (DEST / "deploy" / "id_rsa").unlink()
    git("add", "-A"); git("commit", "-q", "-m", "Move secrets to environment variables")

    # --- commit 3: new hard-coded secrets that stay in the files ---------------
    write("app/settings.py",
          "DEBUG = True\n"
          f'SECRET_KEY = "django-insecure-{fs.random_token(105, 45)}"\n'
          f'GITHUB_TOKEN = "{fs.github_token(106)}"\n'
          'ADMIN_PASSWORD = "admin"\n'
          '\n# --- the lines below must NOT be flagged ---\n'
          'API_KEY = "your_api_key_here"\n'
          'PASSWORD_FIELD = "password"\n'
          'STRIPE_KEY = os.environ["STRIPE_KEY"]\n'
          'TOKEN_URL = "https://example.com/oauth/token"\n')
    git("add", "-A"); git("commit", "-q", "-m", "Add settings")

    print(f"Demo repo created at: {DEST}")
    print(f"Now run:  python -m core.pipeline {DEST.relative_to(ROOT)} --no-history   (current files only)")
    print(f"     and: python -m core.pipeline {DEST.relative_to(ROOT)}                (with git history)")


if __name__ == "__main__":
    main()
