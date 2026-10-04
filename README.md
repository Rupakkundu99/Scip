# SCIP - Secure Codebase Intelligence Platform

Detect -> Prioritize -> Improve.
A context-aware system for vulnerability discovery and guided remediation in Python repositories.

## Setup

```bash
python -m venv venv
# Windows:  venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
```

## Get test repositories

```bash
# Windows:  scripts\clone_test_repos.bat
# Linux/Mac: bash scripts/clone_test_repos.sh
```

## Run the skeleton pipeline

```bash
python -m core.pipeline test_repos/pygoat
pytest
```

## Project layout

| Folder | Purpose |
|---|---|
| engines/ | Detection engines (deps, secrets, crypto/network, churn) |
| core/ | Finding schema, pipeline, risk graph |
| scoring/ | Composite risk scoring |
| remediation/ | Fix suggestion + verification |
| api/ | Dashboard backend (FastAPI) |
| tests/ | Unit tests |
| data/ | SQLite DB, cached API responses |
| scripts/ | Helper scripts |
| docs/ | Report notes, diagrams |

## Build roadmap
See docs/ROADMAP.md
