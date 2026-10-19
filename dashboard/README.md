# SCIP dashboard

`index.html` is one self-contained page. `api/` is the small local backend that makes it functional.

## Run it

    python -m api                 # opens http://127.0.0.1:8000

* **Scan page:** pick `vulpy`, `pygoat` or paste any folder path, then Scan. The real scanners run; progress is shown live.
* **Remediation page:** "Run remediation" plans library upgrades on a copy of the project, re-scans, and shows the patch.
* **Evaluation page:** "Run evaluation" scores the scan against `evaluation/labels/<folder name>.yaml` if it exists.
* The pygoat sample (scan, remediation, evaluation) is built in and shown until you scan something.
* Opening `index.html` directly (no backend) still works for the sample and for loading a saved `scan.json`.

## Safety

The backend listens on 127.0.0.1 only, accepts JSON only, checks the Host header, and starts tools without a shell.
It never modifies the scanned project: remediation works on a copy and only produces a patch file.
