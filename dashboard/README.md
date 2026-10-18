# SCIP dashboard (v1)

A single self-contained page: `index.html`. Open it in a browser (internet is needed once for the font).

Pages: Overview, Findings, Finding detail, Remediation, Evaluation, Scan.

* It ships with the pygoat scan, remediation report and evaluation numbers embedded.
* To view your own scan: `python -m core.pipeline <project> -o scan.json`, then use the Scan page to load `scan.json`
  (the file is read in the browser and never uploaded).
* Starting scans from the page needs the API (`api/`), which is not built yet.
