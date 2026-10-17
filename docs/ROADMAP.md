# Roadmap and status

`[x]` done, `[~]` partly, `[ ]` not started.

- [x] Step 0  Setup + test targets
- [x] Step 1  Finding schema + pipeline
- [x] Step 2  Dependency engine - OSV + EPSS + KEV + CVSS
- [x] Step 3  Secrets engine - regex + entropy + git history
- [x] Step 4  Crypto & network misuse engine (+ Bandit and Semgrep wrappers)
- [x] Step 5  Git churn (+ code health)
- [x] Step 6  Blast radius + reachability (entry points, call graph, attack paths)
- [x] Step 7  Risk graph + SQLite cache
- [x] Step 8  Scoring + explanations
- [x] Trust fixes: untrusted-repo config, credential redaction, evidence-based false-positive labels
- [ ] Step 9  Remediation + verification (rule-based fixes, re-scan + tests before "verified")
- [~] Step 10 CLI done; HTML report / dashboard not started
- [ ] Step 11 Evaluation (CVSS-only vs risk score, ablation, labelled reachability, comparison with gitleaks/Bandit/osv-scanner)
- [ ] LLM triage - opt-in second opinion that demotes but never deletes; judged by "real findings wrongly suppressed = 0"
- [ ] Step 12 Report + viva

## Known limitations (state these in the report)

- Python only; static analysis only. Dynamic dispatch, plugins and `getattr` are invisible to the call graph,
  which is why dead code is labelled at most MEDIUM and never hidden by `--hide-fp`.
- The package-name -> import-name and transitive-dependency tables (`core/pkg_alias.py`) are curated, not
  complete. Unknown packages are `UNKNOWN`, never `DEAD`.
- Secret validity is never checked (that would mean testing leaked credentials against live services).
- Semgrep support is untested in CI unless Semgrep is installed.
