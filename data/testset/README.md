# Labeled test set

Don't hand-label — pull one of these (pick ONE to start; CVEfixes is the
easiest match for Python-only real-world CVEs, OWASP Benchmark is easiest
if you want Java and a huge pre-labeled set, Juliet is the classic academic
choice with C/C++/Java):

- **CVEfixes** — https://github.com/secureIT-project/CVEfixes
  Real-world CVE-fixing commits mapped to CWE labels, multi-language.
  Ships as a SQLite DB you can query for (vulnerable_code, CWE, fixed_code).

- **OWASP Benchmark** — https://owasp.org/www-project-benchmark/
  ~2,740 labeled Java test cases across ~11 CWE categories, each tagged
  true/false positive in `expectedresults-*.csv`.

- **Juliet Test Suite** — https://samate.nist.gov/SARD/test-suites
  ~64,000 labeled C/C++/Java/C# cases, one CWE per test case, both a
  "bad" (vulnerable) and "good" (fixed) variant per case.

## Expected output format

Whichever you pick, normalize it into `data/testset/labels.json`:

```json
[
  {
    "id": "juliet-CWE89-000123",
    "file": "data/testset/snippets/juliet-CWE89-000123.py",
    "cwe": "CWE-89",
    "vulnerable": true
  },
  {
    "id": "juliet-CWE89-000123-fixed",
    "file": "data/testset/snippets/juliet-CWE89-000123-fixed.py",
    "cwe": null,
    "vulnerable": false
  }
]
```

Put the actual code snippets under `data/testset/snippets/`. `evaluate.py`
(Phase 6) will read `labels.json` and run each `file` through the pipeline.

For the first ~50-sample eval pass (Phase 4), just take a random stratified
slice of whichever dataset you picked — a handful of vulnerable + safe
snippets across a few different CWE categories is enough to sanity-check
the pipeline before scaling up.
