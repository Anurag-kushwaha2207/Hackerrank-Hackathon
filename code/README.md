# Ghost Data Still Exists audit agent

This folder contains the runnable audit program and evaluation reports. Keep the
challenge-provided `dataset/` folder beside `code/` in the project root; dataset
files are inputs and should not be included in the submission archive.

## Run

From the project root, with Python 3.10 or newer:

```powershell
python -m pip install -r code\requirements.txt
python -m pip install -r code\requirements-ocr.txt
python code\main.py
```

The second install enables OCR for screenshot evidence. PDF text extraction is
included in the base requirements. The program writes `output.csv` in the
project root; an alternate output or request file can be selected with
`--output` and `--requests`.

To run the public sample checks:

```powershell
python code\evaluation\main.py
```

The audit is deterministic and makes no model/API calls. It resolves current
and historical identifiers, reads time-bounded evidence in SQL, JSON, text,
logs, PDFs, and (with the OCR extra) images, applies the supplied treatment
rules, and emits ordered findings/remediation/verification steps. Log records
are correlated by request/trace ID so an identity-bearing query can be linked
to its resource result. Full-scope SQL and JSON snapshots can establish
evidence-backed absence only when both the evidence capture and snapshot time
are at or before the case's `audit_at`.
Structured JSON logs retain their event fields, replica system names normalize
to canonical services, and identity-link activity alone is not treated as
proof that a deletable record exists. Identity links join to actual evidence
only by exact resource ID. Empty SQL tables provide table-scoped snapshot
coverage; account activity is used only to correlate a likely resource with a
request, while the activity result itself is never accepted as proof of
deletion.

## Package

Create `code.zip` from the project root with the `code/` folder only. Do not
include `dataset/`, generated `output.csv`, Python caches, or local
environments. The evaluation report and usage report are already under
`code/evaluation/`.
