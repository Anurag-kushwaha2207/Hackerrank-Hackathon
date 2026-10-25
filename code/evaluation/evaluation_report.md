# Evaluation report

## Public sample results

The deterministic evaluator compares the generated predictions with
`dataset/sample_output.csv` for all 32 public requests.

| Metric | Result |
| --- | ---: |
| Case-level deletion-status accuracy | 32/32 (100.0%) |
| Step-level accuracy | 52.09% |
| Field-level accuracy | 86.43% |
| Exact sequence accuracy | 7/32 (21.88%) |

Status accuracy is strong on the public sample, but exact step sequences remain
the main weakness. Similar steps with different resource selection or ordering
are counted as mismatches; the evaluator does not grant partial credit for a
correct status.

## Additional contract cases

The focused tests in `evaluation/main.py` supplement the public sample:

1. A request to export data while keeping the account active is not a deletion
   authorization and must be `NOT_APPLICABLE`.
2. A Spanish request explicitly asking for permanent account deletion is
   authorized.
3. A request asking to remove an account profile and its personal details is
   authorized.
4. A profile row with `account_status=DELETED` is still physically present and
   must not be treated as absent solely because of that field.
5. Verification steps for a complete case must use the allowed operation,
   phase, state, and an evidence reference.

## Failures found and improvements made

- The initial full-dataset run failed validation because an authorized case
  produced `COMPLETE` without any verification steps. Added parsing of
  participant-visible SQL `snapshot_scope` contents so eligible pre-cutoff
  full-scope snapshots can support explicit absence checks for covered systems.
- Some logs used pipe-delimited trace IDs or `requestId=` instead of a
  `trace_id=` field. Trace parsing now correlates identity-bearing lookup
  events with the resource result, including separate completed/404 results.
- Structured JSON log lines are parsed as JSON instead of loose key/value
  text, preserving event fields and timestamps for reliable trace matching.
- Replica system names are normalized to their canonical service IDs. Catalog
  identity-link events are no longer treated as proof that a data record
  exists, and direct PII fields are checked against the resolved subject
  rather than unrelated people in shared records.
- A profile's business-level `account_status=DELETED` was previously liable to
  be confused with physical row deletion. The classifier now treats a row as
  present unless evidence explicitly establishes absence, such as a zero-row
  lookup or HTTP 404.
- The public sample still exposes substantial exact-step and sequence errors.
  Identity matching and parsers are deterministic, but evidence-to-resource
  resolution and complete policy coverage need further evaluation.

The metrics above are from the public sample evaluator, not a hidden-label
evaluation of the 518-request set. No organizer-only answers are used.
