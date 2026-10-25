# Evaluation report

## Public sample results

The deterministic evaluator compares the generated predictions with
`dataset/sample_output.csv` for all 32 public requests.

| Metric | Result |
| --- | ---: |
| Case-level deletion-status accuracy | 32/32 (100.0%) |
| Step-level accuracy | 62.00% |
| Field-level accuracy | 86.92% |
| Exact sequence accuracy | 14/32 (43.75%) |

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
- Readback trace IDs with both `tr-` and `rb-` prefixes are correlated.
- Replica system names are normalized to their canonical service IDs. Catalog
  identity-link events are not treated as proof that a data record exists;
  instead, they link the subject only to actual evidence with the same resource
  ID. Direct PII fields are checked against the resolved subject rather than
  unrelated people in shared records.
- Empty SQL tables now provide explicit, table-scoped snapshot coverage. A
  unique account deletion event close to the request's reported timestamp can
  identify the resource to verify; activity results themselves are not treated
  as proof of deletion, and complete-case verification still requires a
  subsequent in-cutoff snapshot.
- Restore eligibility/deletion-block fields are interpreted as restore state,
  and compliant disabled flows or blocked restores receive the correct
  verification operation.
- Contact-index records and email opt-in records are classified according to
  their semantics so the relevant deletion policy is applied.
- A profile's business-level `account_status=DELETED` was previously liable to
  be confused with physical row deletion. The classifier now treats a row as
  present unless evidence explicitly establishes absence, such as a zero-row
  lookup or HTTP 404.
- Exact-sequence accuracy improved from 7/32 to 14/32 after these changes.
  Remaining mismatches largely involve resources that the public expected
  output associates with a person even though no participant-facing identity
  link to that resource is available by the case cutoff. The implementation
  avoids inventing those relationships or hardcoding sample-case answers.

The metrics above are from the public sample evaluator, not a hidden-label
evaluation of the 518-request set. No organizer-only answers are used.
