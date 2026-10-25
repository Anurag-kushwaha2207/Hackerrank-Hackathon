#!/usr/bin/env python3
"""Run public-sample scoring and focused contract tests."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

import main as audit  # noqa: E402


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def score(expected_rows: list[dict[str, str]], actual_rows: list[dict[str, str]]) -> dict[str, float | int]:
    actual = {row["case_id"]: row for row in actual_rows}
    status_correct = 0
    sequence_correct = 0
    steps_expected = 0
    steps_correct = 0
    fields_expected = 0
    fields_correct = 0
    for expected in expected_rows:
        predicted = actual.get(expected["case_id"])
        if not predicted:
            continue
        if predicted["deletion_status"] == expected["deletion_status"]:
            status_correct += 1
        expected_steps = json.loads(expected["steps_json"])
        predicted_steps = json.loads(predicted["steps_json"])
        if predicted_steps == expected_steps:
            sequence_correct += 1
        steps_expected += max(len(expected_steps), len(predicted_steps))
        for index in range(max(len(expected_steps), len(predicted_steps))):
            if index >= len(expected_steps) or index >= len(predicted_steps):
                continue
            expected_step = expected_steps[index]
            predicted_step = predicted_steps[index]
            if predicted_step == expected_step:
                steps_correct += 1
            fields_expected += len(expected_step)
            fields_correct += sum(
                predicted_step.get(key) == value for key, value in expected_step.items()
            )
    count = len(expected_rows)
    return {
        "cases": count,
        "status_correct": status_correct,
        "status_accuracy": status_correct / count if count else 0.0,
        "sequence_correct": sequence_correct,
        "sequence_accuracy": sequence_correct / count if count else 0.0,
        "steps_expected": steps_expected,
        "step_accuracy": steps_correct / steps_expected if steps_expected else 0.0,
        "fields_expected": fields_expected,
        "field_accuracy": fields_correct / fields_expected if fields_expected else 0.0,
    }


class ContractTests(unittest.TestCase):
    def test_non_deletion_export_request_is_not_authorized(self) -> None:
        self.assertFalse(audit.classify_request(
            "Please export my data and keep my account active."
        ))

    def test_spanish_deletion_request_is_authorized(self) -> None:
        self.assertTrue(audit.classify_request(
            "Solicito la eliminación permanente de mi cuenta."
        ))

    def test_profile_removal_request_is_authorized(self) -> None:
        self.assertTrue(audit.classify_request(
            "Please remove my account profile and personal details."
        ))

    def test_audit_of_prior_deletion_is_authorized(self) -> None:
        self.assertTrue(audit.classify_request(
            "My account was meant to be deleted. Please check whether the profile is gone."
        ))

    def test_phases_and_operations_have_deterministic_order(self) -> None:
        self.assertEqual(
            sorted(
                ["VERIFICATION", "FINDING", "REMEDIATION"],
                key=audit.PHASE_ORDER.__getitem__,
            ),
            ["FINDING", "REMEDIATION", "VERIFICATION"],
        )
        self.assertLess(
            audit.OPERATION_ORDER["DISABLE_DATA_FLOW"],
            audit.OPERATION_ORDER["DELETE_RECORD"],
        )

    def test_output_contract_accepts_evidence_backed_complete_case(self) -> None:
        requests = [{"case_id": "case_test"}]
        rows = [{
            "case_id": "case_test",
            "deletion_status": "COMPLETE",
            "steps": [{
                "step_no": 1,
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": "account_test",
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": "evidence_test",
            }],
        }]
        audit.validate_output(rows, requests)

    def test_deleted_account_status_does_not_mean_profile_row_is_absent(self) -> None:
        record = audit.EvidenceRecord(
            resource_id="account_test",
            system_id="account_service",
            category="USER_PROFILE",
            values={"account_status": "DELETED", "email": "person@example.test"},
            evidence_id="evidence_test",
            captured_at="2026-01-01T00:00:00Z",
        )
        self.assertEqual(audit.status_from_record(record), "PRESENT")

    def test_full_scope_snapshot_supports_evidence_backed_absence_checks(self) -> None:
        systems = {
            "account_service",
            "analytics_platform",
            "backup_service",
            "export_service",
            "integration_service",
            "search_service",
            "security_service",
            "support_platform",
        }
        records = [
            audit.EvidenceRecord(
                resource_id=f"snapshot_scope_{system}",
                system_id=system,
                category="SNAPSHOT_SCOPE",
                values={"origin_system": system},
                evidence_id="evidence_scope",
                captured_at="2026-06-01T00:00:00Z",
            )
            for system in systems
        ]
        result = audit.audit_case(
            {
                "case_id": "case_scope",
                "email": "person@example.test",
                "audit_at": "2026-06-02T00:00:00Z",
                "request_text": "Please delete my account.",
            },
            records,
            [],
            {},
            {"person@example.test": {"user_test"}},
            {},
            [],
        )
        self.assertEqual(result["deletion_status"], "COMPLETE")
        self.assertEqual(len(result["steps"]), len(systems))
        self.assertTrue(
            all(step["evidence_id"] == "evidence_scope" for step in result["steps"])
        )

    def test_pipe_delimited_trace_context_links_resource_to_identity(self) -> None:
        record = audit.parse_text_record(
            '2026-02-03T05:53:54Z | INFO | search_service | tr-4410322 | '
            'index_query_completed | resource_id="search_2818" result="hit"',
            {"file_id": "evidence_trace", "captured_at": "2026-02-03T05:59:42Z"},
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.values["trace_id"], "tr-4410322")
        record.source_text = (
            "2026-02-03T05:53:50Z | DEBUG | search_service | tr-4410322 | "
            "index_query_started | match_key='person@example.test'\n"
            + record.source_text
        )
        subject = audit.Subject("case_trace", "person@example.test", None)
        subject.add("person@example.test")
        self.assertTrue(audit.linked_record(record, subject))

    def test_zero_row_lookup_is_absent_even_with_trace_context(self) -> None:
        record = audit.EvidenceRecord(
            resource_id="account_test",
            system_id="account_service",
            category="USER_PROFILE",
            values={"rows": "0", "http_status": "404"},
            evidence_id="evidence_lookup",
            captured_at="2026-01-01T00:00:00Z",
            source_text="profile_lookup_completed rows=\"0\" http_status=\"404\"",
        )
        self.assertEqual(audit.status_from_record(record), "ABSENT")

    def test_structured_json_log_preserves_fields_and_trace_context(self) -> None:
        record = audit.parse_text_record(
            '2026-02-03T05:53:54Z {"service":"account_service",'
            '"trace_id":"tr-4410322","resource_id":"account_1234",'
            '"event":"profile_lookup_completed","rows":"0","http_status":"404"}',
            {"file_id": "evidence_json_log", "captured_at": "2026-02-03T06:00:00Z"},
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.values["service"], "account_service")
        self.assertEqual(record.values["trace_id"], "tr-4410322")
        self.assertEqual(record.values["event_time"], "2026-02-03T05:53:54Z")
        self.assertEqual(audit.status_from_record(record), "ABSENT")

    def test_replica_names_resolve_to_canonical_system(self) -> None:
        self.assertEqual(
            audit.system_for({"service": "support_replica"}, "support_1234"),
            "support_platform",
        )

    def test_identity_link_activity_does_not_infer_record_category(self) -> None:
        subject = audit.Subject("case_link", "person@example.test", "user_07")
        subject.add("user_07")
        record = audit.activity_link_records(
            [{
                "event_type": "LINK_RESOURCE_IDENTITY",
                "event_time": "2026-01-01T00:00:00Z",
                "activity_id": "activity_link",
                "system_id": "data_catalog",
                "resource_id": "object_19",
                "details": "Attachment catalog confirmed object_19 belongs to user_07.",
            }],
            {"audit_at": "2026-01-02T00:00:00Z"},
            subject,
        )
        self.assertEqual(len(record), 1)
        self.assertEqual(record[0].category, "UNKNOWN")

    def test_unrelated_direct_identifier_does_not_mark_record_as_subject_pii(self) -> None:
        record = audit.EvidenceRecord(
            resource_id="support_1234",
            system_id="support_platform",
            category="SUPPORT_MESSAGE",
            values={"requester_email": "agent@example.test"},
            evidence_id="evidence_shared_message",
            captured_at="2026-01-01T00:00:00Z",
        )
        subject = audit.Subject("case_shared", "person@example.test", "user_1234")
        subject.add("person@example.test")
        self.assertFalse(audit.pii_fields_present(record, subject))


def main() -> None:
    expected = load_rows(ROOT / "dataset" / "sample_output.csv")
    with tempfile.TemporaryDirectory(prefix="deletion-audit-") as temporary:
        output_path = Path(temporary) / "sample-output.csv"
        requests = load_rows(ROOT / "dataset" / "sample_deletion_requests.csv")
        identities = audit.read_csv(ROOT / "dataset" / "user_identities.csv")
        history = audit.read_csv(ROOT / "dataset" / "user_audit_log.csv")
        manifest = audit.read_csv(ROOT / "dataset" / "evidence_files.csv")
        activities = audit.read_csv(ROOT / "dataset" / "system_activity.csv")
        policy = {
            row["data_category"]: row
            for row in audit.read_csv(ROOT / "dataset" / "deletion_rules.csv")
        }
        aliases, profiles = audit.identity_index(identities, history)
        evidence = audit.load_evidence(manifest)
        actual_rows = [
            audit.audit_case(row, evidence, activities, policy, aliases, profiles, history)
            for row in requests
        ]
        audit.write_output(actual_rows, output_path)
        actual = load_rows(output_path)
    print(json.dumps(score(expected, actual), indent=2))
    unittest.main(argv=[sys.argv[0]], exit=False)


if __name__ == "__main__":
    main()
