#!/usr/bin/env python3
"""Evidence-based deletion audit for the Ghost Data Still Exists challenge."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
OPERATION_STATES = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}

TABLE_CATEGORIES = {
    "customer_profiles": "USER_PROFILE",
    "secondary_identifiers": "SECONDARY_IDENTIFIER",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "cache_entries": "CACHE_ENTRY",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "product_telemetry": "PRODUCT_TELEMETRY",
    "support_records": "SUPPORT_MESSAGE",
    "support_messages": "SUPPORT_MESSAGE",
    "support_attachments": "SUPPORT_ATTACHMENT",
    "customer_exports": "USER_EXPORT",
    "marketing_profiles": "MARKETING_PROFILE",
    "email_delivery_logs": "EMAIL_DELIVERY_LOG",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "legal_hold_records": "LEGAL_HOLD_RECORD",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "account_tombstones": "ACCOUNT_TOMBSTONE",
    "connector_subscriptions": "DATA_FLOW",
}

SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "telemetry": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "backup": "backup_service",
    "data_flow": "integration_service",
    "audit_record": "security_service",
    "legal_hold": "legal_service",
    "tombstone": "account_service",
    "cache": "cache_service",
    "marketing": "marketing_service",
    "email_log": "email_service",
    "object": "support_platform",
}

DELETE_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_ATTACHMENT",
    "USER_EXPORT",
    "MARKETING_PROFILE",
}
REDACT_CATEGORIES = {
    "SUPPORT_MESSAGE",
    "EMAIL_DELIVERY_LOG",
    "ACCOUNT_TOMBSTONE",
}
ANONYMIZE_CATEGORIES = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
RETAIN_CATEGORIES = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}

DELETE_WORDS = (
    "delet", "erase", "erasure", "remove", "removal",
    "wipe my", "close my account", "close this account", "close the account",
    "closed my account", "closing my account", "forget me",
    "elimin", "borr", "suprim", "supress", "exclu", "apagamento",
    "löschen", "löschung", "entfernen", "suppression", "supprimer",
    "effacer", "削除", "消去", "삭제", "탈퇴",
)
NON_DELETE_WORDS = (
    "access my data", "access request", "copy of my data", "export my data",
    "correct my", "correction", "rectify", "update my", "change my email",
    "opt out", "opt-out", "unsubscribe", "stop marketing",
    "no longer receive", "marketing emails", "leave my account active",
    "do not delete", "don't delete", "not delete",
    "acceder a mis datos", "acceso a mis datos", "rectificar",
    "corregir mis datos", "actualizar mis datos", "dejar de recibir",
    "optar por no", "acessar meus dados", "corrigir meus dados",
    "atualizar meus dados", "parar de receber", "データへのアクセス",
    "データを訂正", "データを修正", "マーケティングメールを停止",
    "정보에 접근", "정보를 수정", "마케팅 수신 거부",
)

RESOURCE_RE = re.compile(
    r"\b(?:account|search|analytics|telemetry|support|export|backup|data_flow|"
    r"audit_record|legal_hold|tombstone|cache|marketing|email_log|object)_\d+\b",
    re.IGNORECASE,
)
KEY_VALUE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*([^\s,|]+)")
TRACE_ID_RE = re.compile(
    r"(?:\btrace_id\s*=\s*|\brequestId\s*=\s*|\|\s*)(tr-[A-Za-z0-9_-]+)",
    re.IGNORECASE,
)


@dataclass
class Subject:
    case_id: str
    request_email: str
    user_id: str | None
    identifiers: set[str] = field(default_factory=set)
    normalized_ids: set[str] = field(default_factory=set)
    phone_digits: set[str] = field(default_factory=set)
    email_hashes: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)

    def add(self, value: Any) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text or text.casefold() in {"none", "null", "unknown"}:
            return
        self.identifiers.add(text)
        normalized = normalize(text)
        if normalized:
            self.normalized_ids.add(normalized)
        digits = re.sub(r"\D", "", text)
        if len(digits) >= 7 and not ("@" in text):
            self.phone_digits.add(digits)
        if re.fullmatch(r"[a-fA-F0-9]{40,128}", text):
            self.email_hashes.add(text.casefold())

    def matches(self, text: str) -> bool:
        folded = text.casefold()
        for item in self.normalized_ids:
            if item.startswith("user_"):
                if re.search(rf"(?<![a-z0-9]){re.escape(item)}(?![a-z0-9])", folded):
                    return True
            elif "@" in item and item in folded:
                return True
            elif re.fullmatch(r"[a-f0-9]{40,128}", item) and item in folded:
                return True
        for digits in self.phone_digits:
            candidate = re.sub(r"\D", "", text)
            if len(digits) >= 7 and digits in candidate:
                return True
        if any(value in folded for value in self.email_hashes):
            return True
        return any(
            re.search(rf"(?<!\w){re.escape(name.casefold())}(?!\w)", folded)
            for name in self.names
        )


@dataclass
class EvidenceRecord:
    resource_id: str
    system_id: str
    category: str
    values: dict[str, Any]
    evidence_id: str
    captured_at: str
    source_text: str = ""
    linked: bool = False
    snapshot_tables: tuple[str, ...] = ()


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKD", value).casefold()
    return "".join(ch for ch in value if ch.isalnum() or ch in "@._+-")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def classify_request(text: str) -> bool:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    if any(term in normalized for term in NON_DELETE_WORDS):
        return False
    audit_context = (
        "profile is gone",
        "account is gone",
        "account was gone",
        "profile has been removed",
        "request failed",
        "latest state",
        "remains deleted",
        "still existed",
        "cannot identify me",
    )
    return any(term in normalized for term in DELETE_WORDS) or any(
        term in normalized for term in audit_context
    )


def identity_index(
    identities: list[dict[str, str]], history: list[dict[str, str]]
) -> tuple[dict[str, set[str]], dict[str, dict[str, str]]]:
    aliases: dict[str, set[str]] = defaultdict(set)
    profiles: dict[str, dict[str, str]] = {}
    for row in identities:
        user_id = row.get("user_id", "")
        if not user_id:
            continue
        profiles[user_id] = row
        for key in ("email", "name", "phone", "email_hash", "user_id"):
            value = row.get(key, "")
            if value:
                aliases[normalize(value)].add(user_id)
    for row in history:
        user_id = row.get("user_id", "")
        if not user_id:
            continue
        for key in ("old_value", "new_value"):
            value = row.get(key, "")
            if value:
                aliases[normalize(value)].add(user_id)
        aliases[normalize(user_id)].add(user_id)
    return aliases, profiles


def resolve_subject(
    request: dict[str, str],
    aliases: dict[str, set[str]],
    profiles: dict[str, dict[str, str]],
    history: list[dict[str, str]],
) -> Subject:
    request_email = request.get("email", "")
    candidates = aliases.get(normalize(request_email), set())
    user_id = sorted(candidates)[0] if len(candidates) == 1 else None
    subject = Subject(request["case_id"], request_email, user_id)
    subject.add(request_email)
    if user_id:
        subject.add(user_id)
        audit_at = parse_time(request.get("audit_at"))
        profile = profiles.get(user_id, {})
        updated_at = parse_time(profile.get("updated_at"))
        if not audit_at or not updated_at or updated_at <= audit_at:
            for key in ("email", "phone", "email_hash"):
                subject.add(profile.get(key))
            if profile.get("name"):
                subject.names.add(profile["name"].casefold())
        for row in history:
            if row.get("user_id") != user_id:
                continue
            event_time = parse_time(row.get("event_time"))
            if audit_at and event_time and event_time > audit_at:
                continue
            field_name = row.get("field_name", "").casefold()
            if field_name == "name":
                for key in ("old_value", "new_value"):
                    if row.get(key):
                        subject.names.add(row[key].casefold())
            else:
                subject.add(row.get("old_value"))
                subject.add(row.get("new_value"))
    return subject


def system_for(context: dict[str, Any], resource_id: str = "") -> str:
    for key in ("system_id", "data_store", "origin_system", "source_system", "target_system", "system", "service"):
        raw = str(context.get(key, "")).strip()
        if raw and raw.casefold() not in {"none", "unknown"}:
            normalized = raw.casefold()
            for suffix in ("_replica", "_primary", "_failover"):
                if normalized.endswith(suffix):
                    normalized = normalized[: -len(suffix)]
                    prefix = normalized.split("_", 1)[0]
                    return SYSTEM_BY_PREFIX.get(prefix, normalized)
            return raw
    prefix = resource_id.split("_", 1)[0].casefold() if resource_id else ""
    for known, system in SYSTEM_BY_PREFIX.items():
        if resource_id.casefold().startswith(known + "_"):
            return system
    return SYSTEM_BY_PREFIX.get(prefix, "unknown_system")


def category_for(context: dict[str, Any], resource_id: str, source_text: str = "") -> str:
    candidates = []
    for key in ("data_category", "category", "record_type", "collection", "table", "resource_type"):
        candidates.append(str(context.get(key, "")))
    candidates.append(source_text)
    haystack = " ".join(candidates).casefold()
    for table, category in TABLE_CATEGORIES.items():
        if table.casefold() in haystack:
            if category == "SUPPORT_MESSAGE" and "attachment" in haystack:
                return "SUPPORT_ATTACHMENT"
            return category
    resource = resource_id.casefold()
    for prefix, category in (
        ("account_", "USER_PROFILE"),
        ("search_", "SEARCH_INDEX_ENTRY"),
        ("analytics_", "ANALYTICS_PROFILE"),
        ("telemetry_", "PRODUCT_TELEMETRY"),
        ("support_", "SUPPORT_MESSAGE"),
        ("export_", "USER_EXPORT"),
        ("backup_", "BACKUP_ARCHIVE"),
        ("data_flow_", "DATA_FLOW"),
        ("audit_record_", "SECURITY_AUDIT_LOG"),
        ("legal_hold_", "LEGAL_HOLD_RECORD"),
        ("tombstone_", "ACCOUNT_TOMBSTONE"),
        ("cache_", "CACHE_ENTRY"),
        ("marketing_", "MARKETING_PROFILE"),
        ("email_log_", "EMAIL_DELIVERY_LOG"),
    ):
        if resource.startswith(prefix):
            if category == "SUPPORT_MESSAGE" and "attachment" in haystack:
                return "SUPPORT_ATTACHMENT"
            return category
    if "attachment" in haystack:
        return "SUPPORT_ATTACHMENT"
    return "UNKNOWN"


def flatten_values(value: Any, prefix: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, (dict, list)):
                result.update(flatten_values(item, name))
            else:
                result[name] = item
                result[str(key)] = item
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.update(flatten_values(item, f"{prefix}[{index}]"))
    elif prefix:
        result[prefix] = value
    return result


def iter_json_records(value: Any, context: dict[str, Any] | None = None) -> Iterable[tuple[str, dict[str, Any], str]]:
    context = context or {}
    if isinstance(value, dict):
        next_context = dict(context)
        for key in ("captured_at", "data_store", "system_id", "origin_system", "source_system", "category", "data_category", "collection", "record_type"):
            if key in value and not isinstance(value[key], (dict, list)):
                next_context[key] = value[key]
        flat = flatten_values(value)
        resource = str(value.get("resource_id") or value.get("resource") or "")
        if resource and RESOURCE_RE.fullmatch(resource):
            combined = dict(next_context)
            combined.update(value)
            combined.update(flat)
            yield resource, combined, json.dumps(value, ensure_ascii=False, default=str)
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from iter_json_records(child, next_context)
    elif isinstance(value, list):
        for child in value:
            yield from iter_json_records(child, context)


def iter_json_snapshot_scopes(
    value: Any,
    manifest_captured_at: str,
    inherited_system: str = "",
    inherited_snapshot_at: str = "",
) -> Iterable[EvidenceRecord]:
    if isinstance(value, dict):
        data_store = str(value.get("data_store") or inherited_system)
        collection = str(value.get("collection") or "")
        snapshot_time = str(value.get("captured_at") or inherited_snapshot_at)
        if data_store and collection and isinstance(value.get("records"), list):
            yield EvidenceRecord(
                resource_id=f"snapshot_scope_{data_store}_{collection}",
                system_id=data_store,
                category="SNAPSHOT_SCOPE",
                values={
                    "origin_system": data_store,
                    "collection": collection,
                    "snapshot_at": snapshot_time,
                },
                evidence_id="",
                captured_at=manifest_captured_at,
                snapshot_tables=(collection,),
            )
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from iter_json_snapshot_scopes(
                    child, manifest_captured_at, data_store, snapshot_time
                )
    elif isinstance(value, list):
        for child in value:
            yield from iter_json_snapshot_scopes(
                child, manifest_captured_at, inherited_system, inherited_snapshot_at
            )


def sql_records(path: Path, manifest_row: dict[str, str]) -> list[EvidenceRecord]:
    connection = sqlite3.connect(":memory:")
    records: list[EvidenceRecord] = []
    try:
        connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        table_names = tuple(name for (name,) in tables)
        if "snapshot_scope" in table_names:
            scope_rows = connection.execute(
                "SELECT origin_system, captured_at FROM snapshot_scope"
            ).fetchall()
            for origin_system, snapshot_at in scope_rows:
                records.append(
                    EvidenceRecord(
                        resource_id=f"snapshot_scope_{origin_system}",
                        system_id=str(origin_system),
                        category="SNAPSHOT_SCOPE",
                        values={
                            "origin_system": origin_system,
                            "snapshot_at": snapshot_at,
                        },
                        evidence_id=manifest_row["file_id"],
                        captured_at=manifest_row["captured_at"],
                        snapshot_tables=table_names,
                    )
                )
        for (table,) in tables:
            cursor = connection.execute(f'SELECT * FROM "{table.replace(chr(34), chr(34) * 2)}"')
            names = [column[0] for column in cursor.description or []]
            table_category = TABLE_CATEGORIES.get(table, category_for({"table": table}, ""))
            for row in cursor.fetchall():
                values = dict(zip(names, row))
                resource_id = str(values.get("resource_id") or values.get("id") or "")
                if not RESOURCE_RE.fullmatch(resource_id):
                    continue
                category = TABLE_CATEGORIES.get(table, category_for({"table": table, **values}, resource_id))
                if category == "UNKNOWN":
                    category = table_category
                if category == "SUPPORT_MESSAGE" and "attachment" in table.casefold():
                    category = "SUPPORT_ATTACHMENT"
                records.append(
                    EvidenceRecord(
                        resource_id=resource_id,
                        system_id=system_for({"table": table, **values}, resource_id),
                        category=category,
                        values=values,
                        evidence_id=manifest_row["file_id"],
                        captured_at=manifest_row["captured_at"],
                        source_text=f"{table} {values}",
                    )
                )
    except sqlite3.Error as error:
        print(f"Warning: could not parse SQL evidence {path.name}: {error}", file=sys.stderr)
    finally:
        connection.close()
    return records


def activity_link_records(
    activities: list[dict[str, str]], request: dict[str, str], subject: Subject
) -> list[EvidenceRecord]:
    cutoff = parse_time(request.get("audit_at"))
    result = []
    for activity in activities:
        if activity.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue
        event_time = parse_time(activity.get("event_time"))
        if cutoff and event_time and event_time > cutoff:
            continue
        details = activity.get("details", "")
        if not subject.matches(details):
            continue
        resource_id = activity.get("resource_id", "")
        if not resource_id:
            match = RESOURCE_RE.search(details)
            resource_id = match.group(0) if match else ""
        if not resource_id:
            continue
        values = dict(activity)
        result.append(
            EvidenceRecord(
                resource_id=resource_id,
                system_id=system_for(activity, resource_id),
                category=category_for(activity, resource_id),
                values=values,
                evidence_id=activity["activity_id"],
                captured_at=activity["event_time"],
                source_text=details,
            )
        )
    return result


def parse_text_record(line: str, manifest_row: dict[str, str]) -> EvidenceRecord | None:
    resources = RESOURCE_RE.findall(line)
    if not resources:
        return None
    resource_id = resources[0]
    timestamp, separator, payload = line.partition(" ")
    values: dict[str, Any] = {}
    if separator and payload.lstrip().startswith("{"):
        try:
            structured = json.loads(payload)
        except json.JSONDecodeError:
            structured = None
        if isinstance(structured, dict):
            values.update(flatten_values(structured))
            values["event_time"] = timestamp
    if not values:
        values.update(
            {
                key.casefold(): value.strip('"\'')
                for key, value in KEY_VALUE_RE.findall(line)
            }
        )
    trace_match = TRACE_ID_RE.search(line)
    if trace_match:
        values.setdefault("trace_id", trace_match.group(1))
    parts = [part.strip() for part in line.split("|")]
    for index, value in enumerate(parts):
        if value and index not in (0,):
            values.setdefault(f"field_{index}", value)
    context = dict(values)
    for part in parts:
        for category in set(TABLE_CATEGORIES.values()):
            if category.casefold() in part.casefold():
                context["category"] = category
    system = system_for(context, resource_id)
    category = category_for(context, resource_id, line)
    return EvidenceRecord(
        resource_id=resource_id,
        system_id=system,
        category=category,
        values=values,
        evidence_id=manifest_row["file_id"],
        captured_at=manifest_row["captured_at"],
        source_text=line,
    )


def records_from_document_text(text: str, manifest_row: dict[str, str]) -> list[EvidenceRecord]:
    resources = list(dict.fromkeys(RESOURCE_RE.findall(text)))
    if not resources:
        return []
    values = {key.casefold(): value.strip('"\'') for key, value in KEY_VALUE_RE.findall(text)}
    values["document_text"] = text
    output = []
    for resource_id in resources:
        category = category_for(values, resource_id, text)
        output.append(
            EvidenceRecord(
                resource_id=resource_id,
                system_id=system_for(values, resource_id),
                category=category,
                values=values,
                evidence_id=manifest_row["file_id"],
                captured_at=manifest_row["captured_at"],
                source_text=text,
            )
        )
    return output


def load_evidence(manifest: list[dict[str, str]]) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    ocr_engine = None
    for row in manifest:
        path = DATASET / row["file_path"]
        if not path.is_file():
            print(f"Warning: evidence file is missing: {path}", file=sys.stderr)
            continue
        suffix = path.suffix.casefold()
        if suffix == ".sql":
            records.extend(sql_records(path, row))
        elif suffix == ".json":
            try:
                content = json.loads(path.read_text(encoding="utf-8-sig"))
            except json.JSONDecodeError as error:
                print(f"Warning: invalid JSON evidence {path.name}: {error}", file=sys.stderr)
                continue
            for scope in iter_json_snapshot_scopes(content, row["captured_at"]):
                scope.evidence_id = row["file_id"]
                records.append(scope)
            for resource, values, source in iter_json_records(content):
                records.append(
                    EvidenceRecord(
                        resource_id=resource,
                        system_id=system_for(values, resource),
                        category=category_for(values, resource, source),
                        values=values,
                        evidence_id=row["file_id"],
                        captured_at=row["captured_at"],
                        source_text=source,
                    )
                )
        elif suffix in {".log", ".txt", ".csv"}:
            lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
            trace_text: dict[str, list[str]] = defaultdict(list)
            for line in lines:
                trace_match = TRACE_ID_RE.search(line)
                if trace_match:
                    trace_text[trace_match.group(1).casefold()].append(line)
            file_records = []
            for line in lines:
                record = parse_text_record(line, row)
                if record:
                    file_records.append(record)
            for record in file_records:
                trace_id = str(record.values.get("trace_id", "")).casefold()
                if trace_id in trace_text:
                    record.source_text = "\n".join(trace_text[trace_id])
            records.extend(file_records)
        elif suffix == ".pdf":
            try:
                from pypdf import PdfReader
            except ImportError:
                print("Warning: install code/requirements.txt to extract PDF evidence.", file=sys.stderr)
                continue
            reader = PdfReader(str(path))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            records.extend(records_from_document_text(text, row))
        elif suffix in {".png", ".jpg", ".jpeg"}:
            try:
                from rapidocr_onnxruntime import RapidOCR
            except ImportError:
                print("Warning: install code/requirements.txt to OCR image evidence.", file=sys.stderr)
                continue
            if ocr_engine is None:
                ocr_engine = RapidOCR()
            result, _ = ocr_engine(str(path))
            if result:
                text_rows: list[tuple[float, float, str]] = []
                for box, recognized, _confidence in result:
                    y_mid = sum(point[1] for point in box) / len(box)
                    x_mid = sum(point[0] for point in box) / len(box)
                    text_rows.append((y_mid, x_mid, str(recognized)))
                grouped: list[list[tuple[float, float, str]]] = []
                for item in sorted(text_rows):
                    if not grouped or abs(item[0] - grouped[-1][0][0]) > 14:
                        grouped.append([item])
                    else:
                        grouped[-1].append(item)
                lines = [
                    " ".join(value[2] for value in sorted(group, key=lambda value: value[1]))
                    for group in grouped
                ]
                records.extend(records_from_document_text("\n".join(lines), row))
    return records


def linked_record(record: EvidenceRecord, subject: Subject) -> bool:
    if subject.user_id:
        for key, value in record.values.items():
            if value is None:
                continue
            if normalize(str(value)) == normalize(subject.user_id):
                return True
    source = record.source_text or json.dumps(record.values, ensure_ascii=False, default=str)
    return subject.matches(source)


def available_at_cutoff(record: EvidenceRecord, cutoff: datetime | None) -> bool:
    if not cutoff:
        return True
    captured = parse_time(record.captured_at)
    if captured and captured > cutoff:
        return False
    timestamp_fields = {"captured_at", "updated_at", "event_time", "recorded_at", "snapshot_at"}
    return not any(
        event_time and event_time > cutoff
        for key, value in record.values.items()
        if key.casefold().split(".")[-1] in timestamp_fields
        for event_time in [parse_time(str(value))]
    )


def status_from_record(record: EvidenceRecord) -> str:
    state_fields = {
        str(key).casefold().split(".")[-1]: str(value).strip().casefold()
        for key, value in record.values.items()
        if value is not None
    }
    values = " ".join(
        state_fields.get(key, "")
        for key in (
            "state", "status", "record_status", "legal_hold_status",
            "hold_status", "result", "reported_result",
        )
    )
    values += " " + record.source_text.casefold()
    lowered = unicodedata.normalize("NFKD", values).casefold()
    enabled = state_fields.get("enabled")
    if (
        state_fields.get("rows") == "0"
        or state_fields.get("row_count") == "0"
        or state_fields.get("http_status") == "404"
        or state_fields.get("status_code") == "404"
    ):
        return "ABSENT"
    if enabled in {"0", "false", "no"}:
        return "DISABLED"
    if enabled in {"1", "true", "yes"}:
        return "ACTIVE"
    restore_allowed = next(
        (
            state_fields[key]
            for key in ("restore_allowed", "restore_access", "restore_permitted", "can_restore")
            if key in state_fields
        ),
        "",
    )
    if restore_allowed in {"0", "false", "no", "blocked", "disabled", "denied"}:
        return "BLOCKED"
    if restore_allowed in {"1", "true", "yes", "allowed", "enabled", "active"}:
        return "ACTIVE"
    if re.search(r"\bnot[_ ]found\b|\babsent\b|\brows=0\b|\bhttp_status=404\b", lowered):
        return "ABSENT"
    if state_fields.get("record_exists") in {"0", "false", "no"}:
        return "ABSENT"
    if re.search(r"\b(anonymized|anonymised)\b", lowered):
        return "ANONYMIZED"
    if re.search(r"\bredacted\b", lowered):
        return "REDACTED"
    if re.search(r"\bblocked\b|\brestore_allowed=0\b", lowered):
        return "BLOCKED"
    if re.search(r"\bdisabled\b|\benabled=0\b", lowered):
        return "DISABLED"
    if re.search(r"\bidentifiable\b|\bexposed\b", lowered):
        return "IDENTIFIABLE"
    if re.search(r"\bactive\b|\benabled=1\b|\brestore_allowed=1\b", lowered):
        return "ACTIVE"
    return "PRESENT"


def pii_fields_present(record: EvidenceRecord, subject: Subject) -> bool:
    direct_keys = ("name", "full_name", "email", "phone", "email_hash", "display_name", "requester_name", "requester_email", "requester_phone", "owner_email", "owner_phone", "customer_email")
    for key, value in record.values.items():
        if value is None or str(value).strip() == "":
            continue
        short_key = key.casefold().split(".")[-1]
        if (
            short_key in direct_keys
            or short_key.endswith(("_name", "_email", "_phone"))
            or "email_hash" in short_key
        ):
            text = str(value).strip().casefold()
            if (
                text not in {"null", "none", "redacted", "anonymized", "anonymised", "deleted", "***"}
                and subject.matches(str(value))
            ):
                return True
    if record.category not in REDACT_CATEGORIES | ANONYMIZE_CATEGORIES:
        return False
    source = record.source_text or json.dumps(record.values, ensure_ascii=False, default=str)
    direct_identifiers = (
        subject.request_email,
        *subject.email_hashes,
        *subject.phone_digits,
        *subject.names,
    )
    for identifier in direct_identifiers:
        if identifier and identifier.casefold() in source.casefold():
            return True
    if record.category in ANONYMIZE_CATEGORIES and subject.user_id:
        if any(
            normalize(str(value)) == normalize(subject.user_id)
            for value in record.values.values()
            if value is not None
        ):
            return True
    return False


def active_risk(record: EvidenceRecord) -> str | None:
    state = status_from_record(record)
    if record.category == "DATA_FLOW" and state == "ACTIVE":
        return "REPORT_ACTIVE_DATA_FLOW"
    if record.category == "BACKUP_ARCHIVE" and state == "ACTIVE":
        return "REPORT_RESTORE_RISK"
    return None


def required_action(
    record: EvidenceRecord,
    policy: dict[str, dict[str, str]],
    subject: Subject,
    audit_at: datetime | None,
) -> str | None:
    rule = policy.get(record.category)
    if not rule:
        return None
    action = rule["required_action"].strip().upper()
    condition = rule.get("condition", "").casefold()
    if record.category == "SECURITY_AUDIT_LOG" and "retention period" in condition:
        retention_until = next(
            (
                parse_time(str(value))
                for key, value in record.values.items()
                if key.casefold().split(".")[-1] in {"retention_until", "retain_until"}
                and value
            ),
            None,
        )
        if audit_at and retention_until and retention_until <= audit_at:
            return "DELETE"
    if record.category == "LEGAL_HOLD_RECORD" and "legal hold is active" in condition:
        state = status_from_record(record)
        if state != "ACTIVE":
            return "DELETE"
    if record.category in ANONYMIZE_CATEGORIES and "still attributable" in condition:
        if not pii_fields_present(record, subject):
            return None
    return action


def evidence_records_for_case(
    request: dict[str, str], all_records: list[EvidenceRecord], subject: Subject
) -> list[EvidenceRecord]:
    cutoff = parse_time(request.get("audit_at"))
    matched = []
    linked_traces: dict[str, set[str]] = defaultdict(set)
    for record in all_records:
        if not available_at_cutoff(record, cutoff):
            continue
        if linked_record(record, subject):
            record.linked = True
            matched.append(record)
            trace = str(record.values.get("trace_id", ""))
            if trace:
                linked_traces[record.evidence_id].add(trace)
    linked_trace_pairs = {
        (evidence_id, trace)
        for evidence_id, traces in linked_traces.items()
        for trace in traces
    }
    for record in all_records:
        if record in matched:
            continue
        if not available_at_cutoff(record, cutoff):
            continue
        trace = str(record.values.get("trace_id", ""))
        if trace and (record.evidence_id, trace) in linked_trace_pairs:
            matched.append(record)
    latest: dict[tuple[str, str], EvidenceRecord] = {}
    for record in matched:
        key = (record.system_id, record.resource_id)
        old = latest.get(key)
        current_time = parse_time(record.captured_at)
        old_time = parse_time(old.captured_at) if old else None
        if old is None or (current_time and (old_time is None or current_time > old_time)) or (
            current_time == old_time and record.evidence_id == old.evidence_id
        ):
            latest[key] = record
    return list(latest.values())


def make_step(
    phase: str, system: str, resource: str, operation: str, state: str, evidence: str
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system,
        "resource_id": resource,
        "operation": operation,
        "state": state,
        "evidence_id": evidence,
    }


def audit_case(
    request: dict[str, str],
    records: list[EvidenceRecord],
    activities: list[dict[str, str]],
    policy: dict[str, dict[str, str]],
    aliases: dict[str, set[str]],
    profiles: dict[str, dict[str, str]],
    history: list[dict[str, str]],
) -> dict[str, Any]:
    if not classify_request(request.get("request_text", "")):
        return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps": []}
    subject = resolve_subject(request, aliases, profiles, history)
    evidence = evidence_records_for_case(request, records, subject)
    evidence.extend(activity_link_records(activities, request, subject))

    findings: list[dict[str, Any]] = []
    repairs: dict[tuple[str, str], dict[str, Any]] = {}
    verifications: dict[tuple[str, str, str], dict[str, Any]] = {}
    violation = False

    for record in evidence:
        state = status_from_record(record)
        category = record.category
        rule = required_action(
            record,
            policy,
            subject,
            parse_time(request.get("audit_at")),
        )
        risk_operation = active_risk(record)
        if risk_operation:
            violation = True
            finding = make_step(
                "FINDING", record.system_id, record.resource_id,
                risk_operation, "ACTIVE", record.evidence_id
            )
            findings.append(finding)
            operation = "DISABLE_DATA_FLOW" if risk_operation == "REPORT_ACTIVE_DATA_FLOW" else "BLOCK_RESTORE"
            state_after = "DISABLED" if operation == "DISABLE_DATA_FLOW" else "BLOCKED"
            repairs[(record.system_id, record.resource_id)] = make_step(
                "REMEDIATION", record.system_id, record.resource_id, operation, state_after, ""
            )
            verify_operation = "VERIFY_DATA_FLOW_DISABLED" if operation == "DISABLE_DATA_FLOW" else "VERIFY_RESTORE_BLOCKED"
            verifications[(record.system_id, record.resource_id, verify_operation)] = make_step(
                "VERIFICATION", record.system_id, record.resource_id, verify_operation, state_after, ""
            )
            continue

        if not rule:
            continue
        pii_present = pii_fields_present(record, subject)
        if rule == "DELETE" and state not in {"ABSENT", "REDACTED", "ANONYMIZED"}:
            violation = True
            findings.append(make_step("FINDING", record.system_id, record.resource_id, "REPORT_REMAINING_RECORD", "PRESENT", record.evidence_id))
            repairs[(record.system_id, record.resource_id)] = make_step("REMEDIATION", record.system_id, record.resource_id, "DELETE_RECORD", "ABSENT", "")
            verifications[(record.system_id, record.resource_id, "VERIFY_RECORD_ABSENT")] = make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", "")
        elif rule == "REDACT":
            if pii_present:
                violation = True
                findings.append(make_step("FINDING", record.system_id, record.resource_id, "REPORT_EXPOSED_PII", "PRESENT", record.evidence_id))
                repairs[(record.system_id, record.resource_id)] = make_step("REMEDIATION", record.system_id, record.resource_id, "REDACT_RECORD", "REDACTED", "")
                verifications[(record.system_id, record.resource_id, "VERIFY_RECORD_REDACTED")] = make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", "")
            elif category == "ACCOUNT_TOMBSTONE" or state == "REDACTED":
                verifications[(record.system_id, record.resource_id, "VERIFY_RECORD_REDACTED")] = make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", record.evidence_id)
            elif category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
                verifications[(record.system_id, record.resource_id, "VERIFY_RECORD_REDACTED")] = make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", record.evidence_id)
        elif rule == "ANONYMIZE":
            if pii_present:
                violation = True
                findings.append(make_step("FINDING", record.system_id, record.resource_id, "REPORT_EXPOSED_PII", "PRESENT", record.evidence_id))
                repairs[(record.system_id, record.resource_id)] = make_step("REMEDIATION", record.system_id, record.resource_id, "ANONYMIZE_RECORD", "ANONYMIZED", "")
                verifications[(record.system_id, record.resource_id, "VERIFY_RECORD_ANONYMIZED")] = make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "")
            elif state == "ANONYMIZED":
                verifications[(record.system_id, record.resource_id, "VERIFY_RECORD_ANONYMIZED")] = make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", record.evidence_id)
        elif rule == "RETAIN":
            if state not in {"ABSENT", "NOT_FOUND"}:
                verifications[(record.system_id, record.resource_id, "VERIFY_RECORD_PRESENT")] = make_step("VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_PRESENT", "PRESENT", record.evidence_id)

    if not violation and not verifications:
        scope_by_system: dict[str, EvidenceRecord] = {}
        for record in records:
            if record.category != "SNAPSHOT_SCOPE" or not available_at_cutoff(
                record, parse_time(request.get("audit_at"))
            ):
                continue
            previous = scope_by_system.get(record.system_id)
            current_time = parse_time(record.captured_at)
            previous_time = parse_time(previous.captured_at) if previous else None
            if previous is None or (
                current_time and (previous_time is None or current_time > previous_time)
            ):
                scope_by_system[record.system_id] = record
        required_snapshot_systems = {
            "account_service",
            "analytics_platform",
            "backup_service",
            "export_service",
            "integration_service",
            "search_service",
            "security_service",
            "support_platform",
        }
        if required_snapshot_systems.issubset(scope_by_system):
            audit_resource = subject.user_id or subject.request_email
            for system_id in sorted(required_snapshot_systems):
                scope = scope_by_system[system_id]
                verifications[
                    (system_id, audit_resource, "VERIFY_RECORD_ABSENT")
                ] = make_step(
                    "VERIFICATION",
                    system_id,
                    audit_resource,
                    "VERIFY_RECORD_ABSENT",
                    "ABSENT",
                    scope.evidence_id,
                )

    account_records = [r for r in evidence if r.category == "USER_PROFILE"]
    for record in account_records:
        if status_from_record(record) == "ABSENT":
            verifications[(record.system_id, record.resource_id, "VERIFY_RECORD_ABSENT")] = make_step(
                "VERIFICATION", record.system_id, record.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", record.evidence_id
            )

    phase_steps = findings + list(repairs.values()) + list(verifications.values())
    if not violation:
        # A complete answer needs at least one direct, time-bounded verification.
        # If no deletion state was found, keep the supported compliant checks rather
        # than inventing resource IDs or evidence.
        phase_steps = list(verifications.values())
    else:
        for step in verifications.values():
            step["evidence_id"] = ""
    unique_steps: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for step in phase_steps:
        key = (
            step["phase"],
            step["operation"],
            step["system_id"],
            step["resource_id"],
        )
        previous = unique_steps.get(key)
        if previous is None or (not previous["evidence_id"] and step["evidence_id"]):
            unique_steps[key] = step
    phase_steps = list(unique_steps.values())
    phase_steps.sort(
        key=lambda step: (
            PHASE_ORDER[step["phase"]],
            OPERATION_ORDER[step["operation"]],
            step["system_id"],
            step["resource_id"],
        )
    )
    for number, step in enumerate(phase_steps, 1):
        step["step_no"] = number
    return {
        "case_id": request["case_id"],
        "deletion_status": "INCOMPLETE" if violation else "COMPLETE",
        "steps": phase_steps,
    }


def write_output(rows: list[dict[str, Any]], destination: Path) -> None:
    rows.sort(key=lambda row: row["case_id"])
    with destination.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "case_id": row["case_id"],
                "deletion_status": row["deletion_status"],
                "steps_json": json.dumps(row["steps"], ensure_ascii=False, separators=(",", ":")),
            })


def validate_output(rows: list[dict[str, Any]], requests: list[dict[str, str]]) -> None:
    expected_ids = sorted(row["case_id"] for row in requests)
    actual_ids = [row["case_id"] for row in rows]
    if actual_ids != expected_ids:
        raise ValueError(f"Output case IDs mismatch: expected {len(expected_ids)}, got {len(actual_ids)}")
    allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    allowed_phases = set(PHASE_ORDER)
    for row in rows:
        if row["deletion_status"] not in allowed_statuses:
            raise ValueError(f"Invalid status for {row['case_id']}: {row['deletion_status']}")
        steps = row["steps"]
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise ValueError(f"NOT_APPLICABLE case has steps: {row['case_id']}")
        if row["deletion_status"] == "COMPLETE" and not steps:
            raise ValueError(f"COMPLETE case has no evidence-backed verification: {row['case_id']}")
        phases = []
        for number, step in enumerate(steps, 1):
            if step["step_no"] != number or step["phase"] not in allowed_phases:
                raise ValueError(f"Invalid step sequence for {row['case_id']}")
            if set(step) != {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}:
                raise ValueError(f"Invalid step keys for {row['case_id']}")
            if OPERATION_STATES.get(step["operation"]) != (step["phase"], step["state"]):
                raise ValueError(f"Invalid operation/state for {row['case_id']}: {step['operation']}")
            phases.append(PHASE_ORDER[step["phase"]])
            if step["phase"] == "FINDING" and not step["evidence_id"]:
                raise ValueError(f"Finding lacks evidence for {row['case_id']}")
            if row["deletion_status"] == "COMPLETE" and (
                step["phase"] != "VERIFICATION" or not step["evidence_id"]
            ):
                raise ValueError(f"Invalid COMPLETE evidence step for {row['case_id']}")
            if row["deletion_status"] == "INCOMPLETE" and step["phase"] in {"REMEDIATION", "VERIFICATION"} and step["evidence_id"]:
                raise ValueError(f"Future step cites existing evidence for {row['case_id']}")
        if phases != sorted(phases):
            raise ValueError(f"Step phases out of order for {row['case_id']}")


def run(
    output_path: Path = OUTPUT,
    request_path: Path = DATASET / "deletion_requests.csv",
) -> list[dict[str, Any]]:
    requests = read_csv(request_path)
    identities = read_csv(DATASET / "user_identities.csv")
    history = read_csv(DATASET / "user_audit_log.csv")
    manifest = read_csv(DATASET / "evidence_files.csv")
    activities = read_csv(DATASET / "system_activity.csv")
    policy = {
        row["data_category"]: row
        for row in read_csv(DATASET / "deletion_rules.csv")
    }
    aliases, profiles = identity_index(identities, history)
    evidence = load_evidence(manifest)
    results = [audit_case(row, evidence, activities, policy, aliases, profiles, history) for row in requests]
    validate_output(sorted(results, key=lambda row: row["case_id"]), requests)
    write_output(results, output_path)
    statuses: dict[str, int] = defaultdict(int)
    for row in results:
        statuses[row["deletion_status"]] += 1
    print(f"Wrote {len(results)} cases to {output_path}")
    print("Statuses: " + ", ".join(f"{key}={statuses[key]}" for key in sorted(statuses)))
    print(f"Evidence records parsed: {len(evidence)}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT, help="Output CSV path (default: repository root/output.csv)")
    parser.add_argument("--requests", type=Path, default=DATASET / "deletion_requests.csv", help="Request CSV path")
    args = parser.parse_args()
    run(args.output.resolve(), args.requests.resolve())


if __name__ == "__main__":
    main()
