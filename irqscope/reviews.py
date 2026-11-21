"""Versioned, IDA-independent analyst review records."""

import hashlib
import json
import time
from typing import Dict, Optional


REVIEW_FORMAT = "irqscope-review-ledger-v1"
REVIEW_STATUSES = ("open", "confirmed", "dismissed")
MAX_REVIEW_NOTE_CHARS = 8_000
MAX_REVIEW_RECORDS = 100_000
MAX_REVIEW_PAYLOAD_BYTES = 16 * 1024 * 1024


def _valid_key(key: str) -> bool:
    return len(key) == 64 and all(character in "0123456789abcdef" for character in key.lower())


def finding_key(input_sha256: str, svd_sha256: str, finding) -> str:
    """Stable within the same input, device model, and observed access pair."""
    accesses = sorted((
        (int(finding.first.function_ea), int(finding.first.ea)),
        (int(finding.second.function_ea), int(finding.second.ea)),
    ))
    identity = {
        "input_sha256": input_sha256 or "unknown-input",
        "svd_sha256": svd_sha256 or "unknown-svd",
        "rule_id": finding.rule_id,
        "address": int(finding.address),
        "accesses": accesses,
    }
    protocol_identity = getattr(finding, "protocol_identity", None)
    if protocol_identity:
        identity["protocol"] = {
            "contract_sha256": protocol_identity,
            "transaction": getattr(finding, "protocol_name", None),
            "events": [(int(item.function_ea), int(item.ea))
                       for item in getattr(finding, "protocol_events", ())],
            "interrupt_events": [(int(item.function_ea), int(item.ea))
                                  for item in getattr(finding, "protocol_interrupt_events", ())],
            "insertion_index": getattr(finding, "protocol_insertion_index", None),
        }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ReviewLedger:
    def __init__(self, records: Optional[Dict[str, dict]] = None):
        self._records = dict(records or {})

    def get(self, key: str) -> dict:
        value = self._records.get(key)
        return dict(value) if value else {"status": "open", "note": "", "updated_unix_time": None}

    def set(self, key: str, status: str, note: str = "") -> dict:
        if not isinstance(key, str) or not _valid_key(key):
            raise ValueError("Review key must be a SHA-256 hex digest")
        status = str(status).strip().lower()
        if status not in REVIEW_STATUSES:
            raise ValueError(f"Review status must be one of: {', '.join(REVIEW_STATUSES)}")
        note = str(note).strip()
        if len(note) > MAX_REVIEW_NOTE_CHARS:
            raise ValueError(f"Review notes are limited to {MAX_REVIEW_NOTE_CHARS} characters")
        if key not in self._records and len(self._records) >= MAX_REVIEW_RECORDS:
            raise ValueError(f"Review ledger is limited to {MAX_REVIEW_RECORDS} findings")
        record = {"status": status, "note": note, "updated_unix_time": int(time.time())}
        self._records[key] = record
        return dict(record)

    def to_json(self) -> str:
        payload = json.dumps({
            "format": REVIEW_FORMAT,
            "schema_version": 1,
            "records": self._records,
        }, sort_keys=True, separators=(",", ":"))
        if len(payload.encode("utf-8")) > MAX_REVIEW_PAYLOAD_BYTES:
            raise ValueError(f"Review ledger exceeds {MAX_REVIEW_PAYLOAD_BYTES // (1024 * 1024)} MiB")
        return payload

    @classmethod
    def from_json(cls, payload) -> "ReviewLedger":
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        if not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_REVIEW_PAYLOAD_BYTES:
            raise ValueError("Review ledger payload is missing or exceeds its size limit")
        document = json.loads(payload)
        if not isinstance(document, dict) or document.get("format") != REVIEW_FORMAT:
            raise ValueError("Unsupported IRQScope review ledger format")
        if document.get("schema_version") != 1:
            raise ValueError("Unsupported IRQScope review ledger schema version")
        records = document.get("records")
        if not isinstance(records, dict) or len(records) > MAX_REVIEW_RECORDS:
            raise ValueError("Invalid or oversized IRQScope review records")
        validated = {}
        for key, record in records.items():
            if (not isinstance(key, str) or not _valid_key(key)
                    or not isinstance(record, dict)
                    or record.get("status") not in REVIEW_STATUSES
                    or not isinstance(record.get("note", ""), str)
                    or len(record.get("note", "")) > MAX_REVIEW_NOTE_CHARS):
                raise ValueError("Invalid record in IRQScope review ledger")
            updated = record.get("updated_unix_time")
            if updated is not None and not isinstance(updated, int):
                raise ValueError("Invalid review timestamp in IRQScope ledger")
            validated[key] = {
                "status": record["status"],
                "note": record.get("note", ""),
                "updated_unix_time": updated,
            }
        return cls(validated)

    def records(self) -> Dict[str, dict]:
        return {key: dict(value) for key, value in self._records.items()}
