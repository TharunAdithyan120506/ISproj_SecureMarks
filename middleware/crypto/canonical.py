"""Canonical marks record: the exact bytes that are hashed, signed and stored."""
from __future__ import annotations

import json
from datetime import datetime, timezone

RECORD_FIELDS = ("course", "roll_no", "midsem", "endsem", "total", "teacher", "published_at")
MIDSEM_MAX = 50
ENDSEM_MAX = 100


class RecordError(ValueError):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_record(course: str, roll_no: str, midsem: int, endsem: int, teacher: str,
                 published_at: str | None = None) -> dict:
    record = {
        "course": course,
        "roll_no": str(roll_no),
        "midsem": int(midsem),
        "endsem": int(endsem),
        "total": int(midsem) + int(endsem),
        "teacher": teacher,
        "published_at": published_at or now_iso(),
    }
    validate_record(record)
    return record


def validate_record(record: dict) -> None:
    if not isinstance(record, dict) or set(record) != set(RECORD_FIELDS):
        raise RecordError(f"record must have exactly the fields {', '.join(RECORD_FIELDS)}")
    if not isinstance(record["course"], str) or not record["course"]:
        raise RecordError("course must be a non-empty string")
    if not isinstance(record["roll_no"], str) or not record["roll_no"].isdigit():
        raise RecordError("roll_no must be a string of digits")
    for name, top in (("midsem", MIDSEM_MAX), ("endsem", ENDSEM_MAX)):
        v = record[name]
        if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= top:
            raise RecordError(f"{name} must be an integer between 0 and {top}")
    if record["total"] != record["midsem"] + record["endsem"]:
        raise RecordError("total must equal midsem + endsem")
    try:
        datetime.fromisoformat(record["published_at"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise RecordError("published_at must be ISO 8601") from exc


def canonical_record(record: dict) -> bytes:
    validate_record(record)
    return canonical(record)
