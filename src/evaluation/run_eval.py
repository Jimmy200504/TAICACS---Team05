"""Validate and summarize the current evaluation data."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVAL_SET = ROOT / "data" / "processed" / "email_eval_set.jsonl"
DEFAULT_ATTACK_SET = ROOT / "data" / "attacks" / "struqlite_attack_set.jsonl"
DEFAULT_RAW_FILES = (
    ROOT / "data" / "raw" / "normal_emails.csv",
    ROOT / "data" / "raw" / "spam_emails.csv",
    ROOT / "data" / "raw" / "malicious_emails.csv",
)

REQUIRED_EMAIL_FIELDS = {
    "message_id",
    "from",
    "reply_to",
    "subject",
    "body_text",
    "body_html",
    "urls",
    "attachment_names",
    "expected_label",
}
REQUIRED_RAW_FIELDS = REQUIRED_EMAIL_FIELDS | {"rationale"}
ALLOWED_LABELS = {"normal", "trash", "malicious"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: row must be a JSON object")
            records.append(value)
    return records


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def validate_records(records: list[dict[str, Any]], dataset_name: str) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    for index, record in enumerate(records, start=1):
        message_id = str(record.get("message_id", "")).strip()
        missing = sorted(field for field in REQUIRED_EMAIL_FIELDS if field not in record)
        if missing:
            errors.append(f"{dataset_name} row {index}: missing fields: {', '.join(missing)}")
        if not message_id:
            errors.append(f"{dataset_name} row {index}: empty message_id")
        elif message_id in seen_ids:
            errors.append(f"{dataset_name} row {index}: duplicate message_id: {message_id}")
        seen_ids.add(message_id)

        label = str(record.get("expected_label", "")).strip()
        if label not in ALLOWED_LABELS:
            errors.append(f"{dataset_name} row {index}: invalid expected_label: {label!r}")

        for list_field in ("urls", "attachment_names"):
            if not isinstance(record.get(list_field), list):
                errors.append(f"{dataset_name} row {index}: {list_field} must be a list")
    return errors


def validate_raw_records(records_by_file: dict[str, list[dict[str, str]]]) -> list[str]:
    errors: list[str] = []
    for path, records in records_by_file.items():
        for index, record in enumerate(records, start=1):
            missing = sorted(field for field in REQUIRED_RAW_FIELDS if field not in record)
            if missing:
                errors.append(f"{path} row {index}: missing fields: {', '.join(missing)}")
            label = str(record.get("expected_label", "")).strip()
            if label not in ALLOWED_LABELS:
                errors.append(f"{path} row {index}: invalid expected_label: {label!r}")
            for list_field in ("urls", "attachment_names"):
                value = str(record.get(list_field, "")).strip()
                if not (value.startswith("[") and value.endswith("]")):
                    errors.append(f"{path} row {index}: {list_field} must be a JSON-style list string")
    return errors


def counter_lines(title: str, counter: Counter[str]) -> list[str]:
    lines = [title]
    if not counter:
        return lines + ["  - none"]
    width = max(len(key) for key in counter)
    for key in sorted(counter):
        lines.append(f"  - {key:<{width}} : {counter[key]}")
    return lines


def summarize(
    eval_records: list[dict[str, Any]],
    attack_records: list[dict[str, Any]],
    raw_records_by_file: dict[str, list[dict[str, str]]],
) -> str:
    eval_labels = Counter(str(record["expected_label"]) for record in eval_records)
    attack_labels = Counter(str(record["expected_label"]) for record in attack_records)
    attack_types = Counter(str(record.get("attack_type", "unknown")) for record in attack_records)
    source_types = Counter(str(record.get("source_type", "unknown")) for record in eval_records + attack_records)
    raw_labels = Counter()
    for records in raw_records_by_file.values():
        raw_labels.update(str(record.get("expected_label", "")) for record in records)

    lines = [
        "# Data/Evaluation Summary",
        "",
        f"Raw CSV seed emails: {sum(len(records) for records in raw_records_by_file.values())}",
        f"Evaluation seed emails: {len(eval_records)}",
        f"Prompt-injection attack cases: {len(attack_records)}",
        f"Total records prepared: {len(eval_records) + len(attack_records)}",
        "",
    ]
    lines.extend(counter_lines("Raw CSV label distribution:", raw_labels))
    lines.append("")
    lines.extend(counter_lines("Evaluation label distribution:", eval_labels))
    lines.append("")
    lines.extend(counter_lines("Attack expected-label distribution:", attack_labels))
    lines.append("")
    lines.extend(counter_lines("Attack type distribution:", attack_types))
    lines.append("")
    lines.extend(counter_lines("Source type distribution:", source_types))
    lines.append("")
    lines.extend(
        [
            "Validation checks:",
            "  - raw CSV files are readable",
            "  - required webhook fields present",
            "  - expected_label is one of normal/trash/malicious",
            "  - urls and attachment_names are JSON arrays",
            "  - message_id values are non-empty and unique within each file",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-set", type=Path, default=DEFAULT_EVAL_SET)
    parser.add_argument("--attack-set", type=Path, default=DEFAULT_ATTACK_SET)
    parser.add_argument("--raw-files", type=Path, nargs="*", default=list(DEFAULT_RAW_FILES))
    args = parser.parse_args()

    eval_records = load_jsonl(args.eval_set)
    attack_records = load_jsonl(args.attack_set)
    raw_records_by_file = {str(path): load_csv(path) for path in args.raw_files}
    errors = validate_records(eval_records, "evaluation set")
    errors.extend(validate_records(attack_records, "attack set"))
    errors.extend(validate_raw_records(raw_records_by_file))
    if errors:
        print("Validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(summarize(eval_records, attack_records, raw_records_by_file))
    print("")
    print("Validation status: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
