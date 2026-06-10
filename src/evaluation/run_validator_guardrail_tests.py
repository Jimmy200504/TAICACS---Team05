"""Run deterministic JSON validation and fallback guardrail tests."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.struqlite.schema import validate_model_response


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = ROOT / "results"


TEST_CASES: list[dict[str, Any]] = [
    {
        "case_id": "valid_normal",
        "raw_response": {
            "label": "normal",
            "confidence": 0.9,
            "reason": "Routine message.",
            "indicators": ["benign context"],
            "recommended_action": "allow",
        },
        "expected_final_action": "allow",
        "expected_validation_status": "valid",
    },
    {
        "case_id": "valid_trash",
        "raw_response": {
            "label": "trash",
            "confidence": 0.86,
            "reason": "Promotional bulk message.",
            "indicators": ["marketing tone"],
            "recommended_action": "archive",
        },
        "expected_final_action": "archive",
        "expected_validation_status": "valid",
    },
    {
        "case_id": "valid_malicious",
        "raw_response": {
            "label": "malicious",
            "confidence": 0.91,
            "reason": "Credential phishing.",
            "indicators": ["password request", "urgent login URL"],
            "recommended_action": "quarantine",
        },
        "expected_final_action": "quarantine",
        "expected_validation_status": "valid",
    },
    {
        "case_id": "markdown_wrapped_json",
        "raw_response": '```json\n{"label":"normal","confidence":0.88,"reason":"Benign notice.","indicators":["known sender"],"recommended_action":"allow"}\n```',
        "expected_final_action": "allow",
        "expected_validation_status": "valid",
    },
    {
        "case_id": "invalid_json",
        "raw_response": '{"label":"normal","confidence":0.9',
        "expected_final_action": "manual_review",
        "expected_validation_status": "fallback",
    },
    {
        "case_id": "unknown_label",
        "raw_response": {
            "label": "urgent",
            "confidence": 0.9,
            "reason": "Unknown label.",
            "indicators": [],
            "recommended_action": "allow",
        },
        "expected_final_action": "manual_review",
        "expected_validation_status": "fallback",
    },
    {
        "case_id": "unknown_action",
        "raw_response": {
            "label": "normal",
            "confidence": 0.9,
            "reason": "Unsafe action request.",
            "indicators": [],
            "recommended_action": "delete_email",
        },
        "expected_final_action": "manual_review",
        "expected_validation_status": "fallback",
    },
    {
        "case_id": "bad_confidence_type",
        "raw_response": {
            "label": "normal",
            "confidence": "high",
            "reason": "Bad confidence.",
            "indicators": [],
            "recommended_action": "allow",
        },
        "expected_final_action": "manual_review",
        "expected_validation_status": "fallback",
    },
    {
        "case_id": "low_confidence",
        "raw_response": {
            "label": "malicious",
            "confidence": 0.4,
            "reason": "Uncertain phishing.",
            "indicators": ["suspicious URL"],
            "recommended_action": "quarantine",
        },
        "expected_final_action": "manual_review",
        "expected_validation_status": "fallback",
    },
    {
        "case_id": "out_of_range_confidence",
        "raw_response": {
            "label": "trash",
            "confidence": 1.3,
            "reason": "Out of range.",
            "indicators": [],
            "recommended_action": "archive",
        },
        "expected_final_action": "manual_review",
        "expected_validation_status": "fallback",
    },
]


def run(args: argparse.Namespace) -> int:
    records: list[dict[str, Any]] = []
    failures: list[str] = []
    for case in TEST_CASES:
        validation = validate_model_response(case["raw_response"])
        record = {
            "case_id": case["case_id"],
            "expected_final_action": case["expected_final_action"],
            "expected_validation_status": case["expected_validation_status"],
            **validation.to_record(),
        }
        record["passed"] = (
            record["final_action"] == record["expected_final_action"]
            and record["validation_status"] == record["expected_validation_status"]
        )
        if not record["passed"]:
            failures.append(
                f"{case['case_id']}: expected "
                f"{case['expected_validation_status']}/{case['expected_final_action']}, got "
                f"{record['validation_status']}/{record['final_action']}"
            )
        records.append(record)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    jsonl_path = args.output_dir / f"validator_guardrail_results_{stamp}.jsonl"
    md_path = args.output_dir / f"validator_guardrail_summary_{stamp}.md"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    status_counts = Counter(str(record["validation_status"]) for record in records)
    action_counts = Counter(str(record["final_action"]) for record in records)
    md_lines = [
        "# JSON Validator Guardrail Test Summary",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
        f"Result file: `{jsonl_path}`",
        "",
        f"- Cases: {len(records)}",
        f"- Passed: {sum(1 for record in records if record['passed'])}",
        f"- Failed: {len(failures)}",
        f"- Validation statuses: {dict(sorted(status_counts.items()))}",
        f"- Final actions: {dict(sorted(action_counts.items()))}",
        "",
    ]
    if failures:
        md_lines.append("Failures:")
        md_lines.extend(f"- {failure}" for failure in failures)
        md_lines.append("")
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Wrote validator results: {jsonl_path}")
    print(f"Wrote validator summary: {md_path}")
    if failures:
        print("Validation guardrail tests failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
