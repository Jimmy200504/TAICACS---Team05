"""Run n8n webhook end-to-end evaluation and summarize routing behavior."""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.evaluation.metrics import (
    accuracy,
    attack_success_rate,
    malicious_recall,
    manual_review_rate,
    normal_false_positive_rate,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVAL_SET = ROOT / "data" / "processed" / "email_eval_set.jsonl"
DEFAULT_ATTACK_SET = ROOT / "data" / "attacks" / "struqlite_attack_set.jsonl"
DEFAULT_OUTPUT_DIR = ROOT / "results"
DEFAULT_WEBHOOK_URL = "http://127.0.0.1:5678/webhook/email-triage-poc"
EMAIL_FIELDS = (
    "message_id",
    "from",
    "reply_to",
    "subject",
    "body_text",
    "body_html",
    "urls",
    "attachment_names",
    "received_at",
)
UNSAFE_MALICIOUS_ACTIONS = {"allow", "archive"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            value = json.loads(stripped)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: row must be a JSON object")
            records.append(value)
    return records


def select_records(records: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    return records if limit is None else records[:limit]


def webhook_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {field: record.get(field, "" if field not in {"urls", "attachment_names"} else []) for field in EMAIL_FIELDS}


def post_webhook(url: str, payload: dict[str, Any], *, timeout: int) -> tuple[int, dict[str, Any], str]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, {}, body
    parsed: dict[str, Any] = {}
    try:
        value = json.loads(body)
        if isinstance(value, dict):
            parsed = value
    except json.JSONDecodeError:
        parsed = {}
    return status, parsed, body


def prediction_base(record: dict[str, Any], *, source_set: str) -> dict[str, Any]:
    return {
        "message_id": record.get("message_id", ""),
        "attack_id": record.get("attack_id", ""),
        "attack_type": record.get("attack_type", ""),
        "source_set": source_set,
        "source_type": record.get("source_type", ""),
        "expected_label": record.get("expected_label", ""),
        "expected_safe_action": record.get("expected_safe_action", ""),
    }


def append_record(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def reserve_paths(output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for suffix in ("", *(f"_{index}" for index in range(1, 1000))):
        predictions_path = output_dir / f"n8n_webhook_eval_predictions_{stamp}{suffix}.jsonl"
        summary_path = output_dir / f"n8n_webhook_eval_summary_{stamp}{suffix}.md"
        try:
            with predictions_path.open("x", encoding="utf-8"):
                pass
        except FileExistsError:
            continue
        return predictions_path, summary_path
    raise RuntimeError(f"could not reserve output path in {output_dir}")


def metric_block(title: str, records: list[dict[str, Any]], *, is_attack: bool) -> list[str]:
    if not records:
        return [f"## {title}", "", "No records.", ""]
    lines = [
        f"## {title}",
        "",
        f"- Records: {len(records)}",
        f"- Accuracy: {accuracy(records):.3f}",
        f"- Malicious recall: {malicious_recall(records):.3f}",
        f"- Normal false positive rate: {normal_false_positive_rate(records):.3f}",
        f"- Manual review rate: {manual_review_rate(records):.3f}",
    ]
    if is_attack:
        lines.append(f"- Attack success rate: {attack_success_rate(records):.3f}")
    for field, label in (
        ("request_status", "Request statuses"),
        ("validation_status", "Validation statuses"),
        ("final_action", "Final actions"),
        ("route_name", "Routes"),
        ("alert_status", "Alert statuses"),
    ):
        counts = Counter(str(record.get(field, "")) for record in records)
        lines.append(f"- {label}: {dict(sorted(counts.items()))}")
    return lines + [""]


def summarize(records: list[dict[str, Any]], *, predictions_path: Path, webhook_url: str, dry_run: bool) -> str:
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_source[str(record.get("source_set", ""))].append(record)

    unsafe = [
        record
        for record in records
        if record.get("source_set") == "attack"
        and record.get("expected_label") == "malicious"
        and str(record.get("final_action", "")) in UNSAFE_MALICIOUS_ACTIONS
    ]
    not_registered_count = sum(
        1
        for record in records
        if record.get("http_status") == 404
        and "webhook" in str(record.get("raw_response_preview", "")).lower()
        and "not registered" in str(record.get("raw_response_preview", "")).lower()
    )
    lines = [
        "# n8n Webhook End-to-End Evaluation Summary",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
        f"Webhook URL: `{webhook_url}`",
        f"Prediction file: `{predictions_path}`",
        f"Mode: {'dry run (no webhook calls)' if dry_run else 'live n8n webhook calls'}",
        "",
    ]
    lines.extend(metric_block("Overall", records, is_attack=False))
    lines.extend(metric_block("Clean Emails", by_source.get("clean", []), is_attack=False))
    lines.extend(metric_block("Prompt-Injection Attacks", by_source.get("attack", []), is_attack=True))
    lines.extend(
        [
            "## Unsafe Attack Actions",
            "",
            f"- Unsafe attacked-malicious actions: {len(unsafe)}",
        ]
    )
    for record in unsafe[:10]:
        lines.append(
            f"- {record.get('message_id')} ({record.get('attack_type')}): "
            f"final_action={record.get('final_action')}, label={record.get('label')}"
        )
    if not_registered_count:
        lines.extend(
            [
                "",
                "## Webhook Registration Errors",
                "",
                f"- n8n webhook-not-registered responses: {not_registered_count}",
                "- For batch evaluation, activate the workflow and use `/webhook/email-triage-poc`.",
                "- The `/webhook-test/email-triage-poc` URL is only for temporary test executions from the n8n UI.",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    webhook_url = args.webhook_url or os.environ.get("N8N_WEBHOOK_URL", DEFAULT_WEBHOOK_URL)
    clean_records = select_records(load_jsonl(args.eval_set), args.limit_clean)
    attack_records = select_records(load_jsonl(args.attack_set), args.limit_attack)
    predictions_path, summary_path = reserve_paths(args.output_dir)

    predictions: list[dict[str, Any]] = []
    for source_set, records in (("clean", clean_records), ("attack", attack_records)):
        for record in records:
            base = prediction_base(record, source_set=source_set)
            payload = webhook_payload(record)
            if args.dry_run:
                prediction = {
                    **base,
                    "request_status": "dry_run",
                    "predicted_label": "dry_run",
                    "label": "dry_run",
                    "final_action": "dry_run",
                    "validation_status": "dry_run",
                    "route_name": "dry_run",
                }
                predictions.append(prediction)
                append_record(predictions_path, prediction)
                continue
            status, parsed, raw_body = post_webhook(webhook_url, payload, timeout=args.timeout)
            prediction = {
                **base,
                "http_status": status,
                "request_status": "ok" if 200 <= status < 300 and parsed else "error",
                "raw_response_preview": raw_body[:2000],
                "response": parsed,
                "predicted_label": parsed.get("label", ""),
                "label": parsed.get("label", ""),
                "confidence": parsed.get("confidence", ""),
                "recommended_action": parsed.get("recommended_action", ""),
                "final_action": parsed.get("final_action", ""),
                "validation_status": parsed.get("validation_status", ""),
                "validation_errors": parsed.get("validation_errors", []),
                "route_name": parsed.get("route_name", ""),
                "route_status": parsed.get("route_status", ""),
                "alert_status": parsed.get("alert_status", ""),
                "model": parsed.get("model", ""),
                "llm_provider": parsed.get("llm_provider", ""),
                "llm_base_url": parsed.get("llm_base_url", ""),
            }
            predictions.append(prediction)
            append_record(predictions_path, prediction)
            if args.sleep_seconds > 0:
                time.sleep(args.sleep_seconds)

    summary = summarize(predictions, predictions_path=predictions_path, webhook_url=webhook_url, dry_run=args.dry_run)
    summary_path.write_text(summary, encoding="utf-8")
    print(f"Wrote n8n webhook predictions: {predictions_path}")
    print(f"Wrote n8n webhook summary: {summary_path}")
    if not args.dry_run and any(record.get("request_status") == "error" for record in predictions):
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--webhook-url", default="")
    parser.add_argument("--eval-set", type=Path, default=DEFAULT_EVAL_SET)
    parser.add_argument("--attack-set", type=Path, default=DEFAULT_ATTACK_SET)
    parser.add_argument("--limit-clean", type=int, default=5)
    parser.add_argument("--limit-attack", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
