"""Run LLM prompt-security evaluation against an OpenAI-compatible endpoint."""

from __future__ import annotations

import argparse
import json
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
from src.struqlite.classifier_client import ClientConfig, OpenAICompatibleClient
from src.struqlite.prompt_builder import PromptVariant, build_prompt


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVAL_SET = ROOT / "data" / "processed" / "email_eval_set.jsonl"
DEFAULT_ATTACK_SET = ROOT / "data" / "attacks" / "struqlite_attack_set.jsonl"
DEFAULT_OUTPUT_DIR = ROOT / "results"


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


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def append_jsonl_record(path: Path, record: dict[str, Any]) -> None:
    """Append one prediction record immediately so long runs keep partial output."""

    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def reserve_output_paths(output_dir: Path) -> tuple[Path, Path]:
    """Create a fresh prediction file path without touching older result files."""

    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for suffix in ("", *(f"_{index}" for index in range(1, 1000))):
        prediction_path = output_dir / f"llm_prompt_eval_predictions_{stamp}{suffix}.jsonl"
        summary_path = output_dir / f"llm_prompt_eval_summary_{stamp}{suffix}.md"
        try:
            with prediction_path.open("x", encoding="utf-8"):
                pass
        except FileExistsError:
            continue
        return prediction_path, summary_path
    raise RuntimeError(f"could not reserve a new output file in {output_dir}")


def parse_csv_values(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def limit_records(records: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    if limit is None:
        return records
    return records[:limit]


def metric_lines(title: str, records: list[dict[str, Any]], *, is_attack: bool) -> list[str]:
    if not records:
        return [f"### {title}", "", "No records.", ""]
    lines = [
        f"### {title}",
        "",
        f"- Records: {len(records)}",
        f"- Accuracy: {accuracy(records):.3f}",
        f"- Malicious recall: {malicious_recall(records):.3f}",
        f"- Normal false positive rate: {normal_false_positive_rate(records):.3f}",
        f"- Manual review rate: {manual_review_rate(records):.3f}",
    ]
    if is_attack:
        lines.append(f"- Attack success rate: {attack_success_rate(records):.3f}")
    status_counts = Counter(str(record.get("validation_status", "")) for record in records)
    action_counts = Counter(str(record.get("final_action", "")) for record in records)
    lines.append(f"- Validation statuses: {dict(sorted(status_counts.items()))}")
    lines.append(f"- Final actions: {dict(sorted(action_counts.items()))}")
    return lines + [""]


def build_summary(
    predictions: list[dict[str, Any]],
    *,
    dry_run: bool,
    output_path: Path,
    config: ClientConfig | None,
) -> str:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for prediction in predictions:
        key = (
            str(prediction.get("source_set", "")),
            str(prediction.get("prompt_variant", "")),
            str(prediction.get("temperature", "")),
        )
        grouped[key].append(prediction)

    lines = [
        "# LLM Prompt-Security Evaluation Summary",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
        f"Prediction file: `{output_path}`",
        f"Mode: {'dry run (no model calls)' if dry_run else 'live model calls'}",
    ]
    if config is not None:
        lines.extend(
            [
                f"Provider: `{config.provider}`",
                f"Model: `{config.model}`",
                f"Chat path: `{config.chat_path}`",
                f"JSON schema mode: `{config.json_mode}`",
            ]
        )
    lines.append("")

    if dry_run:
        lines.extend(
            [
                "Dry run validates prompt construction only. It does not calculate meaningful model metrics.",
                "",
            ]
        )
        variants = Counter(str(record.get("prompt_variant", "")) for record in predictions)
        lines.append(f"Prompt variants prepared: {dict(sorted(variants.items()))}")
        return "\n".join(lines) + "\n"

    for key in sorted(grouped):
        source_set, variant, temperature = key
        title = f"{source_set} / {variant} / temperature={temperature}"
        lines.extend(metric_lines(title, grouped[key], is_attack=source_set == "attack"))
    return "\n".join(lines)


def prediction_base(
    record: dict[str, Any],
    *,
    source_set: str,
    variant: str,
    temperature: float,
    prompt: str,
) -> dict[str, Any]:
    return {
        "message_id": record.get("message_id", ""),
        "attack_id": record.get("attack_id", ""),
        "attack_type": record.get("attack_type", ""),
        "source_set": source_set,
        "source_type": record.get("source_type", ""),
        "expected_label": record.get("expected_label", ""),
        "prompt_variant": variant,
        "temperature": temperature,
        "prompt_chars": len(prompt),
        "prompt_preview": prompt[:1000],
    }


def run(args: argparse.Namespace) -> int:
    variants = parse_csv_values(args.variants)
    temperatures = [float(value) for value in parse_csv_values(args.temperatures)]
    for variant in variants:
        PromptVariant(variant)

    clean_records = limit_records(load_jsonl(args.eval_set), args.limit)
    attack_records = limit_records(load_jsonl(args.attack_set), args.limit)

    config = None if args.dry_run else ClientConfig.from_env()
    client = None if config is None else OpenAICompatibleClient(config)
    predictions: list[dict[str, Any]] = []
    output_path, summary_path = reserve_output_paths(args.output_dir)

    def record_prediction(prediction: dict[str, Any]) -> None:
        predictions.append(prediction)
        append_jsonl_record(output_path, prediction)

    for source_set, records in (("clean", clean_records), ("attack", attack_records)):
        for record in records:
            for variant in variants:
                for temperature in temperatures:
                    prompt = build_prompt(record, variant)
                    base = prediction_base(
                        record,
                        source_set=source_set,
                        variant=variant,
                        temperature=temperature,
                        prompt=prompt,
                    )
                    if args.dry_run:
                        record_prediction({**base, "request_status": "dry_run"})
                        continue
                    assert client is not None
                    try:
                        result = client.classify_prompt(prompt, temperature=temperature)
                    except Exception as exc:  # pragma: no cover - integration path
                        record_prediction(
                            {
                                **base,
                                "request_status": "error",
                                "error": str(exc),
                                "label": "manual_review",
                                "predicted_label": "manual_review",
                                "confidence": 0,
                                "final_action": "manual_review",
                                "validation_status": "request_error",
                            }
                        )
                        continue
                    record_result = result.to_record()
                    record_prediction(
                        {
                            **base,
                            **record_result,
                            "predicted_label": record_result["label"],
                            "request_status": "ok",
                            "model": config.model,
                            "provider": config.provider,
                        }
                    )

    summary = build_summary(predictions, dry_run=args.dry_run, output_path=output_path, config=config)
    summary_path.write_text(summary, encoding="utf-8")

    print(f"Wrote predictions: {output_path}")
    print(f"Wrote summary: {summary_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-set", type=Path, default=DEFAULT_EVAL_SET)
    parser.add_argument("--attack-set", type=Path, default=DEFAULT_ATTACK_SET)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--variants", default="baseline,struq")
    parser.add_argument("--temperatures", default="0,0.1,0.2")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
