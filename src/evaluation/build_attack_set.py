"""Prepare the prompt-injection attack set from curated source cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "data" / "attacks" / "prompt_injection_cases.jsonl"
DEFAULT_OUTPUT = ROOT / "data" / "attacks" / "struqlite_attack_set.jsonl"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    return records


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def build_attack_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(record) for record in records]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    records = load_jsonl(args.input)
    built = build_attack_records(records)
    write_jsonl(args.output, built)
    print(f"Built {len(built)} prompt-injection attack records: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
