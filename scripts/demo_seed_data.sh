#!/usr/bin/env sh
set -eu

python3 - <<'PY'
import json
from pathlib import Path

paths = [
    Path("data/processed/email_eval_set.jsonl"),
    Path("data/attacks/struqlite_attack_set.jsonl"),
]

for path in paths:
    print(f"== {path} ==")
    with path.open(encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if index >= 2:
                break
            record = json.loads(line)
            print(json.dumps({
                "message_id": record["message_id"],
                "expected_label": record["expected_label"],
                "subject": record["subject"],
            }, ensure_ascii=False))
    print()
PY
