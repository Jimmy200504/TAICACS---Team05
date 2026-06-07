#!/usr/bin/env sh
set -eu

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  python3 -m src.evaluation.check_llm_endpoint "$@"
  exit 0
fi

: "${FINETUNED_MODEL:?Set FINETUNED_MODEL to the fine-tuned model name exposed by LLaMA-Factory or vLLM.}"

python3 -m src.evaluation.check_llm_endpoint \
  --model "$FINETUNED_MODEL" \
  "$@"
