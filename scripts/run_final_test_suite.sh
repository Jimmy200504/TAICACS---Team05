#!/usr/bin/env sh
set -eu

echo "== Unit tests =="
./scripts/run_unit_tests.sh

echo
echo "== Dataset validation =="
./scripts/run_data_validation.sh

echo
echo "== JSON validator guardrails =="
./scripts/run_validator_guardrail_tests.sh

echo
echo "== LLM endpoint compatibility =="
./scripts/check_llm_endpoint.sh

if [ "${RUN_N8N_CONNECTIVITY_CHECK:-0}" = "1" ]; then
  echo
  echo "== n8n container -> LLM connectivity =="
  ./scripts/check_n8n_llm_connectivity.sh
fi

if [ "${RUN_N8N_WEBHOOK_EVAL:-0}" = "1" ]; then
  echo
  echo "== n8n webhook end-to-end evaluation =="
  ./scripts/run_n8n_webhook_eval.sh "$@"
fi

if [ "${RUN_FINETUNED_ENDPOINT_CHECK:-0}" = "1" ]; then
  echo
  echo "== Fine-tuned LLM endpoint compatibility =="
  ./scripts/check_finetuned_llm_endpoint.sh
fi
