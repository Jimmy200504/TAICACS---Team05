#!/usr/bin/env sh
set -eu

python3 -m src.evaluation.run_n8n_webhook_eval \
  --limit-clean "${N8N_ROUTING_CLEAN_LIMIT:-15}" \
  --limit-attack "${N8N_ROUTING_ATTACK_LIMIT:-12}" \
  "$@"
