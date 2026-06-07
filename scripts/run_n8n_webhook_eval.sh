#!/usr/bin/env sh
set -eu

python3 -m src.evaluation.run_n8n_webhook_eval "$@"
