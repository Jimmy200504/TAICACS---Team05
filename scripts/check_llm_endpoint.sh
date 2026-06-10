#!/usr/bin/env sh
set -eu

python3 -m src.evaluation.check_llm_endpoint "$@"
