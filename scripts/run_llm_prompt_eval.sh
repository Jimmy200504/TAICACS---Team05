#!/usr/bin/env sh
set -eu

python3 -m src.evaluation.run_llm_prompt_eval "$@"
