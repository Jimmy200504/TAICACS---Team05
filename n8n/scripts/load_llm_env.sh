#!/usr/bin/env bash

# Source this file so the variables remain in your current shell:
#   source scripts/load_llm_env.sh
#
# Override any value before sourcing if needed:
#   export LLM_MODEL="another/model"
#   source scripts/load_llm_env.sh

export LLM_PROVIDER="${LLM_PROVIDER:-lm-studio}"
export LLM_BASE_URL="${LLM_BASE_URL:-http://127.0.0.1:1234}"
export LLM_CHAT_PATH="${LLM_CHAT_PATH:-/v1/chat/completions}"
export LLM_MODELS_PATH="${LLM_MODELS_PATH:-/api/v1/models}"
export LLM_MODEL="${LLM_MODEL:-google/gemma-4-e4b}"
export LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.1}"
export LLM_TOP_P="${LLM_TOP_P:-0.9}"
export LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-512}"
export LLM_JSON_MODE="${LLM_JSON_MODE:-false}"

if [ -n "${LLM_API_KEY:-}" ]; then
  export LLM_API_KEY
fi

if [ -n "${ALERT_WEBHOOK_URL:-}" ]; then
  export ALERT_WEBHOOK_URL
fi

echo "Loaded n8n LLM environment variables:"
echo "  LLM_PROVIDER=$LLM_PROVIDER"
echo "  LLM_BASE_URL=$LLM_BASE_URL"
echo "  LLM_CHAT_PATH=$LLM_CHAT_PATH"
echo "  LLM_MODELS_PATH=$LLM_MODELS_PATH"
echo "  LLM_MODEL=$LLM_MODEL"
echo "  LLM_TEMPERATURE=$LLM_TEMPERATURE"
echo "  LLM_TOP_P=$LLM_TOP_P"
echo "  LLM_MAX_TOKENS=$LLM_MAX_TOKENS"
echo "  LLM_JSON_MODE=$LLM_JSON_MODE"
echo ""
echo "Start n8n from this shell so it inherits these values:"
echo "  n8n"
