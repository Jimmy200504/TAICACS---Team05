#!/usr/bin/env sh
set -eu

N8N_CONTAINER="${N8N_CONTAINER:-taicacs-n8n}"
N8N_LLM_BASE_URL="${N8N_LLM_BASE_URL:-http://host.docker.internal:18001}"
N8N_LLM_CHAT_PATH="${N8N_LLM_CHAT_PATH:-/v1/chat/completions}"
N8N_LLM_MODEL="${N8N_LLM_MODEL:-gpt-3.5-turbo}"
N8N_LLM_API_KEY="${N8N_LLM_API_KEY:-0}"

docker exec \
  -e N8N_LLM_BASE_URL="$N8N_LLM_BASE_URL" \
  -e N8N_LLM_CHAT_PATH="$N8N_LLM_CHAT_PATH" \
  -e N8N_LLM_MODEL="$N8N_LLM_MODEL" \
  -e N8N_LLM_API_KEY="$N8N_LLM_API_KEY" \
  "$N8N_CONTAINER" \
  node -e '
const baseUrl = process.env.N8N_LLM_BASE_URL.replace(/\/+$/, "");
const chatPath = process.env.N8N_LLM_CHAT_PATH.startsWith("/")
  ? process.env.N8N_LLM_CHAT_PATH
  : `/${process.env.N8N_LLM_CHAT_PATH}`;
const url = `${baseUrl}${chatPath}`;
const payload = {
  model: process.env.N8N_LLM_MODEL,
  messages: [{ role: "user", content: "Return JSON only: {\"ok\": true}" }],
  temperature: 0.1,
  max_tokens: 128,
  stream: false
};
fetch(url, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${process.env.N8N_LLM_API_KEY || ""}`
  },
  body: JSON.stringify(payload)
}).then(async (response) => {
  const text = await response.text();
  console.log(`status ${response.status}`);
  console.log(text);
  if (!response.ok) process.exit(1);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
'
