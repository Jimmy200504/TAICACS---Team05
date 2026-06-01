param(
  [string]$Provider = "lm-studio",
  [string]$BaseUrl = "http://127.0.0.1:1234",
  [string]$ChatPath = "/v1/chat/completions",
  [string]$ModelsPath = "/api/v1/models",
  [string]$Model = "google/gemma-4-e4b",
  [string]$Temperature = "0.1",
  [string]$TopP = "0.9",
  [string]$MaxTokens = "512",
  [string]$JsonMode = "false",
  [string]$ApiKey = "",
  [string]$AlertWebhookUrl = ""
)

$env:LLM_PROVIDER = $Provider
$env:LLM_BASE_URL = $BaseUrl
$env:LLM_CHAT_PATH = $ChatPath
$env:LLM_MODELS_PATH = $ModelsPath
$env:LLM_MODEL = $Model
$env:LLM_TEMPERATURE = $Temperature
$env:LLM_TOP_P = $TopP
$env:LLM_MAX_TOKENS = $MaxTokens
$env:LLM_JSON_MODE = $JsonMode

if ($ApiKey) {
  $env:LLM_API_KEY = $ApiKey
}

if ($AlertWebhookUrl) {
  $env:ALERT_WEBHOOK_URL = $AlertWebhookUrl
}

Write-Host "Loaded n8n LLM environment variables:"
Write-Host "  LLM_PROVIDER=$env:LLM_PROVIDER"
Write-Host "  LLM_BASE_URL=$env:LLM_BASE_URL"
Write-Host "  LLM_CHAT_PATH=$env:LLM_CHAT_PATH"
Write-Host "  LLM_MODELS_PATH=$env:LLM_MODELS_PATH"
Write-Host "  LLM_MODEL=$env:LLM_MODEL"
Write-Host "  LLM_TEMPERATURE=$env:LLM_TEMPERATURE"
Write-Host "  LLM_TOP_P=$env:LLM_TOP_P"
Write-Host "  LLM_MAX_TOKENS=$env:LLM_MAX_TOKENS"
Write-Host "  LLM_JSON_MODE=$env:LLM_JSON_MODE"
Write-Host ""
Write-Host "Start n8n from this PowerShell session so it inherits these values:"
Write-Host "  n8n"
