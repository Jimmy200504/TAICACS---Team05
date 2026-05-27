# StruQ-Protected Email Triage Automation

This repository contains a proof-of-concept email security triage system built with n8n and a local LLM. The system classifies incoming emails as `normal`, `trash`, or `malicious`, while using a StruQ-style prompt structure to reduce prompt injection risk from untrusted email content.

The current implementation is the Week 14 baseline prototype: a webhook-driven n8n workflow that receives sample email JSON, filters and formats it into separated instruction/data channels, calls Ollama, validates the model output, and returns a deterministic routing action.

## Project Goals

- Ingest email-like JSON through an automated n8n workflow.
- Treat all email fields as untrusted data.
- Build a structured LLM query with separate instruction and input channels.
- Remove reserved StruQ delimiters from user-controlled content before prompting.
- Require JSON output from the model and validate it before routing.
- Safely fall back to `manual_review` when the model output is invalid, unknown, or low confidence.

## Repository Layout

```text
.
+-- docs/
|   +-- spec.md                         # Full project specification
|   +-- StruQ Paper.pdf                  # Reference paper
|   +-- week14/                          # Week 14 progress report and screenshots
+-- n8n/
|   +-- README.md                        # Detailed n8n setup and demo guide
|   +-- workflows/
|       +-- email_triage_poc.json        # Exported n8n workflow
+-- README.md                           # Project entry point
```

## System Overview

```text
Webhook input
  -> Extract email fields
  -> Normalize and apply StruQ delimiter filter
  -> Build structured query
  -> Call local Ollama model
  -> Validate JSON response
  -> Return final routing action
```

The LLM only receives trusted instructions in the `[INST]` section. Email content is placed in the `[INPT]` section after filtering. If an email includes text such as `Ignore previous instructions` or fake response delimiters, that text is treated as data to classify, not as workflow or model instructions.

## Requirements

- n8n running locally at `http://127.0.0.1:5678`
- Ollama running locally at `http://127.0.0.1:11434`
- Ollama model:

```bash
ollama pull llama3.2:3b
```

Check that the model is available:

```bash
ollama list
```

## Quick Start

1. Start n8n.
2. Start Ollama.
3. Import the workflow from `n8n/workflows/email_triage_poc.json`.
4. In n8n, open the workflow and click **Listen for test event** on the webhook node.
5. Send a sample email payload to the test webhook:

```bash
curl -X POST http://127.0.0.1:5678/webhook-test/email-triage-poc \
  -H "Content-Type: application/json" \
  -d '{
    "message_id": "demo-malicious-001",
    "from": "it-support@example-login.com",
    "reply_to": "security-update@example-login.com",
    "subject": "Urgent: verify your account password",
    "body_text": "Your mailbox will be disabled today. Verify your account password immediately at the link below to avoid losing access.",
    "body_html": "",
    "urls": ["https://example-login.com/verify-password"],
    "attachment_names": []
  }'
```

The response should contain a validated classification and final action:

```json
{
  "message_id": "demo-malicious-001",
  "label": "malicious",
  "confidence": 0.9,
  "recommended_action": "quarantine",
  "final_action": "quarantine",
  "validation_status": "valid"
}
```

Exact confidence and reason text can vary because they are produced by the model.