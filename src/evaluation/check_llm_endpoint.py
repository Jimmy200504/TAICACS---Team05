"""Check an OpenAI-compatible LLM endpoint for final integration evidence."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = ROOT / "results"


def build_chat_url(base_url: str, chat_path: str) -> str:
    return f"{base_url.rstrip('/')}/{chat_path.lstrip('/')}"


def post_json(url: str, payload: dict[str, Any], *, api_key: str, timeout: int) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"request failed: {exc}") from exc
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"endpoint returned non-object JSON with status {status}")
    parsed["_http_status"] = status
    return parsed


def extract_content(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
            if isinstance(first.get("text"), str):
                return first["text"]
    for key in ("response", "text", "output"):
        if isinstance(response.get(key), str):
            return str(response[key])
    return ""


def is_json_object(text: str) -> bool:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(value, dict)


def run(args: argparse.Namespace) -> int:
    base_url = args.base_url or os.environ.get("GLOWS_BASE_URL", "http://127.0.0.1:18001")
    api_key = args.api_key if args.api_key is not None else os.environ.get("GLOWS_API_KEY", "0")
    model = args.model or os.environ.get("GLOWS_MODEL", "gpt-3.5-turbo")
    chat_path = args.chat_path or os.environ.get("GLOWS_CHAT_PATH", "/v1/chat/completions")
    chat_url = build_chat_url(base_url, chat_path)

    base_payload = {
        "model": model,
        "messages": [{"role": "user", "content": 'Return a short JSON object with key "ok".'}],
        "temperature": 0.1,
        "top_p": 0.9,
        "max_tokens": 128,
        "stream": False,
    }
    basic_response = post_json(chat_url, base_payload, api_key=api_key, timeout=args.timeout)
    basic_content = extract_content(basic_response)
    if not basic_content:
        raise RuntimeError("endpoint response did not contain assistant message content")

    schema_payload = {
        **base_payload,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "endpoint_check",
                "strict": True,
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                },
            },
        },
    }
    schema_status = "not_checked"
    schema_content = ""
    try:
        schema_response = post_json(chat_url, schema_payload, api_key=api_key, timeout=args.timeout)
        schema_content = extract_content(schema_response)
        schema_status = "appears_enforced" if is_json_object(schema_content) else "not_enforced"
    except Exception as exc:  # pragma: no cover - external endpoint path
        schema_status = f"unsupported_or_error: {exc}"

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "chat_url": chat_url,
        "model": model,
        "basic_http_status": basic_response.get("_http_status"),
        "basic_response_has_choices": isinstance(basic_response.get("choices"), list),
        "basic_content_preview": basic_content[:500],
        "strict_json_schema_status": schema_status,
        "strict_json_schema_content_preview": schema_content[:500],
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = args.output_dir / f"llm_endpoint_check_{stamp}.json"
    md_path = args.output_dir / f"llm_endpoint_check_{stamp}.md"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(
        "\n".join(
            [
                "# LLM Endpoint Compatibility Check",
                "",
                f"Generated at: {result['generated_at']}",
                f"Chat URL: `{chat_url}`",
                f"Model: `{model}`",
                "",
                f"- Basic chat-completions status: `{result['basic_http_status']}`",
                f"- OpenAI-style choices present: `{result['basic_response_has_choices']}`",
                f"- Strict JSON schema status: `{schema_status}`",
                "",
                "Basic response preview:",
                "",
                "```text",
                basic_content[:500],
                "```",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote endpoint check JSON: {json_path}")
    print(f"Wrote endpoint check summary: {md_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="")
    parser.add_argument("--chat-path", default="")
    parser.add_argument("--model", default="")
    parser.add_argument("--api-key")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
