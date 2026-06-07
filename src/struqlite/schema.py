"""LLM output schema and validation guardrails."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


ALLOWED_LABELS = {"normal", "trash", "malicious"}
ALLOWED_ACTIONS = {"allow", "archive", "quarantine", "manual_review"}
CONFIDENCE_THRESHOLD = 0.65

OUTPUT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "label": {"type": "string", "enum": sorted(ALLOWED_LABELS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reason": {"type": "string"},
        "indicators": {"type": "array", "items": {"type": "string"}},
        "recommended_action": {"type": "string", "enum": sorted(ALLOWED_ACTIONS)},
    },
    "required": ["label", "confidence", "reason", "indicators", "recommended_action"],
}


@dataclass(frozen=True)
class ValidationResult:
    label: str
    confidence: float
    reason: str
    indicators: list[str]
    recommended_action: str
    final_action: str
    validation_status: str
    validation_errors: list[str]
    parsed_model_response: dict[str, Any] | None

    def to_record(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "confidence": self.confidence,
            "reason": self.reason,
            "indicators": self.indicators,
            "recommended_action": self.recommended_action,
            "final_action": self.final_action,
            "validation_status": self.validation_status,
            "validation_errors": self.validation_errors,
            "parsed_model_response": self.parsed_model_response,
        }


def response_format_json_schema() -> dict[str, Any]:
    """Return an OpenAI-compatible strict JSON schema response_format object."""

    return {
        "type": "json_schema",
        "json_schema": {
            "name": "email_triage_result",
            "strict": True,
            "schema": OUTPUT_JSON_SCHEMA,
        },
    }


def extract_json_text(raw_response: Any) -> str:
    """Extract a JSON-looking object string from a raw model response."""

    if isinstance(raw_response, dict):
        return json.dumps(raw_response)
    text = "" if raw_response is None else str(raw_response).strip()
    if not text:
        return text
    fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    if start != -1 and end == -1:
        return text[start:]
    return text


def close_truncated_json_object(text: str) -> str:
    """Close a JSON object that appears to be truncated at the final brace."""

    candidate = text.strip()
    if not candidate.startswith("{"):
        return candidate

    depth = 0
    in_string = False
    escaped = False
    for char in candidate:
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_string:
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth < 0:
                return candidate

    if in_string or depth <= 0:
        return candidate
    return candidate + ("}" * depth)


def parse_model_response(raw_response: Any) -> dict[str, Any]:
    text = extract_json_text(raw_response)
    candidates = [text]
    repaired = close_truncated_json_object(text)
    if repaired != text:
        candidates.append(repaired)

    last_error: json.JSONDecodeError | None = None
    parsed: Any = None
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            break
        except json.JSONDecodeError as exc:
            last_error = exc
    else:
        if last_error is not None:
            raise last_error
        parsed = json.loads(text)

    if not isinstance(parsed, dict):
        raise ValueError("model response JSON must be an object")
    return parsed


def _fallback(reason: str, parsed: dict[str, Any] | None = None) -> ValidationResult:
    return ValidationResult(
        label="manual_review",
        confidence=0.0,
        reason=f"Manual review required: {reason}",
        indicators=[],
        recommended_action="manual_review",
        final_action="manual_review",
        validation_status="fallback",
        validation_errors=[reason],
        parsed_model_response=parsed,
    )


def fallback_validation(reason: str, parsed: dict[str, Any] | None = None) -> ValidationResult:
    """Build a deterministic manual-review validation result."""

    return _fallback(reason, parsed)


def final_action_for_label(label: str) -> str:
    if label == "normal":
        return "allow"
    if label == "trash":
        return "archive"
    if label == "malicious":
        return "quarantine"
    return "manual_review"


def validate_parsed_response(parsed: dict[str, Any]) -> ValidationResult:
    label = str(parsed.get("label", "")).strip().lower()
    if label not in ALLOWED_LABELS:
        return _fallback(f"unknown label: {parsed.get('label')}", parsed)

    recommended_action = str(parsed.get("recommended_action", "")).strip().lower()
    if recommended_action not in ALLOWED_ACTIONS:
        return _fallback(f"unknown recommended_action: {parsed.get('recommended_action')}", parsed)

    try:
        confidence = float(parsed.get("confidence"))
    except (TypeError, ValueError):
        return _fallback(f"invalid confidence: {parsed.get('confidence')}", parsed)

    if not 0 <= confidence <= 1:
        return _fallback(f"invalid confidence: {parsed.get('confidence')}", parsed)
    if confidence < CONFIDENCE_THRESHOLD:
        return _fallback(f"low confidence: {confidence}", parsed)

    indicators_value = parsed.get("indicators", [])
    indicators = indicators_value if isinstance(indicators_value, list) else []
    indicators = [str(item) for item in indicators[:10] if item is not None]

    return ValidationResult(
        label=label,
        confidence=confidence,
        reason=str(parsed.get("reason", "")),
        indicators=indicators,
        recommended_action=recommended_action,
        final_action=final_action_for_label(label),
        validation_status="valid",
        validation_errors=[],
        parsed_model_response=parsed,
    )


def validate_model_response(raw_response: Any) -> ValidationResult:
    try:
        parsed = parse_model_response(raw_response)
    except (json.JSONDecodeError, ValueError) as exc:
        return _fallback(f"LLM response was not valid JSON: {exc}")
    return validate_parsed_response(parsed)
