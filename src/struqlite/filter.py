"""Filtering and normalization for untrusted email content."""

from __future__ import annotations

import html
import json
import re
from typing import Any


RESERVED_STRINGS = ("[MARK]", "[INST]", "[INPT]", "[RESP]", "[COLN]", "##")
MAX_DATA_CHARS = 8000
MODEL_OUTPUT_JSON_KEYS = frozenset(
    {
        "label",
        "confidence",
        "recommended_action",
        "final_action",
    }
)
MODEL_OUTPUT_LABEL_VALUES = frozenset({"normal", "trash", "malicious", "manual_review"})
MODEL_OUTPUT_ACTION_VALUES = frozenset({"allow", "archive", "quarantine", "manual_review"})

SCRIPT_STYLE_RE = re.compile(r"<(?:script|style)\b[\s\S]*?</(?:script|style)>", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
LABEL_FIELD_RE = re.compile(
    r'"label"\s*:\s*"(?:normal|trash|malicious|manual_review)"',
    re.IGNORECASE,
)
ACTION_FIELD_RE = re.compile(
    r'"(?:recommended_action|final_action)"\s*:\s*"(?:allow|archive|quarantine|manual_review)"',
    re.IGNORECASE,
)
CONFIDENCE_FIELD_RE = re.compile(r'"confidence"\s*:\s*(?:0(?:\.\d+)?|1(?:\.0+)?)', re.IGNORECASE)


def recursive_filter(text: Any, reserved_strings: tuple[str, ...] = RESERVED_STRINGS) -> str:
    """Remove reserved StruQ delimiters until no reserved string remains."""

    previous = None
    current = "" if text is None else str(text)
    while previous != current:
        previous = current
        for token in reserved_strings:
            current = current.replace(token, "")
    return current


def strip_html(html_text: Any) -> str:
    """Convert simple HTML content to readable text without script/style blocks."""

    text = "" if html_text is None else str(html_text)
    text = SCRIPT_STYLE_RE.sub(" ", text)
    text = TAG_RE.sub(" ", text)
    return html.unescape(text)


def normalize_controls(text: Any) -> str:
    """Normalize control characters and repeated whitespace for prompt stability."""

    value = "" if text is None else str(text)
    value = re.sub(r"[\r\b\f\v]", " ", value)
    value = re.sub(r"\t+", " ", value)
    value = re.sub(r"[ \u00a0]{2,}", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def sanitize_text(text: Any, *, apply_struq_filter: bool = True) -> str:
    """Normalize text and optionally remove StruQ reserved delimiter strings."""

    value = normalize_controls(text)
    if apply_struq_filter:
        value = recursive_filter(value)
    return value


def _json_object_candidates(text: str, *, max_candidate_chars: int = 2000) -> list[str]:
    """Return balanced JSON-object-looking substrings from untrusted text."""

    candidates: list[str] = []
    for start, char in enumerate(text):
        if char != "{":
            continue
        depth = 0
        in_string = False
        escaped = False
        stop = min(len(text), start + max_candidate_chars)
        for index in range(start, stop):
            current = text[index]
            if escaped:
                escaped = False
                continue
            if current == "\\" and in_string:
                escaped = True
                continue
            if current == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if current == "{":
                depth += 1
            elif current == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start : index + 1])
                    break
    return candidates


def _looks_like_model_output_json(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    normalized = {str(key).strip().lower(): item for key, item in value.items()}
    keys = set(normalized)
    if len(keys & MODEL_OUTPUT_JSON_KEYS) < 2:
        return False
    label = str(normalized.get("label", "")).strip().lower()
    recommended_action = str(normalized.get("recommended_action", "")).strip().lower()
    final_action = str(normalized.get("final_action", "")).strip().lower()
    if label in MODEL_OUTPUT_LABEL_VALUES:
        return True
    if recommended_action in MODEL_OUTPUT_ACTION_VALUES:
        return True
    return final_action in MODEL_OUTPUT_ACTION_VALUES


def contains_fake_completion_json(text: Any) -> bool:
    """Detect JSON-like classifier outputs embedded inside untrusted email data."""

    value = "" if text is None else str(text)
    if not value:
        return False
    for candidate in _json_object_candidates(value):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if _looks_like_model_output_json(parsed):
            return True
    return bool(LABEL_FIELD_RE.search(value) and (ACTION_FIELD_RE.search(value) or CONFIDENCE_FIELD_RE.search(value)))


def record_contains_fake_completion_json(record: dict[str, Any]) -> bool:
    """Return True if any untrusted email field contains fake classifier JSON."""

    return _record_field_match(record, contains_fake_completion_json)


def _record_field_match(record: dict[str, Any], predicate: Any) -> bool:
    fields = (
        "from",
        "reply_to",
        "subject",
        "body_text",
        "body_html",
        "urls",
        "attachment_names",
    )
    for field in fields:
        value = record.get(field, "")
        if isinstance(value, (list, tuple)):
            if any(predicate(item) for item in value):
                return True
        elif predicate(value):
            return True
    return False


def stable_hash(text: Any) -> str:
    """Return a small stable FNV-1a hash for prompt/debug records."""

    value = "" if text is None else str(text)
    hash_value = 2166136261
    for char in value:
        hash_value ^= ord(char)
        hash_value = (hash_value * 16777619) & 0xFFFFFFFF
    return f"{hash_value:08x}"


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if isinstance(value, tuple):
        return [str(item) for item in value if item is not None]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return [stripped]
        if isinstance(parsed, list):
            return [str(item) for item in parsed if item is not None]
        return [str(parsed)]
    return [str(value)]


def format_email_data(
    record: dict[str, Any],
    *,
    apply_struq_filter: bool = True,
    max_chars: int = MAX_DATA_CHARS,
) -> str:
    """Format email-like records into deterministic prompt data lines."""

    body_html_text = strip_html(record.get("body_html", ""))
    data_lines = [
        f"message_id: {sanitize_text(record.get('message_id', ''), apply_struq_filter=apply_struq_filter)}",
        f"from: {sanitize_text(record.get('from', ''), apply_struq_filter=apply_struq_filter)}",
        f"reply_to: {sanitize_text(record.get('reply_to', ''), apply_struq_filter=apply_struq_filter)}",
        f"subject: {sanitize_text(record.get('subject', ''), apply_struq_filter=apply_struq_filter)}",
        f"received_at: {sanitize_text(record.get('received_at', ''), apply_struq_filter=apply_struq_filter)}",
        "urls: "
        + sanitize_text(", ".join(_as_list(record.get("urls"))), apply_struq_filter=apply_struq_filter),
        "attachment_names: "
        + sanitize_text(
            ", ".join(_as_list(record.get("attachment_names"))),
            apply_struq_filter=apply_struq_filter,
        ),
        "body_text:",
        sanitize_text(record.get("body_text", ""), apply_struq_filter=apply_struq_filter),
    ]
    if body_html_text:
        data_lines.extend(
            [
                "body_html_text:",
                sanitize_text(body_html_text, apply_struq_filter=apply_struq_filter),
            ]
        )
    return "\n".join(line for line in data_lines if line != "")[:max_chars]
