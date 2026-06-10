"""Prompt-security helpers for the StruQ email triage PoC."""

from .filter import (
    RESERVED_STRINGS,
    contains_fake_completion_json,
    format_email_data,
    record_contains_fake_completion_json,
    recursive_filter,
)
from .prompt_builder import PromptVariant, build_prompt
from .schema import (
    ALLOWED_ACTIONS,
    ALLOWED_LABELS,
    OUTPUT_JSON_SCHEMA,
    ValidationResult,
    fallback_validation,
    validate_model_response,
)

__all__ = [
    "ALLOWED_ACTIONS",
    "ALLOWED_LABELS",
    "OUTPUT_JSON_SCHEMA",
    "PromptVariant",
    "RESERVED_STRINGS",
    "ValidationResult",
    "build_prompt",
    "contains_fake_completion_json",
    "fallback_validation",
    "format_email_data",
    "record_contains_fake_completion_json",
    "recursive_filter",
    "validate_model_response",
]
