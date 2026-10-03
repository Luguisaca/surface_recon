"""Minimize common sensitive values before storing or displaying evidence."""

import re
from typing import Any

_PATTERNS = (
    re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)([^\s]+)"),
    re.compile(r"(?i)\b(api[_-]?key\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)\b(token\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)\b(password\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)((?:[A-Za-z0-9_-]*session[A-Za-z0-9_-]*|access_token|refresh_token)=)([^;&?\s]+)"),
)

_SENSITIVE_KEYS = {
    "authorization",
    "api_key",
    "apikey",
    "token",
    "password",
    "secret",
    "session_id",
    "sessionid",
    "jsessionid",
    "access_token",
    "refresh_token",
}


def redact_text(value: str) -> str:
    result = value
    for pattern in _PATTERNS:
        result = pattern.sub(r"\1[REDACTED]", result)
    return result


def minimize(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)

    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if str(key).lower().replace("-", "_") in _SENSITIVE_KEYS
                else minimize(item)
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [minimize(item) for item in value]

    if isinstance(value, tuple):
        return tuple(minimize(item) for item in value)

    return value