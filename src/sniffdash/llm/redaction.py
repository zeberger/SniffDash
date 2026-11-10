"""Remove credentials from anything about to be sent to the external model.

Captures routinely contain secrets: cookies, Authorization headers, login forms.
Google's free tier may use prompts to improve its products, so these never leave
the machine. Bodies are also truncated: the model needs their gist, not megabytes.
"""

from __future__ import annotations

import re

SENSITIVE_HEADERS = ("authorization", "proxy-authorization", "cookie", "set-cookie")
REDACTED = "[REDACTED]"
BODY_CHAR_LIMIT = 2000

_HEADER_LINE = re.compile(rf"^({'|'.join(SENSITIVE_HEADERS)})(\s*:\s*).*$", re.IGNORECASE | re.MULTILINE)
# password=…  /  "password": "…"  /  passwd, pwd, secret, token, api_key (form or JSON bodies)
_SECRET_FIELD = re.compile(
    r'''(?P<key>["']?(?:password|passwd|pwd|secret|token|api[_-]?key)["']?\s*[:=]\s*)(?P<q>["']?)[^"'&\s,}]+(?P=q)''',
    re.IGNORECASE,
)


def redact(text: str, limit: int = BODY_CHAR_LIMIT) -> str:
    text = _HEADER_LINE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    text = _SECRET_FIELD.sub(lambda m: f"{m.group('key')}{m.group('q')}{REDACTED}{m.group('q')}", text)
    if len(text) > limit:
        text = text[:limit] + f"\n… [truncated: {len(text) - limit} more characters not sent]"
    return text
