from __future__ import annotations

MAX_RETRY_DELAY = 8.0
RETRYABLE_HTTP_CODES = frozenset({500, 502, 503, 504})
