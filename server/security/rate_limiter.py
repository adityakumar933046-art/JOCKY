"""
JOCKY Rate Limiting Subsystem.
Provides a thread-safe, sliding-window rate limiter protecting sensitive endpoints
(login, registration, heartbeats, job creation).
Interface is designed to be cleanly swappable with Redis for multi-instance deployments.
"""

import time
import threading
from typing import Dict, List, Optional
from fastapi import HTTPException, status


class InMemoryRateLimiter:
    """Thread-safe sliding-window in-memory rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        self._requests: Dict[str, List[float]] = {}

    def check(self, key: str, limit: int, window_seconds: int) -> bool:
        """Check if request under key is within limit. Returns True if allowed, False if exceeded."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._requests.get(key, [])
            # Purge timestamps outside sliding window
            timestamps = [ts for ts in timestamps if ts > cutoff]

            if len(timestamps) >= limit:
                self._requests[key] = timestamps
                return False

            timestamps.append(now)
            self._requests[key] = timestamps
            return True

    def reset(self, key: Optional[str] = None):
        """Reset limits (useful in testing)."""
        with self._lock:
            if key:
                self._requests.pop(key, None)
            else:
                self._requests.clear()


rate_limiter = InMemoryRateLimiter()


def rate_limit_check(key: str, limit: int, window_seconds: int, action: str = "request"):
    """Enforce rate limit or raise 429 Too Many Requests."""
    allowed = rate_limiter.check(key, limit, window_seconds)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {action}. Please try again later.",
        )
