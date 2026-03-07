"""
=============================================================================
Module: RateLimiter
Purpose: Redis-backed sliding window rate limiter for abuse prevention.
         Three rate zones: public verification (10/min), auth (5/min),
         general API (60/min). Org-level limiting for enterprise.
Inputs:  Client IP, org_id (for enterprise), endpoint zone, Redis client
Outputs: (allowed: bool, retry_after_seconds: int)
Dependencies: redis, time
Security:
  - Uses Redis MULTI/EXEC pipeline for atomic increment+expire
  - IP is pre-hashed (SHA-256) before use as Redis key
  - Zone config cannot be overridden by client
=============================================================================
"""

import hashlib
import time
import os
from typing import Optional


# Rate limit configuration per zone (requests, window_seconds)
RATE_ZONES = {
    "public_verify": (10, 60),     # 10 req/min for public verification
    "auth": (5, 60),               # 5 req/min for login/token endpoints
    "general": (60, 60),           # 60 req/min for general API
    "enterprise": (100, 60),       # 100 req/min per org
    "admin": (200, 60),            # 200 req/min per user
}

_redis_client = None


def _get_redis():
    """Lazy Redis client initialisation."""
    global _redis_client
    if _redis_client is None:
        import redis
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        _redis_client = redis.from_url(redis_url, decode_responses=True)
    return _redis_client


def _hash_ip(ip: str) -> str:
    """SHA-256 of IP — avoid storing raw IPs in Redis."""
    salt = os.environ.get("IP_HASH_SALT", "secureerase-rate-salt")
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:24]


def check_rate_limit(
    ip: str,
    zone: str,
    org_id: Optional[str] = None,
) -> tuple[bool, int]:
    """
    Sliding window rate limit check using Redis.

    Args:
        ip: Client IP address (will be hashed)
        zone: One of the RATE_ZONES keys
        org_id: For enterprise zone — limits per organisation, not per IP

    Returns:
        (allowed, retry_after_seconds)
        retry_after_seconds is 0 if allowed, >0 if blocked
    """
    if zone not in RATE_ZONES:
        zone = "general"

    limit, window = RATE_ZONES[zone]

    # Key: use org_id for enterprise zone, hashed IP otherwise
    if zone == "enterprise" and org_id:
        key_subject = f"org:{org_id}"
    else:
        key_subject = f"ip:{_hash_ip(ip)}"

    redis_key = f"rl:{zone}:{key_subject}"
    now = int(time.time())
    window_start = now - window

    try:
        r = _get_redis()
        pipe = r.pipeline()

        # Sliding window: store timestamps as sorted set members
        # Remove expired entries
        pipe.zremrangebyscore(redis_key, 0, window_start)
        # Count current requests in window
        pipe.zcard(redis_key)
        # Add current request timestamp
        pipe.zadd(redis_key, {str(now) + f":{time.time_ns()%1000000}": now})
        # Set key expiry to window duration
        pipe.expire(redis_key, window)

        results = pipe.execute()
        current_count = results[1]  # count before adding current request

        if current_count >= limit:
            # Calculate retry_after: time until oldest entry leaves window
            oldest = r.zrange(redis_key, 0, 0, withscores=True)
            if oldest:
                oldest_ts = int(oldest[0][1])
                retry_after = max(1, (oldest_ts + window) - now)
            else:
                retry_after = window
            # Remove the request we just added (it was rejected)
            r.zpopmax(redis_key)
            return False, retry_after

        return True, 0

    except Exception:
        # On Redis failure, allow the request (fail open for availability)
        # Log this in production — Redis failure means no rate limiting
        return True, 0


def get_rate_limit_headers(ip: str, zone: str,
                            org_id: Optional[str] = None) -> dict:
    """
    Return X-RateLimit-* headers for the current request.
    Does not consume a request slot.
    """
    if zone not in RATE_ZONES:
        zone = "general"
    limit, window = RATE_ZONES[zone]

    if zone == "enterprise" and org_id:
        key_subject = f"org:{org_id}"
    else:
        key_subject = f"ip:{_hash_ip(ip)}"

    redis_key = f"rl:{zone}:{key_subject}"
    now = int(time.time())
    window_start = now - window

    try:
        r = _get_redis()
        r.zremrangebyscore(redis_key, 0, window_start)
        current = r.zcard(redis_key)
        remaining = max(0, limit - current)
        return {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(now + window),
        }
    except Exception:
        return {}
