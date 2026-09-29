"""
JOCKY Cryptographic Utilities.
Provides PBKDF2 password hashing, canonical SHA-256 evidence integrity hashing,
and cryptographically chained custody event hashing.
"""

import os
import json
import hmac
import hashlib
import secrets
from typing import Any, Optional
from server.config import config


def hash_password(password: str, iterations: Optional[int] = None) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with a random salt."""
    if not password:
        raise ValueError("Password cannot be empty.")
    
    iter_count = iterations or config.PBKDF2_ITERATIONS
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iter_count,
        dklen=32,
    )
    return f"pbkdf2:sha256:{iter_count}${salt.hex()}${key.hex()}"


def verify_password(plain_password: str, hashed: str) -> bool:
    """Verify a plain password against a stored PBKDF2 hash using constant-time comparison."""
    if not plain_password or not hashed:
        return False

    try:
        prefix, salt_hex, key_hex = hashed.split("$")
        parts = prefix.split(":")
        if len(parts) != 3 or parts[0] != "pbkdf2" or parts[1] != "sha256":
            return False

        iterations = int(parts[2])
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)

        computed_key = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt,
            iterations,
            dklen=32,
        )
        return hmac.compare_digest(computed_key, expected_key)
    except Exception:
        return False


def compute_canonical_evidence_hash(data: Any) -> str:
    """Compute the deterministic SHA-256 checksum of forensic evidence using canonical JSON serialization."""
    canonical_json = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_event_hash(
    previous_hash: str,
    timestamp_str: str,
    actor_id: str,
    action: str,
    metadata_str: str = "",
) -> str:
    """Compute a cryptographically linked custody event hash incorporating the previous event hash."""
    payload = f"{previous_hash}|{timestamp_str}|{actor_id}|{action}|{metadata_str}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a high-entropy cryptographically secure random token."""
    return secrets.token_urlsafe(nbytes)


def hash_agent_token(token: str) -> str:
    """Hash an agent secret token for secure database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# Convenience aliases
compute_evidence_hash = compute_canonical_evidence_hash
compute_custody_hash = compute_event_hash
