"""
JOCKY Central Server Configuration.
Enterprise security settings, authentication parameters, and environment validation.
"""

import os
import secrets
from pathlib import Path


class ServerConfig:
    def __init__(self):
        # Environment mode: 'development', 'testing', or 'production'
        self.ENV: str = os.environ.get("JOCKY_ENV", "development").lower()
        self.ENVIRONMENT: str = self.ENV

        # Database
        self.DATABASE_URL: str = os.environ.get("JOCKY_DATABASE_URL", "sqlite:///./jocky_central.db")

        # API
        self.API_V1_PREFIX: str = "/api/v1"
        self.PROJECT_NAME: str = "JOCKY Central Forensic Platform"
        self.VERSION: str = "1.0.0"

        # Core Security Key
        _env_secret = os.environ.get("JOCKY_SECRET_KEY")
        if self.ENV == "production":
            if not _env_secret or len(_env_secret.strip()) < 32:
                raise ValueError(
                    "FATAL CONFIGURATION ERROR: JOCKY_ENV is 'production' but JOCKY_SECRET_KEY is either "
                    "missing or shorter than 32 characters. A cryptographically secure secret is required."
                )
            self.SECRET_KEY: str = _env_secret
        else:
            # Development / test secret (isolated, never used in production)
            self.SECRET_KEY: str = _env_secret or "dev-test-secret-key-32-chars-minimum-entropy-required-12345"

        self.JWT_ALGORITHM: str = "HS256"
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

        # Cryptography - PBKDF2 Password Hashing
        self.PBKDF2_ITERATIONS: int = int(os.environ.get("JOCKY_PBKDF2_ITERATIONS", "100000"))

        # Account Lockout Policy
        self.MAX_LOGIN_ATTEMPTS: int = int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5"))
        self.LOCKOUT_MINUTES: int = int(os.environ.get("LOCKOUT_MINUTES", "15"))

        # Multi-Tenancy
        self.DEFAULT_ORG_ID: str = "org-default"

        # Backward Compatibility Keys (Step 4 legacy fallback)
        self.AGENT_SECRET_KEY: str = os.environ.get("JOCKY_AGENT_SECRET", "jocky-agent-secret-key-2026")
        self.ANALYST_SECRET_KEY: str = os.environ.get("JOCKY_ANALYST_SECRET", "jocky-analyst-secret-key-2026")

        # Agent Management
        self.HEARTBEAT_TIMEOUT_SECONDS: int = 60
        self.DEFAULT_PAGE_SIZE: int = 50


config = ServerConfig()
