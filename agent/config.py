"""
JOCKY Agent Configuration.
"""

import os
from dataclasses import dataclass


@dataclass
class AgentConfig:
    server_url: str = os.environ.get("JOCKY_SERVER_URL", "http://127.0.0.1:8000")
    agent_secret_key: str = os.environ.get("JOCKY_AGENT_SECRET", "jocky-agent-secret-key-2026")
    heartbeat_interval_seconds: float = float(os.environ.get("JOCKY_HEARTBEAT_INTERVAL", "10.0"))
    poll_interval_seconds: float = float(os.environ.get("JOCKY_POLL_INTERVAL", "3.0"))
    identity_file: str = os.environ.get("JOCKY_IDENTITY_FILE", ".jocky_agent_identity.json")
    request_timeout: float = 15.0


agent_config = AgentConfig()
