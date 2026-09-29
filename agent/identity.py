"""
JOCKY Agent Identity.

Manages persistent agent UUID and host fingerprinting.
Ensures restarting the agent does not create duplicate server registrations.
"""

import os
import json
import uuid
import socket
import platform
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class AgentIdentity:
    agent_id: str
    hostname: str
    operating_system: str
    os_version: str
    architecture: str
    jocky_version: str = "1.0.0"
    collector_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def load_or_create(cls, storage_path: str = ".jocky_agent_identity.json") -> "AgentIdentity":
        """Load persistent agent identity from disk or generate a new unique identity."""
        path = Path(storage_path)
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return cls(
                    agent_id=data["agent_id"],
                    hostname=platform.node() or socket.gethostname(),
                    operating_system=platform.system(),
                    os_version=platform.version(),
                    architecture=platform.machine(),
                    jocky_version=data.get("jocky_version", "1.0.0"),
                    collector_version=data.get("collector_version", "1.0.0"),
                )
            except Exception:
                pass  # Fall back to creating new identity if file corrupted

        # Create new unique agent ID (never uses hostname as ID)
        new_id = f"AGT-{uuid.uuid4().hex[:10].upper()}"
        identity = cls(
            agent_id=new_id,
            hostname=platform.node() or socket.gethostname(),
            operating_system=platform.system(),
            os_version=platform.version(),
            architecture=platform.machine(),
            jocky_version="1.0.0",
            collector_version="1.0.0",
        )
        try:
            path.write_text(json.dumps(identity.to_dict(), indent=2), encoding="utf-8")
        except Exception:
            pass

        return identity
