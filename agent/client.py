"""
JOCKY Agent HTTP REST Client.

Communicates with JOCKY Central Server over authenticated REST API.
"""

from typing import Optional, Dict, Any, List
import httpx

from agent.config import AgentConfig, agent_config
from agent.identity import AgentIdentity


class AgentClient:
    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or agent_config
        self.headers = {
            "X-Agent-Key": self.config.agent_secret_key,
            "Content-Type": "application/json",
            "User-Agent": "JOCKY-Agent/1.0",
        }

    def _url(self, path: str) -> str:
        return f"{self.config.server_url.rstrip('/')}/api/v1{path}"

    def register(self, identity: AgentIdentity) -> Dict[str, Any]:
        """Register agent with the central platform."""
        url = self._url("/agents/register")
        with httpx.Client(timeout=self.config.request_timeout) as client:
            resp = client.post(url, json=identity.to_dict(), headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    def heartbeat(self, agent_id: str) -> Dict[str, Any]:
        """Send periodic liveness ping."""
        url = self._url(f"/agents/{agent_id}/heartbeat")
        with httpx.Client(timeout=self.config.request_timeout) as client:
            resp = client.post(url, headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    def fetch_next_job(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Query central server for next assigned forensic job."""
        url = self._url(f"/agents/{agent_id}/jobs/next")
        with httpx.Client(timeout=self.config.request_timeout) as client:
            resp = client.get(url, headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    def update_job_status(self, job_id: str, agent_id: str, status: str, error: Optional[str] = None) -> Dict[str, Any]:
        """Notify server of execution status transitions (e.g. RUNNING, FAILED)."""
        url = self._url(f"/jobs/{job_id}/status?agent_id={agent_id}")
        payload = {"status": status, "error": error}
        with httpx.Client(timeout=self.config.request_timeout) as client:
            resp = client.post(url, json=payload, headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    def upload_job_results(
        self,
        job_id: str,
        agent_id: str,
        evidence_records: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        execution_status: str = "COMPLETED",
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Upload forensic evidence and detected threat findings to central store."""
        url = self._url(f"/jobs/{job_id}/results")
        payload = {
            "job_id": job_id,
            "agent_id": agent_id,
            "evidence_records": evidence_records,
            "findings": findings,
            "execution_status": execution_status,
            "error": error,
        }
        with httpx.Client(timeout=self.config.request_timeout) as client:
            resp = client.post(url, json=payload, headers=self.headers)
            resp.raise_for_status()
            return resp.json()
