"""
JOCKY Endpoint Agent Daemon.

Main agent process that connects to JOCKY Central Server, maintains heartbeats,
polls for assigned forensic jobs, and uploads captured evidence and threat findings.
Supports trust-state lifecycle (PENDING -> AUTHORIZED -> SUSPENDED -> REVOKED).
"""

import sys
import time
import signal
import threading
from typing import Optional

from agent.identity import AgentIdentity
from agent.config import AgentConfig, agent_config
from agent.client import AgentClient
from agent.executor import AgentJobExecutor


class JockyAgentDaemon:
    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or agent_config
        self.identity = AgentIdentity.load_or_create(storage_path=self.config.identity_file)
        self.client = AgentClient(config=self.config)
        self.running = False
        self.trust_state = "PENDING"
        self._last_heartbeat = 0.0

    def register(self) -> bool:
        """Register agent with central server."""
        print(f"[JOCKY AGENT] Connecting to central platform at {self.config.server_url}...")
        try:
            resp = self.client.register(self.identity)
            self.trust_state = resp.get("trust_state", "PENDING")
            print(
                f"[JOCKY AGENT] Registered successfully. Agent ID: {self.identity.agent_id} "
                f"(Status: {resp.get('status')}, Trust State: {self.trust_state})"
            )
            if self.trust_state == "PENDING":
                print("[JOCKY AGENT] Awaiting administrator authorization before job polling begins.")
            return True
        except Exception as e:
            print(f"[JOCKY AGENT ERROR] Registration failed: {e}", file=sys.stderr)
            return False

    def send_heartbeat_if_due(self):
        """Send heartbeat if interval elapsed."""
        now = time.time()
        if now - self._last_heartbeat >= self.config.heartbeat_interval_seconds:
            try:
                resp = self.client.heartbeat(self.identity.agent_id)
                self.trust_state = resp.get("trust_state", self.trust_state)
                self._last_heartbeat = now
            except Exception as e:
                # If suspended or revoked, heartbeat returns 403
                if "403" in str(e):
                    print(f"[JOCKY AGENT] Heartbeat rejected by central server: Agent is {self.trust_state}.")
                else:
                    print(f"[JOCKY AGENT WARNING] Heartbeat failed: {e}", file=sys.stderr)

    def process_next_job(self) -> bool:
        """Poll and execute next pending job. Returns True if a job was executed."""
        try:
            job = self.client.fetch_next_job(self.identity.agent_id)
            if not job:
                return False

            job_id = job["job_id"]
            name = job.get("name", "Unnamed Job")
            source = job.get("jocky_source", "")
            detection = job.get("detection_enabled", True)

            print(f"\n[JOCKY AGENT] Received job '{name}' ({job_id})")

            # 1. Update status to RUNNING
            self.client.update_job_status(job_id=job_id, agent_id=self.identity.agent_id, status="RUNNING")

            # 2. Execute via AgentJobExecutor
            print(f"[JOCKY AGENT] Executing forensic collectors for job {job_id}...")
            res = AgentJobExecutor.execute_job(jocky_source=source, detection_enabled=detection)

            status = "COMPLETED" if res["success"] else "FAILED"
            error = res["error"]

            # 3. Upload evidence and findings with SHA-256 integrity hashes
            print(f"[JOCKY AGENT] Uploading {len(res['evidence_records'])} evidence records and {len(res['findings'])} findings...")
            self.client.upload_job_results(
                job_id=job_id,
                agent_id=self.identity.agent_id,
                evidence_records=res["evidence_records"],
                findings=res["findings"],
                execution_status=status,
                error=error,
            )
            print(f"[JOCKY AGENT] Job {job_id} finished with status: {status}")
            return True

        except Exception as e:
            # If agent not yet authorized or suspended, 403 is expected
            if "403" in str(e):
                pass
            else:
                print(f"[JOCKY AGENT ERROR] Job processing error: {e}", file=sys.stderr)
            return False

    def run_once(self) -> bool:
        """Single-shot iteration: registers, sends heartbeat, and processes one job."""
        if not self.register():
            return False
        self.send_heartbeat_if_due()
        return self.process_next_job()

    def start(self):
        """Start long-running agent daemon loop."""
        self.running = True
        print(f"[JOCKY AGENT] Starting daemon for {self.identity.hostname} ({self.identity.operating_system})...")

        if not self.register():
            print("[JOCKY AGENT ERROR] Initial registration failed. Retrying in background...", file=sys.stderr)

        while self.running:
            self.send_heartbeat_if_due()
            self.process_next_job()
            time.sleep(self.config.poll_interval_seconds)

    def stop(self):
        """Stop agent daemon."""
        self.running = False


def main():
    agent = JockyAgentDaemon()

    def handle_signal(sig, frame):
        print("\n[JOCKY AGENT] Shutting down agent daemon...")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    agent.start()


if __name__ == "__main__":
    main()
