"""
JOCKY Agent Job Executor.

Enforces defense-in-depth: independently verifies JOCKY source and enforces
the IR Allow-List locally before executing any forensic collectors.
Attaches SHA-256 canonical integrity checksums to collected evidence.
"""

import json
import hashlib
from typing import Dict, Any, List
from compiler.compiler import Compiler
from compiler.ir import IRInstruction
from runtime.interpreter import ForensicInterpreter
from runtime.collectors.factory import get_collector


def _compute_canonical_sha256(data: Any) -> str:
    """Compute canonical SHA-256 hash of an evidence payload."""
    canonical_json = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class AgentJobExecutor:
    ALLOWED_OPCODES = {"SYSTEM_INFO", "SCAN", "ANALYZE", "REPORT", "DETECT"}
    ALLOWED_SCAN_TARGETS = {"PROCESSES", "NETWORK", "FILES", "DRIVERS", "SERVICES"}
    ALLOWED_ANALYZE_TARGETS = {"PERSISTENCE", "MEMORY", "NETWORK"}

    @classmethod
    def execute_job(cls, jocky_source: str, detection_enabled: bool = True) -> Dict[str, Any]:
        """Execute a forensic job received from central server with strict verification.
        
        Args:
            jocky_source: JOCKY script code.
            detection_enabled: Whether to run the ThreatDetectionEngine on evidence.
            
        Returns:
            Dict containing evidence_records, findings, execution_status, and error if any.
        """
        # 1. Independent local compilation
        compiler = Compiler()
        compile_res = compiler.compile(jocky_source)
        if not compile_res.success:
            return {
                "success": False,
                "evidence_records": [],
                "findings": [],
                "error": f"Agent compilation validation failed: {'; '.join(compile_res.errors)}",
            }

        # 2. Strict IR Allow-List Verification
        for inst in compile_res.ir or []:
            opcode = inst.opcode.upper()
            if opcode not in cls.ALLOWED_OPCODES:
                return {
                    "success": False,
                    "evidence_records": [],
                    "findings": [],
                    "error": f"Agent Security Rejection: Disallowed opcode '{opcode}'.",
                }

            if opcode == "SCAN":
                target = (inst.target or "").upper()
                if target not in cls.ALLOWED_SCAN_TARGETS:
                    return {
                        "success": False,
                        "evidence_records": [],
                        "findings": [],
                        "error": f"Agent Security Rejection: Disallowed SCAN target '{target}'.",
                    }

            if opcode == "ANALYZE":
                target = (inst.target or "").upper()
                if target not in cls.ALLOWED_ANALYZE_TARGETS:
                    return {
                        "success": False,
                        "evidence_records": [],
                        "findings": [],
                        "error": f"Agent Security Rejection: Disallowed ANALYZE target '{target}'.",
                    }

        # 3. Safe Execution via Forensic Runtime
        try:
            interpreter = ForensicInterpreter(
                mode="real",
                quiet=True,  # Quiet mode for agent execution
                enable_detection=detection_enabled,
            )
            exec_res = interpreter.execute(compile_res.ir)

            if not exec_res.success:
                return {
                    "success": False,
                    "evidence_records": [],
                    "findings": [],
                    "error": f"Runtime execution failed: {exec_res.error}",
                }

            evidence_data = []
            for rec in exec_res.records:
                rec_dict = rec.to_dict()
                # Compute SHA-256 canonical hash
                rec_dict["content_hash"] = _compute_canonical_sha256(rec.data)
                rec_dict["hash_algorithm"] = "SHA-256"
                evidence_data.append(rec_dict)

            findings_data = (
                [f.to_dict() for f in exec_res.detection_result.findings]
                if exec_res.detection_result
                else []
            )

            return {
                "success": True,
                "evidence_records": evidence_data,
                "findings": findings_data,
                "error": None,
            }

        except Exception as e:
            return {
                "success": False,
                "evidence_records": [],
                "findings": [],
                "error": f"Unhandled executor exception: {e}",
            }
