"""
JOCKY Forensic Interpreter.

Executes JOCKY IR instructions in either SIMULATION mode (default)
or REAL collection mode (--real) using platform-specific ForensicCollectors.
"""

import sys
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field

from compiler.ir import IRInstruction
from runtime.collectors.base import ForensicCollector
from runtime.collectors.factory import get_collector
from evidence.models import EvidenceRecord
from evidence.store import EvidenceStore


from detection.models import DetectionResult
from detection.engine import ThreatDetectionEngine
from reports.threat_report import ThreatReport


@dataclass
class ExecutionResult:
    success: bool
    mode: str
    records: List[EvidenceRecord] = field(default_factory=list)
    output_lines: List[str] = field(default_factory=list)
    error: Optional[str] = None
    detection_result: Optional[DetectionResult] = None
    threat_report_path: Optional[str] = None


class ForensicInterpreter:
    def __init__(
        self,
        mode: str = "simulation",
        collector: Optional[ForensicCollector] = None,
        evidence_store: Optional[EvidenceStore] = None,
        quiet: bool = False,
        enable_detection: bool = False,
        threat_report_name: Optional[str] = None,
    ):
        """
        Args:
            mode: "simulation" (default) or "real"
            collector: Optional ForensicCollector (auto-detected if None in real mode)
            evidence_store: Optional EvidenceStore for persisting evidence
            quiet: If True, suppresses direct print output (useful for tests/JSON mode)
            enable_detection: If True, executes ThreatDetectionEngine on collected evidence
            threat_report_name: Optional custom filename for threat report JSON
        """
        self.mode = mode.lower()
        self.collector = collector
        self.evidence_store = evidence_store or EvidenceStore()
        self.quiet = quiet
        self.enable_detection = enable_detection
        self.threat_report_name = threat_report_name
        self.records: List[EvidenceRecord] = []
        self.output_lines: List[str] = []

    def _log(self, text: str = ""):
        self.output_lines.append(text)
        if not self.quiet:
            try:
                print(text)
            except UnicodeEncodeError:
                # Safe fallback if terminal doesn't support UTF-8 arrow
                print(text.encode(sys.stdout.encoding or "ascii", errors="replace").decode(sys.stdout.encoding or "ascii"))

    def execute(self, instructions: List[IRInstruction]) -> ExecutionResult:
        self.records.clear()
        self.output_lines.clear()

        if self.mode == "real":
            return self._execute_real(instructions)
        else:
            return self._execute_simulation(instructions)

    def _execute_simulation(self, instructions: List[IRInstruction]) -> ExecutionResult:
        self._log("\n[JOCKY RUNTIME]")

        for inst in instructions:
            if inst.opcode == "SYSTEM_INFO":
                self._log("→ Collect system information")
            elif inst.opcode == "SCAN":
                target_name = (inst.target or "").lower()
                self._log(f"→ Scan {target_name}")
            elif inst.opcode == "ANALYZE":
                target_name = (inst.target or "").lower()
                self._log(f"→ Analyze {target_name}")
            elif inst.opcode == "REPORT":
                self._log(f"→ Generate report: {inst.target}")
            else:
                self._log(f"→ Unknown instruction: {inst.opcode}")

        return ExecutionResult(
            success=True,
            mode="simulation",
            records=[],
            output_lines=self.output_lines,
        )

    def _execute_real(self, instructions: List[IRInstruction]) -> ExecutionResult:
        if self.collector is None:
            try:
                self.collector = get_collector()
            except Exception as e:
                err_msg = f"Collector initialization failed: {e}"
                self._log(f"[JOCKY ERROR] {err_msg}")
                return ExecutionResult(
                    success=False,
                    mode="real",
                    error=err_msg,
                    output_lines=self.output_lines,
                )

        self._log(f"\n[JOCKY] Platform: {self.collector.platform_name}")
        self._log(f"[JOCKY] Collector: {self.collector.__class__.__name__}")
        self._log("\n[JOCKY FORENSIC COLLECTION]\n")

        # Get system metadata for tagging records
        host_name = "UNKNOWN"
        os_name = self.collector.platform_name

        for inst in instructions:
            try:
                rec = None

                if inst.opcode == "SYSTEM_INFO":
                    self._log("→ Collecting system information... ", end_char="")
                    raw = self.collector.collect_system_info()
                    items = raw.get("items", {})
                    host_name = items.get("hostname", host_name)
                    rec = self._create_and_save_record("system_info", raw, host_name, os_name)
                    self._log("OK")

                elif inst.opcode == "SCAN":
                    target = (inst.target or "").upper()
                    if target == "PROCESSES":
                        self._log("→ Scanning processes... ", end_char="")
                        raw = self.collector.scan_processes()
                        rec = self._create_and_save_record("scan_processes", raw, host_name, os_name)
                        self._log("OK")
                    elif target == "NETWORK":
                        self._log("→ Scanning network... ", end_char="")
                        raw = self.collector.scan_network()
                        rec = self._create_and_save_record("scan_network", raw, host_name, os_name)
                        self._log("OK")
                    elif target == "FILES":
                        self._log("→ Scanning files... ", end_char="")
                        raw = self.collector.scan_files()
                        rec = self._create_and_save_record("scan_files", raw, host_name, os_name)
                        self._log("OK")
                    elif target == "DRIVERS":
                        self._log("→ Scanning drivers... ", end_char="")
                        raw = self.collector.scan_drivers()
                        rec = self._create_and_save_record("scan_drivers", raw, host_name, os_name)
                        self._log("OK")
                    elif target == "SERVICES":
                        self._log("→ Scanning services... ", end_char="")
                        raw = self.collector.scan_services()
                        rec = self._create_and_save_record("scan_services", raw, host_name, os_name)
                        self._log("OK")
                    else:
                        self._log(f"→ Unknown scan target '{target}'... SKIPPED")

                elif inst.opcode == "ANALYZE":
                    target = (inst.target or "").upper()
                    if target == "PERSISTENCE":
                        self._log("→ Analyzing persistence... ", end_char="")
                        raw = self.collector.analyze_persistence()
                        rec = self._create_and_save_record("analyze_persistence", raw, host_name, os_name)
                        self._log("OK")
                    elif target == "MEMORY":
                        self._log("→ Analyzing memory indicators... ", end_char="")
                        raw = self.collector.analyze_memory()
                        rec = self._create_and_save_record("analyze_memory", raw, host_name, os_name)
                        self._log("OK")
                    elif target == "NETWORK":
                        self._log("→ Analyzing network... ", end_char="")
                        raw = self.collector.analyze_network()
                        rec = self._create_and_save_record("analyze_network", raw, host_name, os_name)
                        self._log("OK")
                    else:
                        self._log(f"→ Unknown analyze target '{target}'... SKIPPED")

                elif inst.opcode == "REPORT":
                    report_name = inst.target or "forensic_report"
                    self._log(f"→ Generating report: {report_name}... ", end_char="")
                    self.evidence_store.save_report(report_name, self.records)
                    self._log("OK")

                if rec:
                    self.records.append(rec)

            except Exception as e:
                self._log(f"FAILED ({e})")

        self._log(f"\n[JOCKY] Evidence records generated: {len(self.records)}")
        self._log("[JOCKY] Evidence stored locally")

        detection_result = None
        threat_report_path = None

        if self.enable_detection:
            self._log("\n[JOCKY THREAT ANALYSIS]\n")
            engine = ThreatDetectionEngine()

            def on_progress(category_name: str, status: str):
                cat_display = category_name.capitalize()
                self._log(f"→ {cat_display} rules... {status}")

            detection_result = engine.analyze(self.records, progress_callback=on_progress)
            self._log(f"\n[JOCKY] Findings generated: {len(detection_result.findings)}")
            self._log("\n[JOCKY THREAT SUMMARY]\n")
            for lvl in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                self._log(f"{lvl}: {detection_result.summary.get(lvl, 0)}")

            report_name = self.threat_report_name or "threat_report"
            report = ThreatReport(detection_result)
            report_file = self.evidence_store.output_dir / f"{report_name}.json"
            report.save(report_file)
            threat_report_path = str(report_file)
            self._log("\n[JOCKY] Threat report generated.")

        return ExecutionResult(
            success=True,
            mode="real",
            records=self.records,
            output_lines=self.output_lines,
            detection_result=detection_result,
            threat_report_path=threat_report_path,
        )

    def _log(self, text: str = "", end_char: str = "\n"):
        if end_char == "\n":
            self.output_lines.append(text)
        else:
            if self.output_lines and not self.output_lines[-1].endswith("\n"):
                self.output_lines[-1] += text
            else:
                self.output_lines.append(text)

        if not self.quiet:
            try:
                print(text, end=end_char, flush=True)
            except UnicodeEncodeError:
                safe = text.encode(sys.stdout.encoding or "ascii", errors="replace").decode(sys.stdout.encoding or "ascii")
                print(safe, end=end_char, flush=True)

    def _create_and_save_record(
        self,
        operation: str,
        raw_result: Dict[str, Any],
        hostname: str,
        os_name: str,
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            hostname=hostname,
            operating_system=os_name,
            collector=self.collector.__class__.__name__,
            operation=operation,
            collection_status=raw_result.get("status", "success"),
            data=raw_result.get("items", {}),
            metadata=raw_result.get("metadata", {}),
        )
        self.evidence_store.save(record)
        return record
