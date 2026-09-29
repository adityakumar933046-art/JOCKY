#!/usr/bin/env python3
"""
JOCKY CLI - Command-Line Interface for the JOCKY Digital Forensics Language.

Supports:
  - Default compilation & simulation execution
  - Real read-only forensic collection (--real)
  - Structured JSON export (--json)
  - Diagnostic views (--tokens, --ast, --ir, --check)
"""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path so modules resolve cleanly
project_root = Path(__file__).resolve().parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from compiler.compiler import Compiler
from evidence.serializer import EvidenceSerializer
from evidence.store import EvidenceStore
from runtime.interpreter import ForensicInterpreter


def main() -> int:
    # Ensure stdout handles UTF-8 (e.g. arrow symbol →) on all consoles
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        description="JOCKY: Digital Forensics Programming Language Compiler & Runtime",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("source", help="Path to JOCKY source script (.jocky)")
    parser.add_argument("--real", action="store_true", help="Execute real read-only forensic collection against host OS")
    parser.add_argument("--detect", action="store_true", help="Execute threat detection engine against collected forensic evidence")
    parser.add_argument("--report", default="threat_report", help="Report name for generated threat report JSON (default: threat_report)")
    parser.add_argument("--json", action="store_true", help="Output collected evidence in structured JSON format")
    parser.add_argument("--tokens", action="store_true", help="Display token stream from lexical analysis")
    parser.add_argument("--ast", action="store_true", help="Display Abstract Syntax Tree (AST)")
    parser.add_argument("--ir", action="store_true", help="Display JOCKY Intermediate Representation (IR)")
    parser.add_argument("--check", action="store_true", help="Validate syntax and semantics without running runtime")
    parser.add_argument("--output-dir", default="evidence_output", help="Directory where evidence JSON files are stored")

    args = parser.parse_args()

    source_path = Path(args.source)
    if not source_path.exists():
        print(f"[JOCKY ERROR] File not found: {args.source}", file=sys.stderr)
        return 1

    try:
        source_code = source_path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[JOCKY ERROR] Could not read file: {e}", file=sys.stderr)
        return 1

    # In JSON mode with real execution, suppress standard compiler verbose banners to keep stdout pure JSON
    quiet_mode = args.json and args.real

    if not quiet_mode:
        print("[JOCKY] Compiling...")

    compiler = Compiler()
    result = compiler.compile(source_code)

    if not result.success:
        print("\n[JOCKY] Compilation Failed:", file=sys.stderr)
        for err in result.errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    if not quiet_mode:
        print("[JOCKY] Parsing successful")
        print("[JOCKY] Semantic analysis successful")
        print("[JOCKY] IR generation successful")

    # Diagnostic inspection flags
    if args.tokens:
        print("\n=== TOKENS ===")
        for tok in result.tokens:
            print(f"  {tok}")

    if args.ast:
        print("\n=== AST ===")
        for stmt in result.ast.statements:
            print(f"  {stmt}")

    if args.ir:
        print("\n=== IR INSTRUCTIONS ===")
        for inst in result.ir:
            print(f"  {inst}")

    if args.check:
        print("\n[JOCKY] Validation complete. Script is syntactically and semantically valid.")
        return 0

    # Runtime Execution
    mode = "real" if args.real else "simulation"
    store = EvidenceStore(output_dir=args.output_dir) if args.real else None

    from reports.threat_report import ThreatReport

    interpreter = ForensicInterpreter(
        mode=mode,
        evidence_store=store,
        quiet=quiet_mode,
        enable_detection=args.detect,
        threat_report_name=args.report,
    )

    exec_result = interpreter.execute(result.ir)

    if not exec_result.success:
        print(f"\n[JOCKY ERROR] Runtime failure: {exec_result.error}", file=sys.stderr)
        return 1

    if args.json:
        if args.detect and exec_result.detection_result:
            # Output threat report JSON
            print(ThreatReport(exec_result.detection_result).to_json(indent=2))
        elif args.real:
            # Output full JSON evidence records
            print(EvidenceSerializer.to_json(exec_result.records, indent=2))
        else:
            # Output simulation summary JSON
            sim_summary = {
                "mode": "simulation",
                "status": "success",
                "instructions": [inst.to_dict() for inst in result.ir],
            }
            print(EvidenceSerializer.to_json(sim_summary, indent=2))

    if not quiet_mode:
        print("\n[JOCKY] Execution completed successfully.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
