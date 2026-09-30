# JOCKY Forensic Language Reference Manual

## 1. Introduction

The **JOCKY Domain-Specific Language (DSL)** is a declarative, statically verifiable forensic analysis scripting language designed for computer and network triage. It abstracts heterogeneous operating system internals into standardized forensic collection and detection primitives.

Unlike general-purpose scripting languages (PowerShell, Python, Bash), JOCKY is **strictly non-Turing complete by design**: it contains no arbitrary loops, no unbounded recursion, no file modification primitives, and no system-altering side effects. Every JOCKY program is deterministic, verifiable, and safe to execute in production enterprise environments.

---

## 2. Lexical Structure

### 2.1 Character Set & Comments
JOCKY scripts are UTF-8 encoded text files (standard extension `.jocky`).
The lexer recognizes two comment styles:
- **Hash Comments**: `# This is a comment` (Python / Bash style)
- **Double-Slash Comments**: `// This is a comment` (C / Java style)

Comments continue to the end of the line and are discarded during tokenization.

```jocky
# Full Endpoint Triage Script
// Compatible with both comment conventions
SYSTEM_INFO
SCAN PROCESSES
```

### 2.2 Keywords & Tokens
JOCKY is case-insensitive regarding command keywords, though uppercase is conventional:

| Category | Keywords / Tokens | Description |
| :--- | :--- | :--- |
| **System Info** | `SYSTEM`, `INFO`, `SYSTEM_INFO` | Collects host, OS, CPU, memory, uptime, and identity telemetry. |
| **Scan Verbs** | `SCAN` | Enumerates operating system entities. |
| **Scan Targets** | `PROCESSES`, `NETWORK`, `DRIVERS`, `SERVICES`, `FILES` | Specific OS telemetry domains to query. |
| **Direct Scans** | `PROCESS_SCAN`, `NETWORK_SCAN`, `DRIVER_SCAN`, `SERVICE_SCAN`, `FILE_SCAN` | Unified shorthand scan keywords. |
| **Analysis Verbs** | `ANALYZE` | Inspects and evaluates collected system structures. |
| **Analysis Targets**| `PERSISTENCE`, `MEMORY` | Deep analysis domains. |
| **Direct Analysis**| `PERSISTENCE_SCAN`, `MEMORY_SCAN` | Unified shorthand analysis keywords. |
| **Detection** | `DETECT`, `THREATS` | Invokes the deterministic 15-rule Threat Detection Engine. |
| **Reporting** | `REPORT` | Consolidates evidence and findings into a signed report. |

### 2.3 Literals & Identifiers
- **String Literals**: Enclosed in double quotes (e.g., `"quick_triage"`, `"endpoint_report"`). Used for naming output reports or filtering scopes.
- **Identifiers**: Alphanumeric tokens used for targets and options.

---

## 3. Formal Grammar (EBNF)

```ebnf
program         = { statement } ;

statement       = comment_line
                | system_info_cmd
                | scan_cmd
                | analyze_cmd
                | detect_cmd
                | report_cmd ;

system_info_cmd = "SYSTEM" "INFO" | "SYSTEM_INFO" ;

scan_cmd        = "SCAN" scan_target
                | direct_scan_cmd ;

scan_target     = "PROCESSES" | "NETWORK" | "DRIVERS" | "SERVICES" | "FILES" ;

direct_scan_cmd = "PROCESS_SCAN"
                | "NETWORK_SCAN"
                | "SERVICE_SCAN"
                | "DRIVER_SCAN"
                | "FILE_SCAN" ;

analyze_cmd     = "ANALYZE" analyze_target
                | direct_analyze ;

analyze_target  = "PERSISTENCE" | "MEMORY" | "NETWORK" ;

direct_analyze  = "PERSISTENCE_SCAN" | "MEMORY_SCAN" ;

detect_cmd      = "DETECT" [ "THREATS" ] ;

report_cmd      = "REPORT" string_literal ;

string_literal  = '"' { character } '"' ;
```

---

## 4. AST (Abstract Syntax Tree) Representation

The recursive descent parser transforms tokens into strongly typed AST nodes:

```python
class ASTNode:
    pass

class Program(ASTNode):
    statements: list[Command]

class SystemInfoCommand(Command):
    pass

class ScanCommand(Command):
    target: str  # 'PROCESSES', 'NETWORK', 'DRIVERS', 'SERVICES', 'FILES'

class AnalyzeCommand(Command):
    target: str  # 'PERSISTENCE', 'MEMORY', 'NETWORK'

class DetectCommand(Command):
    scope: str   # 'THREATS' or 'ALL'

class ReportCommand(Command):
    report_name: str
```

---

## 5. Semantic Analysis & Validation

Before bytecode/IR emission, the JOCKY semantic analyzer enforces strict safety and logic rules:

1. **Evidence Prerequisites for Detection**:
   - The `DETECT` command triggers threat analysis over collected evidence.
   - If a script requests `DETECT` without preceding evidence collection commands (`SYSTEM_INFO`, `SCAN`, or `ANALYZE`), the semantic analyzer raises a semantic error:
     ```
     Semantic Error: DETECT command requires prior evidence collection commands in script.
     ```
2. **Duplicate Target Detection**:
   - Redundant scans of the same subsystem within a single execution cycle are flagged or optimized.
3. **Report Target Validation**:
   - Report names must be valid alphanumeric identifiers safe for filesystem storage (avoiding directory traversal characters like `..`, `/`, or `\`).

---

## 6. Intermediate Representation (IR) Specification

The compiler compiles validated AST trees into linear, serializable JOCKY IR opcodes:

```json
[
  {"opcode": "SYSTEM_INFO", "args": {}},
  {"opcode": "SCAN", "args": {"target": "PROCESSES"}},
  {"opcode": "SCAN", "args": {"target": "NETWORK"}},
  {"opcode": "ANALYZE", "args": {"target": "PERSISTENCE"}},
  {"opcode": "DETECT", "args": {"scope": "THREATS"}},
  {"opcode": "REPORT", "args": {"name": "complete_assessment"}}
]
```

### The Strict IR Allow-List
Both the Central Server and distributed Agents strictly enforce an IR allow-list. Every opcode and target is validated against this table before execution:

| Opcode | Valid Target Arguments | Safe Operation Guarantee |
| :--- | :--- | :--- |
| `SYSTEM_INFO` | None | Read-only OS and hardware metadata query |
| `SCAN` | `PROCESSES`, `NETWORK`, `DRIVERS`, `SERVICES`, `FILES` | Non-destructive OS API enumeration |
| `ANALYZE` | `PERSISTENCE`, `MEMORY`, `NETWORK` | In-memory structural inspection |
| `DETECT` | `THREATS` | Deterministic rule-based threat evaluation |
| `REPORT` | `<alphanumeric_string>` | Cryptographic report serialization |

*Any opcode not explicitly enumerated above is immediately rejected, guaranteeing that shell commands or malicious payloads can never be executed through JOCKY.*

---

## 7. Execution Semantics

JOCKY scripts can be executed in two distinct modes:

### 7.1 Simulation Mode (`--sim` or default CLI)
- Compiles the script, generates IR, and simulates forensic collection using synthetic telemetry profiles.
- Produces realistic sample evidence records for training, validation, CI/CD pipelines, and script testing without requiring administrative host privileges.

### 7.2 Real Mode (`--real`)
- Directly interacts with operating system APIs:
  - **Windows**: Calls Win32 API functions (`CreateToolhelp32Snapshot`), parses the Windows Registry via `winreg`, and queries the Service Control Manager.
  - **Linux**: Traverses `/proc`, `/sys`, reads systemd unit files, and parses network tables.
- Computes canonical SHA-256 hashes for all collected evidence.
- When paired with `--detect`, executes the 15-rule Threat Detection Engine against live host telemetry.

---

## 8. Example Programs

### 8.1 Complete Threat Assessment (`examples/forensic_complete.jocky`)
```jocky
# Complete forensic scan and threat assessment
// Collect all host telemetry
SYSTEM_INFO
PROCESS_SCAN
NETWORK_SCAN
SERVICE_SCAN
DRIVER_SCAN
PERSISTENCE_SCAN
MEMORY_SCAN
FILE_SCAN

// Execute automated threat detection engine
DETECT

// Generate consolidated, hash-verified report
REPORT "complete_assessment_report"
```

### 8.2 Standard Syntax Triage (`examples/forensic_scan.jocky`)
```jocky
# Comprehensive Endpoint Triage
SYSTEM INFO
SCAN PROCESSES
SCAN NETWORK
SCAN DRIVERS
SCAN SERVICES
SCAN FILES
ANALYZE PERSISTENCE
ANALYZE MEMORY
REPORT "endpoint_full_triage"
```

### 8.3 Rapid Persistence & Sockets Audit
```jocky
// Focused investigation on persistence and active sockets
SCAN NETWORK
ANALYZE PERSISTENCE
DETECT
REPORT "c2_persistence_audit"
```

---

## 9. Error Handling

JOCKY provides descriptive, structured error messages:

- **Lexer Error**: Emitted when illegal characters or unclosed string literals are encountered:
  ```
  Lexer Error [Line 3, Col 12]: Unterminated string literal
  ```
- **Parser Error**: Emitted on syntax violations:
  ```
  Parser Error [Line 2, Col 1]: Expected valid scan target after 'SCAN', found 'UNKNOWN'
  ```
- **Semantic Error**: Emitted when logical constraints are violated:
  ```
  Semantic Error: DETECT command requires prior evidence collection commands in script.
  ```
- **IR Allow-List Rejection**: Emitted if unauthorized opcodes are submitted:
  ```
  Security Violation: Opcode 'EXECUTE_SHELL' is not in the JOCKY IR allow-list. Execution denied.
  ```
