"""
JOCKY Compiler Validation API Endpoint.

Allows the web dashboard to validate JOCKY source code live and return
precise line/column errors before submitting a job.
"""

from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter
from compiler.compiler import Compiler
from server.services.job_service import JobService

router = APIRouter(prefix="/compiler", tags=["Compiler"])


class ValidateRequest(BaseModel):
    source: str


class CompilerDiagnostic(BaseModel):
    message: str
    line: Optional[int] = None
    column: Optional[int] = None


class ValidateResponse(BaseModel):
    valid: bool
    errors: List[str] = []
    diagnostics: List[CompilerDiagnostic] = []
    tokens_count: int = 0
    instructions_count: int = 0


@router.post("/validate", response_model=ValidateResponse)
def validate_jocky_script(req: ValidateRequest):
    """Validate JOCKY source code and test against the IR Allow-List."""
    compiler = Compiler()
    res = compiler.compile(req.source)

    if not res.success:
        diagnostics = []
        for err in res.errors:
            # Parse line:col if present in error string
            line = None
            col = None
            if "at " in err and ":" in err:
                try:
                    parts = err.split("at ", 1)[1].split(":", 1)
                    line = int(parts[0])
                    col = int(parts[1].split()[0].replace(":", ""))
                except Exception:
                    pass
            diagnostics.append(CompilerDiagnostic(message=err, line=line, column=col))

        return ValidateResponse(
            valid=False,
            errors=res.errors,
            diagnostics=diagnostics,
            tokens_count=len(res.tokens) if res.tokens else 0,
            instructions_count=0,
        )

    # Check IR Allow-list
    try:
        JobService.validate_jocky_source_and_ir(req.source)
    except Exception as e:
        err_msg = str(getattr(e, "detail", e))
        return ValidateResponse(
            valid=False,
            errors=[err_msg],
            diagnostics=[CompilerDiagnostic(message=err_msg)],
            tokens_count=len(res.tokens) if res.tokens else 0,
            instructions_count=len(res.ir) if res.ir else 0,
        )

    return ValidateResponse(
        valid=True,
        errors=[],
        diagnostics=[],
        tokens_count=len(res.tokens) if res.tokens else 0,
        instructions_count=len(res.ir) if res.ir else 0,
    )
