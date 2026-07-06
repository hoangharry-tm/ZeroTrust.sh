"""XGrammar-2-enforced JSON schemas for all Python worker response types.

These Pydantic models define the wire format between the Go orchestrator and the
Python worker. The Go side unmarshals the `result` field of each Response into
the appropriate struct.
"""

from enum import Enum

from pydantic import BaseModel, Field

import tuning

# ── LLM Verifier ─────────────────────────────────────────────────────────────

class LLMVerdict(str, Enum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class LLMVerifierResult(BaseModel):
    """Wire schema returned by the llm_verify handler to the Go orchestrator."""

    verdict: LLMVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    justification: str = Field(max_length=tuning.VERDICT_MAX_JUSTIFICATION_LEN)
    asc_rounds: int = Field(default=0, ge=0)


# ── CodeT5+ Classifier ──────────────────────────────────────────────────────

class ClassifierLabel(str, Enum):
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    UNCERTAIN = "uncertain"


class ClassifierResult(BaseModel):
    surface_id: str
    label: ClassifierLabel
    confidence: float = Field(ge=0.0, le=1.0)


# ── LLM Semantic Scan (ReAct loop) ───────────────────────────────────────────

class ScanVerdict(str, Enum):
    CONFIRMED = "confirmed"
    UNCERTAIN = "uncertain"


# ── Semantic Summarizer (LLM sub-object schemas) ──────────────────────────────

class TaintFlowSchema(BaseModel):
    untrusted_sources: list[str] = Field(default_factory=list)
    sanitizer_nodes: list[str] = Field(default_factory=list)
    sink_type: str = ""
    taint_propagates: bool = False


class AuthGuardSchema(BaseModel):
    check_present: bool = False
    check_location: str = ""


class LogicFlawSchema(BaseModel):
    resource_id_source: str = ""
    db_sink: str = ""
    check_location: str = ""


class LLMScanResult(BaseModel):
    verdict: ScanVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    cwe: str
    justification: str
    early_exit: bool = False
