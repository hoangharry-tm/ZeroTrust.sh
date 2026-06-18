"""XGrammar-2-enforced JSON schemas for all Python worker response types.

These Pydantic models define the wire format between the Go orchestrator and the
Python worker. The Go side unmarshals the `result` field of each Response into
the appropriate struct.
"""

from enum import Enum

from pydantic import BaseModel, Field

# ── LLM Verifier ─────────────────────────────────────────────────────────────

class LLMVerdict(str, Enum):
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class LLMVerifierResult(BaseModel):
    """Wire schema returned by the llm_verify handler to the Go orchestrator."""

    verdict: LLMVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    justification: str = Field(max_length=200)
    asc_rounds: int = Field(default=0, ge=0)


# ── UniXcoder Classifier ──────────────────────────────────────────────────────

class ClassifierLabel(str, Enum):
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    UNCERTAIN = "uncertain"


class ClassifierResult(BaseModel):
    verdict: ClassifierLabel
    confidence: float = Field(ge=0.0, le=1.0)


# ── LLM Semantic Scan (ReAct loop) ───────────────────────────────────────────

class ScanVerdict(str, Enum):
    CONFIRMED = "confirmed"
    UNCERTAIN = "uncertain"


class LLMScanResult(BaseModel):
    verdict: ScanVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    cwe: str
    justification: str
