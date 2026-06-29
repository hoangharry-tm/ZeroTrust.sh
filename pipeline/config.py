from dataclasses import dataclass, field
from pathlib import Path

_ROOT = Path(__file__).parent.parent


@dataclass
class Config:
    # Paths
    raw_dir: Path = field(default_factory=lambda: _ROOT / "tests/corpus/raw")
    checkpoint_dir: Path = field(default_factory=lambda: _ROOT / ".pipeline")

    # Data
    languages: list[str] = field(
        default_factory=lambda: ["python", "java", "javascript", "go", "csharp"]
    )

    # Model
    model_id: str = "Salesforce/codet5p-220m"
    max_tokens: int = 1024  # ponytail: CodeT5+ primary limit
    fallback_max_tokens: int = 512

    # Thresholds
    vuln_threshold: float = 0.5  # classifier min confidence
    label_confidence: float = 0.7  # cleanlab label quality cutoff


CFG = Config()
