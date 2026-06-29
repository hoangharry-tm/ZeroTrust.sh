#!/usr/bin/env python3
"""Pipeline orchestrator: run stages sequentially with checkpoint/resume."""
import importlib
import json
import time
from pathlib import Path

from pipeline.config import CFG, Config

STAGES = ["collect", "normalize", "label", "train", "evaluate"]

_MODULE: dict[str, str] = {
    "collect":   "pipeline.collectors",
    "normalize": "pipeline.normalizer",
    "label":     "pipeline.labeler",
    "train":     "pipeline.train",
    "evaluate":  "pipeline.evaluate",
}


def _ckpt(stage: str) -> Path:
    return CFG.checkpoint_dir / f"{stage}.done"


def run(stages: list[str] | None = None, cfg: Config = CFG, force: bool = False) -> None:
    for stage in stages or STAGES:
        ckpt = _ckpt(stage)
        if not force and ckpt.exists():
            print(f"skip  {stage}")
            continue
        print(f"run   {stage}")
        mod = importlib.import_module(_MODULE[stage])
        mod.run(cfg)
        cfg.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        ckpt.write_text(json.dumps({"ts": time.time()}))
        print(f"done  {stage}")


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="ZeroTrust pipeline runner")
    p.add_argument("stages", nargs="*", choices=STAGES, metavar="STAGE", help=f"Stages: {STAGES}")
    p.add_argument("--force", "-f", action="store_true", help="Re-run even if checkpoint exists")
    args = p.parse_args()
    run(args.stages or None, force=args.force)
