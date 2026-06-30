#!/usr/bin/env python3
"""LoRA fine-tuning of Salesforce/codet5p-220m on CVEFixes corpus.

Usage:
    python scripts/train_lora.py --language python
    python scripts/train_lora.py --language all          # trains each language in sequence
    python scripts/train_lora.py --language python --eval-only  # skip train, only benchmark

Adapters saved to ~/.zerotrust/adapters/{language}/
Eval probabilities exported to ~/.zerotrust/adapters/{language}/eval_probs.csv
  (columns: prob, label — consumed by scripts/calibrate.py --eval-probs)
"""
from __future__ import annotations

import argparse
import csv
import json
import pathlib
import sys
from typing import Any

try:
    from torch.utils.data import Dataset as _Dataset
except ImportError:
    _Dataset = object  # type: ignore[assignment,misc]

NORMALIZED_DIR = pathlib.Path("tests/corpus/normalized")
ADAPTERS_DIR = pathlib.Path.home() / ".zerotrust" / "adapters"
MODEL_NAME = "Salesforce/codet5p-220m"
BATCH_SIZE = 8  # ponytail: mirrors Go ClassifierBatchSize = 8
LORA_R = 16
LORA_ALPHA = 32
LORA_DROPOUT = 0.05
MAX_EPOCHS = 5
LEARNING_RATE = 2e-4
LANGUAGES = ["python", "java", "javascript", "typescript", "go", "c#"]


def _load_jsonl(path: pathlib.Path) -> list[dict]:
    with path.open() as f:
        return [json.loads(l) for l in f if l.strip()]


def _load_weights(lang: str) -> tuple[float, float]:
    path = NORMALIZED_DIR / f"{lang}_weights.json"
    if path.exists():
        w = json.loads(path.read_text())
        return float(w.get("vuln", 1.0)), float(w.get("safe", 1.0))
    return 1.0, 1.0


def _find_attention_modules(model) -> list[str]:
    """Dynamically find attention projection layers for LoRA targeting."""
    target: list[str] = []
    for name, _ in model.named_modules():
        # T5 uses q, k, v, o projections inside SelfAttention
        if any(name.endswith(f".{proj}") for proj in ("q", "k", "v", "o", "wi", "wo")):
            target.append(name.split(".")[-1])
    # De-duplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for t in target:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique if unique else ["q", "v"]


class _VulnDataset(_Dataset):  # type: ignore[misc]
    def __init__(self, records: list[dict], tokenizer: Any, max_length: int = 1024) -> None:
        self.records = records
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, idx: int) -> dict:
        import torch
        r = self.records[idx]
        enc = self.tokenizer(
            r["code"],
            max_length=self.max_length,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "label": torch.tensor(float(r["label"]), dtype=torch.float32),
        }


def _mean_pool(last_hidden, attention_mask):
    mask = attention_mask.unsqueeze(-1).float()
    return (last_hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)


def train_language(lang: str, eval_only: bool = False) -> None:
    try:
        import torch
        from peft import LoraConfig, get_peft_model, TaskType  # type: ignore[import-untyped]
        from torch import nn
        from torch.utils.data import DataLoader
        from transformers import AutoTokenizer, T5EncoderModel  # type: ignore[import-untyped]
    except ImportError as exc:
        print(f"missing dependency: {exc} — pip install peft transformers torch", file=sys.stderr)
        sys.exit(1)

    adapter_dir = ADAPTERS_DIR / lang
    adapter_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=== {lang} ===", file=sys.stderr)

    train_path = NORMALIZED_DIR / f"{lang}_train.jsonl"
    test_path = NORMALIZED_DIR / f"{lang}_test.jsonl"

    if not test_path.exists():
        print(f"  no test split for {lang} — skipping", file=sys.stderr)
        return

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    base_model = T5EncoderModel.from_pretrained(MODEL_NAME)

    if not eval_only and train_path.exists():
        target_modules = _find_attention_modules(base_model)
        print(f"  LoRA target_modules: {target_modules}", file=sys.stderr)

        lora_cfg = LoraConfig(
            r=LORA_R,
            lora_alpha=LORA_ALPHA,
            lora_dropout=LORA_DROPOUT,
            target_modules=target_modules,
            task_type=TaskType.FEATURE_EXTRACTION,
            bias="none",
        )
        model = get_peft_model(base_model, lora_cfg)
        model.print_trainable_parameters()

        # Linear probe on top of mean-pooled encoder
        hidden_size = model.config.hidden_size
        probe = nn.Linear(hidden_size, 1).to("cpu")
        nn.init.xavier_uniform_(probe.weight)
        nn.init.zeros_(probe.bias)

        vuln_w, safe_w = _load_weights(lang)
        # BCEWithLogitsLoss with pos_weight = vuln_w / safe_w
        pos_weight = torch.tensor([vuln_w / safe_w])
        loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

        train_records = _load_jsonl(train_path)
        train_ds = _VulnDataset(train_records, tokenizer)
        loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, num_workers=0)

        params = list(model.parameters()) + list(probe.parameters())
        optimizer = torch.optim.AdamW(params, lr=LEARNING_RATE)

        use_fp16 = torch.cuda.is_available()
        scaler = torch.amp.GradScaler("cuda") if use_fp16 else None  # type: ignore[attr-defined]

        model.train()
        probe.train()
        for epoch in range(MAX_EPOCHS):
            total_loss = 0.0
            for batch in loader:
                optimizer.zero_grad()
                input_ids = batch["input_ids"]
                attn_mask = batch["attention_mask"]
                labels = batch["label"]

                if use_fp16 and scaler is not None:
                    with torch.amp.autocast("cuda"):  # type: ignore[attr-defined]
                        out = model(input_ids=input_ids, attention_mask=attn_mask)
                        pooled = _mean_pool(out.last_hidden_state, attn_mask)
                        logits = probe(pooled).squeeze(-1)
                        loss = loss_fn(logits, labels)
                    scaler.scale(loss).backward()
                    scaler.step(optimizer)
                    scaler.update()
                else:
                    out = model(input_ids=input_ids, attention_mask=attn_mask)
                    pooled = _mean_pool(out.last_hidden_state, attn_mask)
                    logits = probe(pooled).squeeze(-1)
                    loss = loss_fn(logits, labels)
                    loss.backward()
                    optimizer.step()

                total_loss += loss.item()

            avg = total_loss / max(len(loader), 1)
            print(f"  epoch {epoch + 1}/{MAX_EPOCHS}  loss={avg:.4f}", file=sys.stderr)

        model.save_pretrained(str(adapter_dir))
        torch.save(probe.state_dict(), adapter_dir / "probe.pt")
        print(f"  adapter saved to {adapter_dir}", file=sys.stderr)
    else:
        # Eval-only: load saved adapter
        if not (adapter_dir / "adapter_config.json").exists():
            print(f"  no adapter found at {adapter_dir} — skipping eval", file=sys.stderr)
            return

        try:
            from peft import PeftModel  # type: ignore[import-untyped]
        except ImportError:
            print("peft required for eval: pip install peft", file=sys.stderr)
            sys.exit(1)

        hidden_size = base_model.config.hidden_size
        probe = nn.Linear(hidden_size, 1)
        probe.load_state_dict(torch.load(adapter_dir / "probe.pt", map_location="cpu"))
        model = PeftModel.from_pretrained(base_model, str(adapter_dir))

    # Evaluation on test split
    model.eval()
    probe.eval()
    test_records = _load_jsonl(test_path)
    test_ds = _VulnDataset(test_records, tokenizer)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, shuffle=False, num_workers=0)

    all_probs: list[float] = []
    all_labels: list[int] = []

    with torch.no_grad():
        for batch in test_loader:
            out = model(input_ids=batch["input_ids"], attention_mask=batch["attention_mask"])
            pooled = _mean_pool(out.last_hidden_state, batch["attention_mask"])
            logits = probe(pooled).squeeze(-1)
            probs = torch.sigmoid(logits).tolist()
            all_probs.extend(probs if isinstance(probs, list) else [probs])
            all_labels.extend(int(l) for l in batch["label"].tolist())

    # Export eval probs for calibrate.py
    eval_probs_path = adapter_dir / "eval_probs.csv"
    with eval_probs_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["prob", "label"])
        writer.writerows(zip(all_probs, all_labels))
    print(f"  eval probs exported to {eval_probs_path}", file=sys.stderr)

    # Quick accuracy summary
    correct = sum(1 for p, l in zip(all_probs, all_labels) if (round(p) == l))
    acc = correct / len(all_labels) if all_labels else 0.0
    print(f"  test accuracy: {acc:.3f} ({correct}/{len(all_labels)})", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", default="all", help="language or 'all'")
    parser.add_argument("--eval-only", action="store_true", help="skip training, only benchmark")
    args = parser.parse_args()

    langs = LANGUAGES if args.language == "all" else [args.language]
    for lang in langs:
        train_language(lang, eval_only=args.eval_only)


if __name__ == "__main__":
    main()
