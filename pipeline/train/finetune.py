"""LoRA fine-tuning for patch generation on curated vulnerability dataset.

Loads .tmp/train_data.jsonl + .tmp/val_data.jsonl produced by worker/training/curate.py,
applies PEFT LoRA adapters to the base model, and saves adapter weights to models/lora_adapters/.

Usage:
    python pipeline/train/finetune.py [--model ...] [--data-dir .tmp] [--output models/lora_adapters]
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


def _format_prompt(example: dict) -> str:
    return (
        f"### Instruction:\n{example['instruction']}\n\n"
        f"### Input:\n{example['input']}\n\n"
        f"### Response:\n{example['output']}"
    )


def train(
    model_name: str,
    data_dir: Path,
    output_dir: Path,
    lora_r: int,
    lora_alpha: int,
    epochs: int,
    batch_size: int,
    lr: float,
) -> None:
    # Lazy imports so the module is importable without GPU deps installed.
    import torch
    from datasets import load_dataset  # type: ignore[import-untyped]
    from peft import LoraConfig, TaskType, get_peft_model  # type: ignore[import-untyped]
    from transformers import (  # type: ignore[import-untyped]
        AutoModelForCausalLM,
        AutoTokenizer,
        EarlyStoppingCallback,
        TrainingArguments,
    )
    from trl import SFTTrainer  # type: ignore[import-untyped]

    output_dir.mkdir(parents=True, exist_ok=True)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    log.info("device=%s model=%s", device, model_name)

    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        trust_remote_code=True,
        torch_dtype=torch.float16 if device == "cuda" else torch.float32,
        device_map="auto" if device == "cuda" else None,
    )

    lora_cfg = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=0.05,
        target_modules=["q_proj", "v_proj"],  # ponytail: covers most causal LM families
    )
    model = get_peft_model(model, lora_cfg)
    model.print_trainable_parameters()

    raw = load_dataset(
        "json",
        data_files={
            "train": str(data_dir / "train_data.jsonl"),
            "validation": str(data_dir / "val_data.jsonl"),
        },
    )
    dataset = raw.map(lambda ex: {"text": _format_prompt(ex)})

    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size,
        gradient_accumulation_steps=4,
        learning_rate=lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        fp16=device == "cuda",
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=10,
        report_to="none",
    )

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        dataset_text_field="text",
        max_seq_length=1024,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    try:
        trainer.train()
    except RuntimeError as exc:
        if "out of memory" in str(exc).lower():
            log.error("CUDA OOM — reduce batch_size or lora_r: %s", exc)
            raise SystemExit(1) from exc
        raise

    model.save_pretrained(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))
    log.info("adapter weights saved → %s", output_dir)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="LoRA fine-tune on curated vulnerability patches")
    ap.add_argument("--model", default=os.getenv("ZT_FINETUNE_MODEL", "Salesforce/codet5p-220m-py"))
    ap.add_argument("--data-dir", default=".tmp")
    ap.add_argument("--output", default="models/lora_adapters")
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch-size", type=int, default=4)
    ap.add_argument("--lr", type=float, default=2e-4)
    args = ap.parse_args()

    train(
        model_name=args.model,
        data_dir=Path(args.data_dir),
        output_dir=Path(args.output),
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
    )


if __name__ == "__main__":
    main()
