#!/usr/bin/env python3
"""Ethos SemanticGuard fine-tuning (BERT-family, 3-class).

Trains BENIGN/INJECTION/JAILBREAK classifiers on the assembled corpus
(scripts/prepare_semantic_dataset.py), calibrates the operating threshold on
the eval split (max recall subject to FPR <= 1%), evaluates the frozen test
split, and exports the exact format the Rust loader consumes
(config.json + tokenizer.json + model.safetensors).

Usage:
  python scripts/train_semantic_guard.py --base google-bert/bert-base-uncased \
      --out models/ethos-guard-bert-base
  python scripts/train_semantic_guard.py --base prajjwal1/bert-tiny \
      --out models/ethos-guard-tiny --epochs 6
"""

from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from datasets import Dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = ROOT / "data" / "semantic_guard"

ID2LABEL = {0: "BENIGN", 1: "INJECTION", 2: "JAILBREAK"}
LABEL2ID = {v: k for k, v in ID2LABEL.items()}


def load_jsonl(path: Path) -> Dataset:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return Dataset.from_list(rows)


def compute_metrics(eval_pred) -> dict:
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    out = {}
    for cid, name in ID2LABEL.items():
        tp = int(((preds == cid) & (labels == cid)).sum())
        fp = int(((preds == cid) & (labels != cid)).sum())
        fn = int(((preds != cid) & (labels == cid)).sum())
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        out[f"{name}_precision"] = p
        out[f"{name}_recall"] = r
        out[f"{name}_f1"] = f1
    out["macro_f1"] = float(np.mean([out[f"{n}_f1"] for n in ID2LABEL.values()]))
    return out


def risk_scores(probs: np.ndarray) -> np.ndarray:
    """Risk = 1 - P(BENIGN); identical semantics to the Rust loader."""
    return 1.0 - probs[:, LABEL2ID["BENIGN"]]


def calibrate(probs: np.ndarray, labels: np.ndarray, max_fpr: float = 0.01) -> dict:
    risk = risk_scores(probs)
    best = None
    for thr in np.arange(0.30, 1.0, 0.01):
        pred = risk >= thr
        tp = int((pred & (labels != 0)).sum())
        fn = int((~pred & (labels != 0)).sum())
        fp = int((pred & (labels == 0)).sum())
        tn = int((~pred & (labels == 0)).sum())
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        if fpr <= max_fpr and (best is None or recall > best["recall"]):
            best = {"threshold": round(float(thr), 2), "recall": round(recall, 4), "fpr": round(fpr, 4)}
    if best is None:
        best = {"threshold": 0.90, "recall": 0.0, "fpr": 0.0, "note": "no threshold met FPR target"}
    return best


def _normalize_layernorm_keys(path: Path) -> None:
    """transformers v5 state dicts rename LayerNorm weight/bias to
    gamma/beta; candle (and v4-era loaders) expect the classic names.
    Normalizing to weight/bias works for both worlds (v5 loads old-style)."""
    try:
        from safetensors.torch import load_file, save_file

        state = load_file(str(path))
        renamed = {
            k.replace(".gamma", ".weight").replace(".beta", ".bias"): v
            for k, v in state.items()
        }
        if any(k != r for k, r in zip(state.keys(), renamed.keys())):
            save_file(renamed, str(path))
    except Exception as e:  # noqa: BLE001 - best effort, loader will report
        print(f"  ! layer-norm key normalization skipped: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--base", default="google-bert/bert-base-uncased")
    ap.add_argument("--tokenizer", default=None,
                    help="tokenizer override (e.g. prajjwal1/bert-tiny ships only a slow "
                         "vocab.txt — use google-bert/bert-base-uncased, same 30522 vocab)")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max-len", type=int, default=512)
    ap.add_argument("--seed", type=int, default=440)
    ap.add_argument("--max-negatives", type=int, default=0,
                    help="cap BENIGN rows in train (0 = no cap); guards class imbalance")
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"device: {device} ({torch.cuda.get_device_name(0) if device == 'cuda' else 'cpu'})")

    train_ds = load_jsonl(args.data / "train.jsonl")
    eval_ds = load_jsonl(args.data / "eval.jsonl")
    test_ds = load_jsonl(args.data / "test.jsonl")

    if args.max_negatives:
        benign = [r for r in train_ds if r["label"] == 0][: args.max_negatives]
        others = [r for r in train_ds if r["label"] != 0]
        train_ds = Dataset.from_list(others + benign)
    print(f"train={len(train_ds)} eval={len(eval_ds)} test={len(test_ds)}")

    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer or args.base)
    try:
        model = AutoModelForSequenceClassification.from_pretrained(
            args.base, num_labels=3, id2label=ID2LABEL, label2id=LABEL2ID,
        )
    except ValueError:
        # Old-style checkpoints (e.g. prajjwal1/bert-tiny) lack `model_type`
        # in config.json, which transformers v5 rejects on AutoModel.
        from transformers import BertConfig, BertForSequenceClassification

        cfg = BertConfig.from_pretrained(args.base)
        cfg.num_labels = 3
        cfg.id2label = ID2LABEL
        cfg.label2id = LABEL2ID
        model = BertForSequenceClassification.from_pretrained(args.base, config=cfg)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=args.max_len)

    train_tok = train_ds.map(tokenize, batched=True)
    eval_tok = eval_ds.map(tokenize, batched=True)
    test_tok = test_ds.map(tokenize, batched=True)

    # transformers v5 dropped warmup_ratio; compute steps instead.
    steps_per_epoch = math.ceil(len(train_tok) / args.batch)
    warmup_steps = max(1, int(steps_per_epoch * args.epochs * 0.06))

    args_training = TrainingArguments(
        output_dir=str(args.out / "_checkpoints"),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch * 2,
        learning_rate=args.lr,
        warmup_steps=warmup_steps,
        weight_decay=0.01,
        fp16=torch.cuda.is_available(),
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=1,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        logging_steps=50,
        report_to=[],
        seed=args.seed,
    )

    trainer = Trainer(
        model=model,
        args=args_training,
        train_dataset=train_tok,
        eval_dataset=eval_tok,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
    )
    trainer.train()

    # ---- calibration on eval; frozen-test evaluation -----------------------
    eval_probs = torch.softmax(
        torch.tensor(trainer.predict(eval_tok).predictions), dim=-1
    ).numpy()
    eval_labels = np.array(eval_ds["label"])
    operating = calibrate(eval_probs, eval_labels)
    print(f"operating point (FPR<=1%): {operating}")

    test_out = trainer.predict(test_tok)
    test_probs = torch.softmax(torch.tensor(test_out.predictions), dim=-1).numpy()
    test_labels = np.array(test_ds["label"])
    risk = risk_scores(test_probs)
    pred = risk >= operating["threshold"]
    tp = int((pred & (test_labels != 0)).sum())
    fn = int((~pred & (test_labels != 0)).sum())
    fp = int((pred & (test_labels == 0)).sum())
    tn = int((~pred & (test_labels == 0)).sum())
    acceptance = {
        "attack_recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "benign_fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }
    print(f"frozen test @ threshold {operating['threshold']}: {acceptance}")

    # ---- export (the exact layout cargo loader expects) --------------------
    args.out.mkdir(parents=True, exist_ok=True)
    trainer.model.save_pretrained(args.out, safe_serialization=True)
    tokenizer.save_pretrained(args.out)
    _normalize_layernorm_keys(args.out / "model.safetensors")
    (args.out / "ethos_model_card.json").write_text(json.dumps({
        "base": args.base,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "id2label": ID2LABEL,
        "operating_threshold": operating["threshold"],
        "eval_calibration": operating,
        "frozen_test": acceptance,
        "train_size": len(train_ds),
        "eval_size": len(eval_ds),
        "test_size": len(test_ds),
        "epochs": args.epochs,
        "seed": args.seed,
    }, indent=2), encoding="utf-8")
    print(f"exported -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
