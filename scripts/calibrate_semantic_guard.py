#!/usr/bin/env python3
"""Calibrate a trained SemanticGuard model and report acceptance metrics.

- Threshold is chosen on the EVAL split only (max recall subject to a
  configurable FPR budget, default 0.5% to leave margin).
- Reported on the frozen TEST split, split into:
    * overall test (mixed public corpora — contains label noise)
    * ETHOS acceptance subset (the in-repo attack corpus + repo docs/code
      hard negatives) — the paper's gate.
- Writes the chosen threshold + metrics back into ethos_model_card.json.

Usage:
  python scripts/calibrate_semantic_guard.py --model-dir data/semantic_guard/models/ethos-guard-bert-base
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = ROOT / "data" / "semantic_guard"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def is_ethos_attack(row: dict) -> bool:
    return row["label"] != 0 and row["source"].startswith("ethos:")


def is_ethos_hard_neg(row: dict) -> bool:
    return row["label"] == 0 and (
        row["source"].startswith(("ethos-docs:", "ethos-code:")) or row["source"] == "ethos:agent_prompt"
    )


def scores(model, tokenizer, rows: list[dict], batch: int = 64) -> list[float]:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    out: list[float] = []
    for i in range(0, len(rows), batch):
        texts = [r["text"] for r in rows[i:i + batch]]
        enc = tokenizer(texts, truncation=True, max_length=512, padding=True, return_tensors="pt")
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.no_grad():
            probs = torch.softmax(model(**enc).logits, dim=-1)
        out += [float(1.0 - p) for p in probs[:, 0].cpu()]
    return out


def stats(rows: list[dict], risk: list[float], thr: float) -> dict:
    tp = fn = fp = tn = 0
    for row, r in zip(rows, risk):
        pred = r >= thr
        if row["label"] != 0 and pred:
            tp += 1
        elif row["label"] != 0:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
    return {
        "n": len(rows),
        "attack_recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "benign_fpr": round(fp / (fp + tn), 4) if fp + tn else None,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model-dir", type=Path, required=True)
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--fpr-budget", type=float, default=0.005)
    args = ap.parse_args()

    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    model.eval()
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)

    eval_rows = load_jsonl(args.data / "eval.jsonl")
    test_rows = load_jsonl(args.data / "test.jsonl")
    eval_risk = scores(model, tokenizer, eval_rows)
    test_risk = scores(model, tokenizer, test_rows)

    best = None
    for thr in [round(0.30 + 0.01 * i, 2) for i in range(70)]:
        m = stats(eval_rows, eval_risk, thr)
        if m["benign_fpr"] is not None and m["benign_fpr"] <= args.fpr_budget:
            if best is None or m["attack_recall"] > best[1]["attack_recall"]:
                best = (thr, m)
    if best is None:
        raise SystemExit("no threshold met the FPR budget")
    thr, eval_m = best

    acceptance_rows = [r for r in test_rows if is_ethos_attack(r) or is_ethos_hard_neg(r)]
    acceptance_risk = [r for row, r in zip(test_rows, test_risk) if is_ethos_attack(row) or is_ethos_hard_neg(row)]

    report = {
        "model_dir": str(args.model_dir),
        "calibrated_at": datetime.now(timezone.utc).isoformat(),
        "fpr_budget": args.fpr_budget,
        "threshold": thr,
        "eval": eval_m,
        "test_overall": stats(test_rows, test_risk, thr),
        "test_ethos_attacks": stats(
            [r for r in test_rows if is_ethos_attack(r)],
            [r for row, r in zip(test_rows, test_risk) if is_ethos_attack(row)], thr),
        "test_ethos_hard_negatives": stats(
            [r for r in test_rows if is_ethos_hard_neg(r)],
            [r for row, r in zip(test_rows, test_risk) if is_ethos_hard_neg(row)], thr),
    }
    for name in ("test_overall", "test_ethos_attacks", "test_ethos_hard_negatives"):
        m = report[name]
        print(f"{name}: n={m['n']} recall={m['attack_recall']} fpr={m['benign_fpr']} ({m['tp']}/{m['fn']}/{m['fp']}/{m['tn']})")
    print(f"threshold (FPR budget {args.fpr_budget}): {thr}  eval={eval_m}")

    card_path = args.model_dir / "ethos_model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8")) if card_path.exists() else {}
    card["operating_threshold"] = thr
    card["acceptance"] = report
    card_path.write_text(json.dumps(card, indent=2), encoding="utf-8")
    print(f"model card updated -> {card_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
