#!/usr/bin/env python3
"""Diagnose misses/false-positives for a trained SemanticGuard model.

Prints the worst false negatives (attacks scored below threshold) and false
positives in the frozen Ethos acceptance subset, plus optional full-test hits.

Usage:
  python scripts/diagnose_semantic_guard.py --model-dir data/semantic_guard/models/ethos-guard-bert-base --threshold 0.38
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = ROOT / "data" / "semantic_guard"


def risk_scores(model, tokenizer, texts: list[str], batch: int = 64) -> list[float]:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    out = []
    for i in range(0, len(texts), batch):
        enc = tokenizer(texts[i:i + batch], truncation=True, max_length=512, padding=True, return_tensors="pt")
        enc = {k: v.to(device) for k, v in enc.items()}
        with torch.no_grad():
            probs = torch.softmax(model(**enc).logits, dim=-1)
        out += [float(1.0 - p) for p in probs[:, 0].cpu()]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model-dir", type=Path, required=True)
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--split", default="test")
    ap.add_argument("--threshold", type=float, required=True)
    ap.add_argument("--show", type=int, default=12)
    args = ap.parse_args()

    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    model.eval()
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)

    rows = [json.loads(l) for l in (args.data / f"{args.split}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    risk = risk_scores(model, tokenizer, [r["text"] for r in rows])

    def ethos_attack(r):
        return r["label"] != 0 and r["source"].startswith("ethos:")

    def ethos_neg(r):
        return r["label"] == 0 and (r["source"].startswith(("ethos-docs:", "ethos-code:")) or r["source"] == "ethos:agent_prompt")

    misses = sorted(
        ((x, r) for r, x in zip(rows, risk) if ethos_attack(r) and x < args.threshold),
        key=lambda t: t[0],
    )
    fps = sorted(
        ((x, r) for r, x in zip(rows, risk) if ethos_neg(r) and x >= args.threshold),
        key=lambda t: -t[0],
    )

    print(f"ETHOS ATTACK MISSES: {len(misses)}  (threshold {args.threshold})")
    for x, r in misses[: args.show]:
        print(f"  {x:.3f} [{r['source']}] {r['text'][:110]!r}")

    print(f"\nETHOS HARD-NEGATIVE FALSE POSITIVES: {len(fps)}")
    for x, r in fps[: args.show]:
        print(f"  {x:.3f} [{r['source']}] {r['text'][:110]!r}")

    # Full-test worst misses (public corpora; label noise expected)
    others = sorted(
        ((x, r) for r, x in zip(rows, risk) if r["label"] != 0 and not ethos_attack(r) and x < args.threshold),
        key=lambda t: t[0],
    )
    print(f"\nOTHER (public) TEST MISSES: {len(others)}")
    for x, r in others[:6]:
        print(f"  {x:.3f} [{r['source']}] {r['text'][:90]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
