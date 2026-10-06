#!/usr/bin/env python3
"""Ethos SemanticGuard dataset builder.

Assembles a 3-class prompt-injection training corpus for the custom
`ethos-guard-*` classifiers (see docs/semantic-guard-finetune-plan.md).

  labels: 0 = BENIGN, 1 = INJECTION, 2 = JAILBREAK
  records: {"text": str, "label": int, "source": str}

Stages:
  1. Positives from the in-repo Ethos attack corpus (data/injections/*.json)
  2. Negatives from the Ethos repo itself (docs + Rust code = hard negatives)
  3. Optional public HF corpora (--hf; needs `pip install datasets`)
  4. Exact dedup, then deterministic stratified 80/10/10 split by (label, source)
  5. JSONL splits + a manifest (counts, hashes, seed, git rev) in reports/

Usage:
  python scripts/prepare_semantic_dataset.py --local-only
  python scripts/prepare_semantic_dataset.py --hf --hf-limit 5000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INJECTION_DIR = ROOT / "data" / "injections"
DEFAULT_OUT = ROOT / "data" / "semantic_guard"
MANIFEST_OUT = ROOT / "reports" / "semantic_dataset_manifest.json"

BENIGN, INJECTION, JAILBREAK = 0, 1, 2

JAILBREAK_HINTS = (
    "dan", "jailbreak", "developer mode", "do anything now", "persona",
    "role-play", "roleplay", "no restrictions", "unrestricted",
)

HF_CORPORA = {
    # dataset id: (config, split, builder)
    "deepset/prompt-injections": (None, "train", "deepset"),
    "jackhhao/jailbreak-classification": (None, "train", "jackhhao"),
    "lakera/gandalf_ignore_instructions": (None, "train", "gandalf"),
    "tatsu-lab/alpaca": (None, "train", "alpaca_negative"),
    "databricks/databricks-dolly-15k": (None, "train", "dolly_negative"),
}


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def dedup_key(text: str) -> str:
    return hashlib.sha1(norm(text).lower().encode("utf-8", "ignore")).hexdigest()


def guess_label(record: dict, text: str) -> int:
    meta = " ".join(
        str(record.get(k, ""))
        for k in ("name", "attack_type", "technique", "evasion_mechanism", "actor_goal", "attacker_goal")
    ).lower()
    blob = (meta + " " + text).lower()
    return JAILBREAK if any(h in blob for h in JAILBREAK_HINTS) else INJECTION


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------

def load_ethos_positives() -> list[dict]:
    out = []
    for path in sorted(INJECTION_DIR.glob("*.json")):
        try:
            cases = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"  ! skip {path.name}: {e}", file=sys.stderr)
            continue
        if not isinstance(cases, list):
            continue
        for case in cases:
            poison = norm(case.get("poisoned_content", ""))
            if len(poison) >= 8:
                out.append({
                    "text": poison,
                    "label": guess_label(case, poison),
                    "source": f"ethos:{path.stem}",
                })
            # The agent prompt is the *benign* surrounding task — a hard negative.
            prompt = norm(case.get("agent_prompt", ""))
            if len(prompt) >= 8:
                out.append({
                    "text": prompt,
                    "label": BENIGN,
                    "source": "ethos:agent_prompt",
                })
    return out


def load_ethos_negatives() -> list[dict]:
    """Docs + code from this repo: the exact domain text the guard must not flag."""
    out = []

    doc_files = [ROOT / "README.md", ROOT / "AGENTS.md", ROOT / "TODO.md", ROOT / "PROPOSAL.md"]
    doc_files += sorted((ROOT / "docs").glob("*.md"))
    for path in doc_files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for chunk in chunk_text(text, 1200):
            out.append({"text": chunk, "label": BENIGN, "source": f"ethos-docs:{path.name}"})

    code_files = sorted((ROOT / "src").rglob("*.rs"))
    rng = random.Random(440)
    rng.shuffle(code_files)
    for path in code_files[:40]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for chunk in chunk_text(text, 1200)[:4]:
            out.append({"text": chunk, "label": BENIGN, "source": f"ethos-code:{path.name}"})
    return out


def chunk_text(text: str, size: int) -> list[str]:
    text = norm(text)
    if len(text) <= size:
        return [text] if len(text) >= 8 else []
    # Chunk on whitespace boundaries.
    words = text.split(" ")
    chunks, current, length = [], [], 0
    for w in words:
        if length + len(w) + 1 > size and current:
            chunks.append(" ".join(current))
            current, length = [], 0
        current.append(w)
        length += len(w) + 1
    if current:
        chunks.append(" ".join(current))
    return chunks


def load_hf_corpora(limit: int) -> list[dict]:
    try:
        import datasets  # noqa: F401  (optional dependency)
    except ImportError:
        print("!! --hf requested but `datasets` is not installed: pip install datasets", file=sys.stderr)
        return []

    out = []
    for repo, (_cfg, split, kind) in HF_CORPORA.items():
        try:
            ds = datasets.load_dataset(repo, split=split)
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"  ! {repo}: {e}", file=sys.stderr)
            continue
        count = 0
        for row in ds:
            if count >= limit:
                break
            rec = _hf_row_to_record(kind, row, repo)
            if rec:
                out.append(rec)
                count += 1
        print(f"  + {repo}: {count} rows")
    return out


def _hf_row_to_record(kind: str, row: dict, repo: str) -> dict | None:
    if kind == "deepset":
        text = norm(row.get("text", ""))
        label = INJECTION if int(row.get("label", 0)) == 1 else BENIGN
    elif kind == "jackhhao":
        text = norm(row.get("prompt", ""))
        label = JAILBREAK if str(row.get("type", "")).lower() == "jailbreak" else BENIGN
    elif kind == "gandalf":
        text = norm(row.get("text", ""))
        label = INJECTION
    elif kind == "alpaca_negative":
        text = norm(f"{row.get('instruction', '')} {row.get('input', '')}".strip())
        label = BENIGN
    elif kind == "dolly_negative":
        text = norm(f"{row.get('instruction', '')} {row.get('context', '')}".strip())
        label = BENIGN
    else:
        return None
    if len(text) < 8:
        return None
    return {"text": text[:8000], "label": label, "source": f"hf:{repo}"}


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def dedup(records: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for rec in records:
        key = dedup_key(rec["text"])
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def split(records: list[dict], seed: int) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    groups: dict[tuple[int, str], list[dict]] = {}
    for rec in records:
        bucket = rec["source"].split(":")[0].split("/")[0]
        groups.setdefault((rec["label"], bucket), []).append(rec)

    splits = {"train": [], "eval": [], "test": []}
    for items in groups.values():
        rng.shuffle(items)
        n = len(items)
        n_eval = max(1, int(n * 0.10)) if n >= 5 else 0
        n_test = max(1, int(n * 0.10)) if n >= 5 else 0
        splits["eval"] += items[:n_eval]
        splits["test"] += items[n_eval:n_eval + n_test]
        splits["train"] += items[n_eval + n_test:]
    for items in splits.values():
        rng.shuffle(items)
    return splits


def git_rev() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=440)
    ap.add_argument("--local-only", action="store_true", help="skip HF downloads (offline mode)")
    ap.add_argument("--hf", action="store_true", help="include public HF corpora")
    ap.add_argument("--hf-limit", type=int, default=5000, help="rows per HF source")
    ap.add_argument(
        "--extra", type=Path, action="append", default=[],
        help="extra JSONL files ({text,label,source}) — e.g. LM Studio output; repeatable",
    )
    args = ap.parse_args()

    if args.hf and args.local_only:
        ap.error("--hf and --local-only are mutually exclusive")

    records: list[dict] = []
    print("[1/4] Ethos attack corpus (positives + benign agent prompts)…")
    records += load_ethos_positives()
    print(f"      {len(records)} records")

    print("[2/4] Ethos repo docs + code (hard negatives)…")
    before = len(records)
    records += load_ethos_negatives()
    print(f"      {len(records) - before} records")

    if args.hf:
        print(f"[3/4] Public HF corpora (limit {args.hf_limit}/source)…")
        records += load_hf_corpora(args.hf_limit)
    else:
        print("[3/4] Public HF corpora skipped (use --hf to include)")

    for extra in args.extra:
        try:
            added = 0
            for line in extra.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                text = norm(rec.get("text", ""))
                if len(text) >= 8 and int(rec.get("label", BENIGN)) in (BENIGN, INJECTION, JAILBREAK):
                    records.append({"text": text[:8000], "label": int(rec["label"]),
                                    "source": str(rec.get("source", f"extra:{extra.name}"))})
                    added += 1
            print(f"      + {extra}: {added} records")
        except (OSError, json.JSONDecodeError) as e:
            print(f"  ! skip {extra}: {e}", file=sys.stderr)

    records = dedup(records)
    print(f"[4/4] {len(records)} unique records after dedup")

    splits = split(records, args.seed)
    args.out.mkdir(parents=True, exist_ok=True)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_rev": git_rev(),
        "seed": args.seed,
        "hf": args.hf,
        "labels": {"0": "BENIGN", "1": "INJECTION", "2": "JAILBREAK"},
        "counts": {},
        "splits": {},
        "sha256": {},
    }
    for name, items in splits.items():
        path = args.out / f"{name}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for rec in items:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        payload = path.read_bytes()
        manifest["splits"][name] = len(items)
        manifest["sha256"][name] = hashlib.sha256(payload).hexdigest()
        by_label: dict[str, int] = {}
        for rec in items:
            by_label[str(rec["label"])] = by_label.get(str(rec["label"]), 0) + 1
        manifest["counts"][name] = by_label
        print(f"  {name}: {len(items)} -> {path}")

    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"  manifest -> {MANIFEST_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
