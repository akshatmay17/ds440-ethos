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

# Public corpora. Licences checked on the HF dataset API / card (2026-11-03);
# keep docs/semantic-guard-finetune-plan.md ("Public corpora") in sync.
HF_CORPORA = {
    # dataset id: (config, split, builder)
    # Apache-2.0. 546 train rows, label 1 = injection.
    "deepset/prompt-injections": (None, "train", "deepset"),
    # Apache-2.0. 1044 train rows, type = jailbreak | benign.
    "jackhhao/jailbreak-classification": (None, "train", "jackhhao"),
    # MIT. 777 train rows of Gandalf "ignore instructions" attacks. Uses the
    # canonical "Lakera/..." casing; "lakera/..." also works, through a 307 redirect.
    "Lakera/gandalf_ignore_instructions": (None, "train", "gandalf"),
    # MIT. 223k train rows of Mosscap (DEF CON 31) password-extraction prompts.
    # Streamed and capped at --hf-limit. Labelled INJECTION wholesale, which is
    # noisy: a few rows are innocuous chat sent to the game.
    "Lakera/mosscap_prompt_injection": (None, "train", "mosscap"),
    # CC-BY-NC-4.0 (non-commercial). General instructions used as benign negatives.
    "tatsu-lab/alpaca": (None, "train", "alpaca_negative"),
    # CC-BY-SA-3.0 (share-alike: anything derived from these rows inherits it).
    # Benign negatives.
    "databricks/databricks-dolly-15k": (None, "train", "dolly_negative"),
}
STREAMED = {"Lakera/mosscap_prompt_injection"}  # large corpora: stream instead of full download


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

# Directories whose JSON scenarios are used for AGENT evaluation. Their text
# must never enter the classifier TRAIN split, or scanner/guard results on
# those cases are contaminated.
EVAL_SCENARIO_DIRS = [
    ROOT / "data" / "injections",
    ROOT / "data" / "imported",
    ROOT / "data" / "benign",
    ROOT / "data" / "capability",
    ROOT / "data" / "channels",
]
EVAL_TEXT_FIELDS = (
    "poisoned_content", "agent_prompt", "benign_prompt",
    "mock_urls", "mock_commands", "setup_files",
)


def _iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)


def eval_text_hashes() -> set[str]:
    """SHA1 (via dedup_key) of every text field in every eval scenario, so
    public-corpus rows that duplicate an eval payload can be dropped."""
    hashes: set[str] = set()
    for d in EVAL_SCENARIO_DIRS:
        for path in sorted(d.glob("*.json")) if d.exists() else []:
            try:
                cases = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(cases, list):
                continue
            for case in cases:
                for field in EVAL_TEXT_FIELDS:
                    for text in _iter_strings(case.get(field, "")):
                        t = norm(text)
                        if len(t) >= 8:
                            hashes.add(dedup_key(t))
    return hashes


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
                    "eval_derived": True,
                })
            # The agent prompt is the *benign* surrounding task — a hard negative.
            prompt = norm(case.get("agent_prompt", ""))
            if len(prompt) >= 8:
                out.append({
                    "text": prompt,
                    "label": BENIGN,
                    "source": "ethos:agent_prompt",
                    "eval_derived": True,
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
    # Exclude files that embed literal attack payloads (they are attack text,
    # not benign code — labeling them BENIGN poisons the hard negatives).
    code_files = [
        p for p in code_files
        if p.name not in ("synthetic.rs", "benchmark.rs")
    ]
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
            ds = datasets.load_dataset(repo, split=split, streaming=repo in STREAMED)
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
    elif kind == "mosscap":
        text = norm(row.get("prompt", ""))
        label = INJECTION  # same convention as Gandalf: secret-extraction attempts
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


def split(records: list[dict], seed: int, eval_cases: str = "heldout") -> dict[str, list[dict]]:
    rng = random.Random(seed)

    # Records derived from agent-eval scenarios are kept out of TRAIN so that
    # classifier/scanner numbers on those cases are not contaminated.
    #   heldout : eval-derived rows go to the TEST split only (never trained on)
    #   exclude : eval-derived rows are dropped entirely
    #   include : no separation (NOT recommended — leaks eval into train)
    eval_rows = [r for r in records if r.get("eval_derived")]
    records = [r for r in records if not r.get("eval_derived")]

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
    if eval_cases == "include":
        # Split eval rows across train/eval/test like everything else.
        groups2: dict[tuple[int, str], list[dict]] = {}
        for rec in eval_rows:
            bucket = rec["source"].split(":")[0].split("/")[0]
            groups2.setdefault((rec["label"], bucket), []).append(rec)
        for items in groups2.values():
            rng.shuffle(items)
            n = len(items)
            n_eval = max(1, int(n * 0.10)) if n >= 5 else 0
            n_test = max(1, int(n * 0.10)) if n >= 5 else 0
            splits["eval"] += items[:n_eval]
            splits["test"] += items[n_eval:n_eval + n_test]
            splits["train"] += items[n_eval + n_test:]
    elif eval_cases == "heldout":
        splits["test"] += eval_rows
    # "exclude": drop them

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
        "--eval-cases", choices=("heldout", "exclude", "include"), default="heldout",
        help="agent-eval scenario text: heldout=test split only (default), "
             "exclude=drop, include=split normally (leaks eval into train)",
    )
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

    # Drop any non-eval record whose text duplicates an eval scenario payload,
    # so public corpora cannot re-introduce eval text into the train split.
    eval_hashes = eval_text_hashes()
    kept, dropped = [], 0
    for r in records:
        if not r.get("eval_derived") and dedup_key(r["text"]) in eval_hashes:
            dropped += 1
            continue
        kept.append(r)
    records = kept
    if dropped:
        print(f"      dropped {dropped} record(s) colliding with eval scenario text")
    print(f"[4/4] {len(records)} unique records after dedup")

    splits = split(records, args.seed, args.eval_cases)
    n_eval_derived = sum(1 for items in splits.values() for r in items if r.get("eval_derived"))
    print(f"      eval-derived rows: {n_eval_derived} (policy: {args.eval_cases})")
    args.out.mkdir(parents=True, exist_ok=True)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_rev": git_rev(),
        "seed": args.seed,
        "hf": args.hf,
        "eval_cases_policy": args.eval_cases,
        "eval_derived_in_test": 0,
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
            if rec.get("eval_derived"):
                manifest["eval_derived_in_test"] += 1 if name == "test" else 0
        manifest["counts"][name] = by_label
        print(f"  {name}: {len(items)} -> {path}")

    MANIFEST_OUT.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_OUT.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"  manifest -> {MANIFEST_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
