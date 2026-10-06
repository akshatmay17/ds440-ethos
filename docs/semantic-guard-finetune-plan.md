# SemanticGuard Fine-Tuning Plan — Ethos Custom Injection Classifier

**Status:** plan (GPU busy — execution queued)
**Owner:** Harsh Rathi (engineering)
**Feeds:** Paper 1 (Condition D defense telemetry + model-selection table)

---

## 1. Goal & Constraints

Ship an **ungated, Ethos-owned** prompt-injection/jailbreak classifier for the
`SemanticGuard` neural tier — no Meta license, no HuggingFace token, no
external gate. Two variants:

| Variant | Role | Backbone | Size | Latency target (CPU) |
| :--- | :--- | :--- | :--- | :--- |
| `ethos-guard-bert-base` | quality tier (`DebertaV3PromptInjection` slot) | `bert-base-uncased` fine-tune | ~440MB fp32 | <150ms |
| `ethos-guard-tiny` | **custom "Laya System 1"** (`LayaSystem1` slot) | `bert-tiny` fine-tune | ~17MB | <35ms |

Hard constraints:
- **BERT-family only** — the candle + tokenizers Rust loader is already
  verified end-to-end (`--features semantic-ml`); BERT checkpoints drop in
  with zero Rust changes.
- **RTX 3060 local** — BERT-base @ seq 512 / batch 16 ≈ 4–6GB VRAM; fits
  with fp16 even on the 6GB variant.
- **LM Studio clarification:** LM Studio cannot fine-tune (no training
  support). Its role is **data generation** (OpenAI-compatible API on
  `:1234`/`:2277`) and local generative eval.
- **Blind-test integrity:** the 34 in-repo cases (`data/injections/*.json`)
  and the synthetic evasion suite are the **frozen acceptance gate** —
  never trained on.

## 2. Data Plan

### 2.1 Positives (attacks)
| Source | Notes |
| :--- | :--- |
| `deepset/prompt-injections` | classic ungated corpus (~660 rows, EN+DE) |
| ProtectAI PINT benchmark (train split) | broad injection coverage |
| `jackhhao/jailbreak-classification` | jailbreak class |
| `lakera/gandalf_ignore_instructions` | instruction-override style |
| Ethos in-repo cases (34) | domain gold — seeds for generation, frozen for eval |
| **Synthetic multiplication** | extend `src/aci/synthetic.rs` mutations to dataset scale: homoglyphs, base64, zero-width splicing, markdown cloaking, role-play frames, `<|start_system_directive|>` wrappers, multi-turn splits |

Target: **20–50k positives** after augmentation.

### 2.2 Negatives (the hard part — this is where `mrm8488` failed)
| Source | Notes |
| :--- | :--- |
| `tatsu-lab/alpaca`, `databricks/dolly-15k` | benign instructions |
| `bigcode/the-stack-smol` slice | code-like agent context |
| Ethos repo itself | README/AGENTS.md/docs — **hard negatives**: security docs that *discuss* injection, exfil, `curl`, `.env` |
| LM Studio batch generation | domain-matched benign agent tasks (DeepSeek-R1/Qwen via local API) |
| Benign shell/config text | `.env`-shaped configs, API docs, changelogs phrasing "ignore previous" |

Target: **20–50k negatives**, ~1:1 balance, ≥10% hard negatives, code-like
text deliberately over-represented (agent context).

### 2.3 Labels
3-class head (Prompt-Guard parity): `0=BENIGN, 1=INJECTION, 2=JAILBREAK`
(ContextDilation folds into INJECTION). The Rust loader maps `id2label`
automatically — benign detection + risk-class mapping already handle this.

### 2.4 Splits
- Exact + MinHash dedup across all sources before splitting.
- Stratified 80/10/10 by source+label; cross-split contamination check.
- Frozen acceptance set: 34 Ethos cases + synthetic suite (never in train).

## 3. Training Recipe (RTX 3060)

- Base: `google-bert/bert-base-uncased` (and `prajjwal1/bert-tiny` variant)
- Seq len 512 (prefix-truncate), 4 epochs, lr 2e-5, warmup 6%, wd 0.01
- Batch 16 fp16 (12GB) / 8 + grad-accum 2 (6GB)
- Class weights for imbalance; early stop on eval macro-F1
- Python venv: `torch` (cu121), `transformers`, `datasets`, `scikit-learn`, `evaluate`
- Threshold calibration on eval split: **maximize attack recall subject to
  FPR ≤ 1%** (agent-safety posture); record the operating point in the model
  card and pass through `SemanticGuard::new(model_type, threshold)`.

## 4. Export & Integration

1. `save_pretrained(..., safe_serialization=True)` → `config.json` +
   `tokenizer.json` + `model.safetensors` (the exact format the loader was
   verified against).
2. Drop into `~/.ethos/models/ethos-guard-bert-base/`; run with
   `ETHOS_SEMANTIC_NEURAL=1 ETHOS_SEMANTIC_MODEL_DIR=...`.
3. Slot mapping: tiny → `SemanticModelType::LayaSystem1` (the custom Laya),
   base → `DebertaV3PromptInjection` slot.
4. **Rust↔Python parity test:** same 100 texts through both loaders; scores
   must agree within ±0.02 (this catches loader bugs — e.g., today's
   missing-CLS saturation was found exactly this way).
5. Live check: `cargo test --release --features semantic-ml --test
   test_rust_semantic_guard -- --ignored`.

## 5. Acceptance Gates (all must pass before shipping weights)

- Attack recall ≥ 99% on the frozen acceptance set (34 + synthetic).
- Benign FPR ≤ 1% on held-out benign corpus **including code and security
  documentation**.
- Rust↔Python parity ±0.02; latency targets met (base <150ms, tiny <35ms).
- All 25 existing test suites stay green with the neural tier loaded.
- No false positives on the Ethos repo's own README/AGENTS.md text.

## 6. Parallel Work While GPU Is Busy

1. `scripts/prepare_semantic_dataset.py` — download, dedup, split, manifest
   (no GPU). **Delivered:** `--local-only` pipeline runs offline today —
   253 records (88 attack-side + 165 hard negatives from repo docs/code),
   80/10/10 split, manifest at `reports/semantic_dataset_manifest.json`.
   `--hf` adds public corpora; `--extra` merges LM Studio generation files.
2. `scripts/eval_semantic_baseline.py` — baseline table for the paper.
   **Delivered (heuristic):** test-split attack recall **0.25** at FPR ≤ 1%
   vs the marker heuristic — the "before" column that motivates the neural
   tier. `--mode model --model-id <hf-or-dir>` runs any HF classifier
   (needs `pip install torch transformers`).
3. `scripts/generate_semantic_data_lmstudio.py` — LM Studio batch generation
   of benign agent tasks, hard negatives, and attack paraphrases
   (stdlib-only; run when the GPU frees up, then merge via `--extra`).
4. Rust-side **DeBERTa-v2/v3 candle port** — unlocks Prompt-Guard-86M /
   ProtectAI as additional slots without retraining.

## 7. Risks

- **Overfitting to attack phrasing** → public corpora + augmentation mix;
  paraphrase positives via LM Studio.
- **Code false-positives** (the observed `mrm8488` failure) → hard negatives
  + FPR gate + threshold calibration.
- **Benchmark contamination** → hash dedup; frozen acceptance set.
- **Dataset licensing** → record licenses per source; review before
  redistributing trained weights (repo is Unlicense; public corpora vary).
- **Weights are not committed to git** — ship via release asset or
  documented download; `data/semantic_guard/raw/` stays out of the repo.

## 8. Phases

| Phase | Work | GPU |
| :--- | :--- | :--- |
| 0 | This plan + prep scripts + dataset manifests | none |
| 1 | Dataset assembly, dedup, baselines | light |
| 2 | Train `ethos-guard-bert-base` (~30–60 min on 3060) | yes |
| 3 | Train tiny (Laya System 1) + threshold calibration + parity | yes |
| 4 | Wire defaults, README/AGENTS update, release v0.3 | none |
