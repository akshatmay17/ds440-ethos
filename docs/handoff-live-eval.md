# Handoff: running the live Paper-1 evaluation on the LM Studio machine

The v2 evaluation harness is merged to `main`. The cloud session that built it
can't reach your local LM Studio, so the live, model-attributed runs happen on
**your PC**. This is the whole procedure.

## 0. Get the code

```powershell
git checkout main
git pull origin main          # must include the "Merge pull request #14" commit
cargo build --release          # or plain `cargo build`; release is faster for a big sweep
```

Git LFS note: the classifier weights under `models/` are LFS pointers. If you
need them (`--features semantic-ml`), run `git lfs pull` once. The eval below
does **not** need them.

## 1. Start LM Studio

1. Launch LM Studio, load the model you want to evaluate (e.g. a DeepSeek-R1
   distill), and **Start Server**.
2. The harness probes `http://127.0.0.1:2277/v1` then `http://127.0.0.1:1234/v1`.
   If your server is on a different port, pass `--endpoint http://127.0.0.1:<port>/v1`
   or set `LM_STUDIO_URL`.
3. Sanity check it's reachable:

   ```powershell
   curl http://127.0.0.1:1234/v1/models
   ```

The harness is **fail-closed**: if it can't reach the server it exits with an
error instead of faking a run. If you see "LM Studio is not reachable", the
server isn't up on a probed port — it is not a code bug.

> `--model deepseek-r1` is a label; on the LM Studio path the harness uses
> whichever deepseek/r1 model the server actually has loaded and records that
> real id in the report (`model` field). Load the model you intend to test.

## 2. Pilot first (cheap, ~minutes)

Confirm everything works and the model is actually being driven before a long
sweep. One repeat, the local attack families only:

```powershell
cargo run --release -- eval --dataset attacks --provider lmstudio --model deepseek-r1 `
  --condition full --variant benign --repeats 1 --output reports/pilot_attacks.json
```

Open `reports/pilot_attacks.json` and check:
- `"driver": "live"` and `"model"` is the real loaded id (NOT `scripted`),
- `invalid_runs` is 0 (if not, the server dropped — restart it),
- some runs show `attack_attempted` / `attack_succeeded` / `attack_blocked`.

If `driver` says `scripted`, the server wasn't reachable and you must fix that
before trusting any numbers.

## 3. The real runs

```powershell
# Local attack families, both task framings, 3 repeats for confidence intervals
cargo run --release -- eval --dataset attacks --provider lmstudio --model deepseek-r1 `
  --condition full --variant both --repeats 3 --output reports/attacks_full.json

# Benign controls + capability tasks (false-positive rate + utility)
cargo run --release -- eval --dataset all --provider lmstudio --model deepseek-r1 `
  --condition full --variant benign --repeats 3 --output reports/all_full.json

# The condition comparison (A vs D): same scenarios, no walls vs full walls
cargo run --release -- eval --dataset attacks --provider lmstudio --model deepseek-r1 `
  --condition raw-shell --variant both --repeats 3 --output reports/attacks_rawshell.json

# A 200-case pilot of the full upstream InjecAgent set (generate it first)
python scripts/import_injecagent.py
cargo run --release -- eval --dataset injecagent-upstream --provider lmstudio --model deepseek-r1 `
  --condition full --sample 200 --seed 440 --output reports/injecagent_sample.json
```

PowerShell 5.1 has no `&&`; the backtick `` ` `` is the line continuation above.

## 4. Build the paper tables

```powershell
# Per-condition / per-variant table with Wilson 95% CIs
python scripts/make_tables.py reports/attacks_full.json reports/all_full.json

# Attack-success difference between conditions (paired McNemar)
python scripts/make_tables.py --mcnemar full raw-shell `
  reports/attacks_full.json reports/attacks_rawshell.json

# CSV / LaTeX for the paper
python scripts/make_tables.py --csv   reports/*_full.json > reports/tables.csv
python scripts/make_tables.py --latex reports/*_full.json > reports/tables.tex
```

`make_tables.py` refuses `driver: scripted` reports unless `--include-scripted`,
and prints a warning row for the old `*_eval_results.json` files — don't cite
those.

## 5. Scanner numbers (no model needed)

```powershell
python scripts/prepare_semantic_dataset.py --hf     # builds data/semantic_guard/ (first time)
cargo run --release -- scanner-eval --semantic      # precision/recall/F1 of the enforcing scanner
```

## 6. Model comparison (optional)

Repeat §3 with a second model loaded in LM Studio and a different `--output`
name, then pass both reports to `make_tables.py`. Each report records its own
served model, so rows stay attributable.

## 7. Commit the reports back

```powershell
git add reports/*_full.json reports/*_sample.json reports/*.traces.jsonl
git commit -m "eval: live DeepSeek-R1 runs through the v2 harness"
git push origin main
```

(`reports/` is tracked; `data/imported/` and `data/semantic_guard/` are
gitignored and stay local.)

## What to hand back / flag to the cloud session

- Any run with `invalid_runs > 0` or `driver: scripted` — means the server
  dropped; those runs are excluded from denominators but worth knowing.
- The `make_tables.py` output (paste it in) — that's the Paper-1 result.
- Anything that errors with a message you don't expect.

## Reference

- Scenario + report schema: `docs/eval-scenario-schema.md`
- Dataset names and flags: `AGENTS.md` → "Benchmark evals"
- Measured results + limits writeup: `docs/security-evaluation.md`
