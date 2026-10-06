# AGENTS.md — Ethos

Rust runtime (`ethos`) providing a taint-tracked sandbox and Agent-Computer Interface (ACI) for autonomous AI coding agents: bitmask provenance tracking, snapshot/rewind, injection containment walls, and a benchmark evaluation harness feeding Paper 1 (DS 440 capstone).

## Commands

- CI gate (`.github/workflows/ci.yml`): `cargo check --all-targets` then `cargo test`. Both must pass before handing off.
- Run one suite: `cargo test --test test_rust_walls` — suites are `tests/test_rust_*.rs`.
- Run one test: `cargo test test_ouroboros`.
- Run the CLI: `cargo run -- [subcommand]` (`default-run = "ethos"`; no `--bin` needed). **There is no `tbox` binary** — mentions in older docs are stale; only `ethos` exists in `Cargo.toml`.
- Subcommands: default (interactive harness), `setup` (provider wizard), `daemon --port` (Axum REST, default 8000), `app` (daemon + browser UI), `run --task "..."`, `eval`, `doctor` (env diagnostics: Postgres, Git, MinGit, walls, sandbox), `tui` (ratatui dashboard).
- No clippy/rustfmt gate in CI; keep the build warning-free.

## Testing gotchas

- `tests/` mixes Rust integration tests (`test_rust_*.rs`, run by `cargo test`) with **stale Python tests** (`test_*.py`) that import a Python `ethos` package that no longer exists (legacy of the pre-Rewrite prototype). Cargo ignores them; do not run pytest, and do not "fix" their imports.
- Postgres is optional everywhere: `DATABASE_URL` only enables the persistent session store (`src/store/postgres.rs`, schema `migrations/0001_init.sql`). Rust tests never need a database.

## Environment

- Copy `.env.example` to `.env` (gitignored; auto-loaded via `dotenvy` at startup). Provider keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `SPIDER_API_KEY`) are optional — pick per provider.
- Local inference (optional, for live evals): LM Studio on port `1234`/`2277` or Ollama on `11434`. Ethos probes these and **falls back to a deterministic baseline driver when offline** — evals never halt without a server.

## Architecture (non-obvious wiring)

- `src/bin/ethos.rs` is a thin entrypoint → `ethos::cli::run_cli()`.
- `src/aci/` typed tool harness (1-indexed `view_lines`, `edit_block`, untrusted-tagged `fetch`) + `state_tree.rs` (branching snapshot DAG).
- `src/runtime/` CoW snapshots + rewind; rollback refuses to delete unless a `.ethos_sandbox` marker file exists (`.taintbox_sandbox` legacy alias). gVisor (`runsc`) detection with local fallback.
- `src/taint/` bitmask provenance: `TRUSTED < INTERNAL < UNTRUSTED < HOSTILE`, worst-severity propagation, sensitive paths (`.env`, `id_rsa`).
- `src/walls/` containment: `PromptInjectScanner`, `OuroborosWall`, `HalluScan`, `EmergencyStop`.
- `src/config/` user config + `models.dev` live catalog (7-day TTL cache; provider/model specs are not hardcoded) + `policy.default.yaml` boundary rules (RULE-001 …). `config/runtime.yaml` holds sandbox runtime settings.
- `apps/desktop/` is a **separate Tauri v2 crate, not part of the root cargo build** (root `Cargo.toml` has no `[workspace]`). Its UI is static HTML/JS in `apps/desktop/ui` — no node/npm build; build from `apps/desktop/src-tauri` with the Tauri CLI. The daemon also serves this UI (embedded via `include_str!`): opencode-style chrome with sidebar menu + tabs (Dashboard / Sessions / Model Catalog / Attack Lab / Security), command palette (Ctrl+P), and a full models.dev catalog browser — all wired to the real `/v1/*` endpoints, no demo data. The TUI's `/models` opens the same catalog as a searchable overlay (zen.rs `draw_models_browser`).
- One UI, three surfaces: the daemon-served browser GUI (`ethos app`), the Tauri desktop app, and the MSI/NSIS installers all ship `apps/desktop/ui`. The Tauri shell (`src-tauri/src/main.rs`) probes `127.0.0.1:8000` and spawns `ethos daemon --port 8000` as a sidecar if nothing is listening (killed on window close); inside the webview, `app.js` detects the `tauri.localhost` origin and defaults its API base to `http://localhost:8000`. If you change daemon routes, all three surfaces are affected.

## Runtime invariants (enforced by tests — preserve when editing taint/walls/runtime)

1. All paths pass `resolve_path()` canonicalization; `../` traversal and symlink escapes return `BLOCKED_BY_POLICY`.
2. Destructive rewind verifies the `.ethos_sandbox` marker before touching files; the marker files themselves are Ouroboros-protected against tool-layer and exec-redirect forgery.
3. Shell-wrapper execs are inspected across **all** args (not just after `-c`/`-Command`/`/c`), case-folded, with stem-based program matching (`curl.exe` ≡ `curl`); `-EncodedCommand` is worst-case classified; `>`/`>>` redirect targets pass the same Ouroboros + sensitive-path walls as the write tool.
4. Content from `fetch()` is tagged untrusted; tainted data cannot trigger privileged actions without explicit policy authorization.
5. Provenance **merges, never downgrades**: an unsourced rewrite of a tainted file keeps the worst severity (`laundering_attempt_blocked` lands in telemetry) — only `declassify` with a valid token may clear it.
6. Both `exec` egress and `fetch()` egress are evaluated against the full tainted ledger: once untrusted data is in play, every network channel walls (allowlist can re-open specific destinations).
7. Path policy matching is case-folded everywhere (Ouroboros patterns, sensitive paths): `.ENV` ≡ `.env`, `Tests/` ≡ `tests/` — NTFS-insensitive casing must not bypass guards.
8. Scanner digests fed to the LLM (`PromptInjectScanner::summarize_findings`) carry pattern names only — never raw attacker excerpts (re-injection channel).
9. Every read-shaped tool (`read`, `view_lines`, `grep` per-file) passes the same sensitive-path gate; exec shell payloads referencing sensitive paths are blocked outright (`SENSITIVE-PATH-EXEC-GUARD`), including the ethos-owned credential stores (`~/.ethos/config.json`, `models_dev_cache.json`).
10. Network allowlist matches on parsed URL host (exact or dot-delimited subdomain) — never substring; the daemon binds loopback-only and masks API keys in all HTTP responses.

`tests/test_rust_redteam.rs` (RT-01 … RT-13) and `tests/test_rust_redteam2.rs` (RT-14 … RT-21, component-structured: harness, policy, daemon, session store) are the adversarial regression suites. A failure there means a wall regressed; flip assertions only when a fix intentionally changes behavior. Residual, documented risks: `runsc` detection is PATH-based (spoofable by host-level writers), WSL2 invocations pass through the login shell, and on platforms without gVisor the runtime is policy-only — exec is same-user host code.

## Benchmark evals (feed Paper 1)

```powershell
cargo run -- eval --dataset <injecagent|hackaprompt|agenthijack|synthetic|all> `
  --provider lmstudio --model deepseek-r1 --output reports/<name>_results.json
```

- Flags: `--split train|eval|test|all` (70/20/10 partition doctrine; `test` is the blind holdout), `--synthetic` (adds mutated evasion vectors).
- Datasets live in `data/injections/*.json`; outputs go to `reports/*.json`. Keep the report schema stable (`timestamp`, `provider`, `model`, `split`, `total_scenarios`, `defense_violations_blocked`, `results[]`) — downstream paper tooling reads it.
- Run each dataset in isolation for clean per-member telemetry; `--dataset all` is the intentional unified suite.
- Wrappers with interactive menus: `scripts/eval_bench.ps1` (Windows) and `scripts/eval_bench.sh`; both accept headless flags. Release packaging: `scripts/build_windows.ps1` / `build_macos.sh` / `build_linux.sh`.

## Repo conventions

- `.gitignore` blocks `*.md` (except `README.md`, `AGENTS.md`, `docs/*.md`), `*.txt`, `*.pdf`, `paper/`, and `scratch/` — "GitHub is code only". Put new docs in `docs/`.
- Main dev machine is Windows PowerShell 5.1 (one macOS); scripts ship as both `.ps1` and `.sh`. PowerShell 5.1 has no `&&` — use `; if ($?) { ... }` in commands.
- Branches: `main` (default) and `harsh-dev`; CI runs on pushes to both plus all PRs.
