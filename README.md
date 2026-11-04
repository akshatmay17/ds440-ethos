# Ethos: A Taint-Tracked Sandbox Runtime & Agent-Computer Interface

> **Security status (October 15, 2026):** command execution defaults to disabled.
> The configured Docker backend runs disposable, non-root, network-disabled
> commands with no host fallback; see [setup and live boundary tests](docs/container-execution.md).
> The application rejects unconfined host execution. gVisor availability alone is not proof of active confinement.
> Semantic scoring is advisory, and 44/44 describes historical classifier
> detections rather than full-agent attack prevention. See the
> [measured evaluation and limitations](docs/security-evaluation.md) before
> interpreting the earlier architectural and release summaries below.

**Corpus audit:** the third named dataset is **HackAPrompt**. Official
InjecAgent provides 1,054 base cases plus 1,054 enhanced variants locally.
The 2,108-case live campaign recorded **92 runtime intercepts**, 2,003 goals
not observed and 13 inconclusive trials; it does not establish 2,108 stopped
attacks. The correct [AgentHijack](https://github.com/tmlr-group/AgentHijack)
contains desktop corruption tasks, requiring a separate VM evaluation.
HackAPrompt's full parquet currently requires authorized access. See
[corpus inventory, results and reproduction commands](docs/attack-campaign.md).
For individual threats and untested areas, see the
[attack-surface coverage audit](docs/attack-surface-coverage.md).
The [secret-boundary follow-up](docs/secret-boundary-review.md) documents a
reproduced hard-link read/write bypass, its fix and obfuscated-read tests.

**Penn State University — DS 440 Capstone (Fall 2026)**  
**Instructor:** Dr. Robert Thomson (Penn State University)  
**Repository:** [`xyzmr114/ds440-ethos`](https://github.com/xyzmr114/ds440-ethos) | **Branch:** `main`
**Deliverables:** Production cross-platform desktop & CLI runtime, automated CI/CD release pipeline, and Empirical Research Paper 1.

---

## 1. Identity & Philosophy: Ethos

**Ethos** provides the **emotional intelligence, principled boundaries, and restraint that autonomous AI coding agents fundamentally lack**.

When frontier LLMs operate in unconstrained environments, they suffer from context burn, blindly execute indirect prompt injections, tamper with test suites, and exfiltrate secrets. An adversary injecting instructions into a third-party dependency, webpage, or git issue can hijack an autonomous coding agent to destroy the codebase or extract `.env` keys.

Ethos wraps autonomous agents in an ironclad Agent-Computer Interface (ACI) featuring:
- **Taint-Tracked I/O**: Mathematical bitmask provenance tracking where untrusted external data cannot trigger privileged tools without authorization.
- **Time-Travel Snapshot & Rewind**: Fast Copy-on-Write state checkpointing and causal DAG branching allowing Tree-of-Thought exploration and clean rollbacks on error.
- **Command Isolation**: Optional disposable Linux Docker containers with pinned images, no network, resource limits and filtered workspace copies. Missing confinement never falls back to a host command; execution is disabled until configured.
- **Multi-Surface Interfaces**: Native Cyber Obsidian TUI (`ethos tui`), Tauri v2 cross-platform desktop app, and Axum REST API daemon on port 8000.

> **CLI Binary Note:** The sole binary is `ethos` (`Cargo.toml` sets `default-run = "ethos"`, so `cargo run -- ...` works with no `--bin`). There is **no `tbox` binary** — older docs that mention one are stale.

---

## 2. Executive Summary & Heilmeier Catechism

### 2.1 The Problem
The **Agent-Computer Interface (ACI)** is the single largest capability lever in autonomous AI. The same frontier model executing on a raw bash shell fails repeatedly on context burns and syntax drift, while on a purpose-built execution harness (SWE-agent, ExploitBench) it achieves state-of-the-art software engineering velocity. 

Simultaneously, agent deployments carry an unresolved vulnerability: **untrusted content** (scraped HTML, emails, tool outputs) enters the LLM's context window without provenance. Indirect prompt injection converts privileged agent tools into an adversary's execution vector. Standard isolation sandboxes (E2B, Daytona) only protect the host operating system from malicious code—they do nothing when an agent is tricked into reading `.env` and sending it to an attacker via legitimate API tools.

### 2.2 The Solution: Three Primitives
Ethos delivers an instrumented runtime with three core primitives:

1. **Snapshot & Rewind (Time-Travel Execution)**: Git-like state branching enabling agents to run, observe, branch (Tree-of-Thought), and instantaneously rewind to clean filesystem states on error without burning context on shell navigation.
2. **Taint-Tracked I/O**: Byte- and object-level provenance tracking. Untrusted data carries custody metadata throughout reads, transformations, and memory. Policy rules enforce boundary safety: tainted data cannot trigger privileged actions (network egress, shell exec, file deletion, secret extraction).
3. **Telemetry by Construction**: Every execution trace automatically generates structured audit streams, yielding empirical datasets for academic research and regulatory compliance.

---

## 3. Team Roles & Strict Division of Labor

The project scope has been sharpened to maximize engineering quality and academic rigor. **All software engineering, packaging, and infrastructure is consolidated under Harsh Rathi, while academic paper authorship is handled by the rest of the team.**

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HARSH RATHI (Engineering Lead)                     │
│  - 100% of Runtime Architecture, Axum REST Daemon & Session Store          │
│  - 100% of Terminal TUI (Cyber Obsidian Zen Engine) & Slash Commands        │
│  - 100% of Desktop GUI (Tauri v2 Native Shell for Windows, macOS, Linux)   │
│  - 100% of Cross-Platform Packaging (MSI, NSIS Setup, DMG, .app, Deb, AppImage)│
│  - 100% of CI/CD Release Automation (GitHub Actions workflows)              │
│  - Disposable Docker commands; optional gVisor remains unverified         │
│  - Co-Leads Benchmark Testing; Executes InjecAgent & HackAPrompt Datasets   │
│  - ZERO academic paper writing duties (100% freed for engineering velocity) │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Empirical Benchmark Runs & Telemetry
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       RESEARCH PAPER 1 AUTHORSHIP TEAM                      │
│                                                                             │
│  ┌───────────────────────────────┐   ┌───────────────────────────────────┐  │
│  │ ARYAMAAN                      │   │ AMMAR                             │  │
│  │ - Lead Author on Paper 1      │   │ - Co-Author on Paper 1            │  │
│  │ - Benchmark Lead: AgentHijack │   │ - Literature Review & Related Work│  │
│  │   Dataset (with LM Studio)    │   │ - Ingestion Pipeline Analysis     │  │
│  └───────────────────────────────┘   └───────────────────────────────────┘  │
│  ┌───────────────────────────────┐   ┌───────────────────────────────────┐  │
│  │ AKSHAT                        │   │ SAATHVIK                          │  │
│  │ - Co-Author on Paper 1        │   │ - Co-Author on Paper 1            │  │
│  │ - Threat Modeling & Attacks   │   │ - Latency & Token Burn Metrics    │  │
│  │ - Condition D Defense Analysis│   │ - Camera-Ready Figures & Layout   │  │
│  └───────────────────────────────┘   └───────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Member Responsibility Matrix

| Member | Primary Domain | Core Deliverables | Active Work |
| :--- | :--- | :--- | :--- |
| **Harsh Rathi** | **Principal Engineer & Architect** | **100% of Software Engineering**: CLI runtime (`ethos`), TUI, Desktop GUI, REST API daemon, gVisor integration, Windows/macOS/Linux installers, GitHub Actions, Onboarding Wizard. Executes **InjecAgent** and **HackAPrompt** benchmarks. | **Active & Shipping** *(Not authoring Paper 1)* |
| **Aryamaan** | **Research Lead & Paper 1 Lead Author** | Paper 1 execution (*Evaluating Tool Ergonomics and Context Compression*). Experimental design, hypothesis validation, and **AgentHijack** benchmark evaluation. | **Paper 1 Lead** |
| **Ammar** | **Data & Literature Lead** | Literature review (SWE-agent, ExploitBench, gVisor), ingestion methodology, dataset documentation, and Paper 1 drafting. | **Paper 1 Co-Author** |
| **Akshat** | **Threat & Security Modeling** | Adversarial threat taxonomy (MITRE ATLAS, indirect injection), Condition D boundary defense evaluation, Paper 1 security section. | **Paper 1 Co-Author** |
| **Saathvik** | **Metrics & Empirical Analytics** | Telemetry data processing, token burn reduction curves, latency overhead tables, and final submission typesetting. | **Paper 1 Co-Author** |

---

## 4. Engineering Master Backlog & Execution Status

All engineering tasks belong strictly to **Harsh Rathi**.

### 4.1 Completed & Verified (Sprint 1 Production)
- [x] **Ethos Primary Binary (`src/bin/ethos.rs`)**: Standalone binary with the `ethos` command-line interface (`default-run = "ethos"`; no `tbox` binary exists).
- [x] **Pure Rust ACI Harness (`src/aci/harness.rs`)**: 1-indexed `view_lines`, exact `edit_block`, pure-Rust `search_files`, `grep`, `fetch` with untrusted tagging, shell wrapper `-c` interceptor, and `fold_output` token compression.
- [x] **Snapshot & Rewind (`src/runtime/base.rs`)**: SHA-256 state hashing, CoW directory snapshotting, and safe destructive rollback guarded by `.ethos_sandbox` marker (with `.taintbox_sandbox` legacy compatibility).
- [x] **Disposable Command Runtime (`src/runtime/container.rs`)**: Configured application execution uses a non-root Docker boundary with no host fallback. Legacy `runsc` probing remains separate; it does not establish active confinement.
- [x] **Causal DAG State Tree (`src/aci/state_tree.rs`)**: Immutable branching history allowing Tree-of-Thought backtracking (`create_branch`, `switch_branch`, `commit`).
- [x] **Taint Provenance Engine (`src/taint/`)**: Bitmask severity tracking (`Trusted`, `Internal`, `Untrusted`, `Hostile`), worst-severity propagation, sensitive path protection (`.env`, `id_rsa`), and network egress allowlisting.
- [x] **Overkill Containment Walls (`src/walls/`)**: `PromptInjectScanner` (5 threat families), `OuroborosWall` (code immutability guard), `HalluScan` (VFS path validation), and `EmergencyStop` (high-severity circuit breaker).
- [x] **`models.dev` Dynamic Catalog (`src/config/models_dev.rs`)**: Live sync against 200+ providers and 7,600+ models with 7-day TTL caching, context window detection, and zero hardcoded specs.
- [x] **Cyber Obsidian Terminal TUI (`src/tui/zen.rs`)**: Ratatui 0.30 interface featuring floating slash command popup (`/`), `Ctrl+X` leader key mode, multi-line prompt editing, setup wizard, and cross-platform clipboard.
- [x] **Axum REST API Daemon (`src/api/routes.rs`)**: High-performance HTTP server on port 8000 exposing `/health`, `/v1/sandboxes`, `/v1/models`, `/v1/metrics`, and telemetry export.
- [x] **Tauri v2 Native Desktop Application (`apps/desktop/`)**: Native desktop GUI for Windows, macOS, and Linux with reactive context inspection and onboarding wizard.
- [x] **Evaluation scenario corpus (`data/`)**: local injection families (`injecagent`, `hackaprompt`, `agenthijack`, `m365`, `evasion`, `modern`), false-positive **benign controls** (`data/benign/`), clean **capability** tasks and their injected twins (`data/capability/`), per-channel `fetch`/`tool_output` cases (`data/channels/`), and importer output for the full upstream InjecAgent set (`data/imported/`, gitignored). Each attack case carries a machine-checkable `oracle`; the schema is in [`docs/eval-scenario-schema.md`](docs/eval-scenario-schema.md) and `scripts/validate_scenarios.py` enforces it.
- [x] **v2 Evaluation Runner (`ethos eval`)**: fail-closed provider selection (`lmstudio`/`ollama`/`openai`/`openrouter`/`anthropic`, plus an explicit labelled `scripted` smoke driver), condition switches (`--condition full|rewind|structured|raw-shell`), task framings (`--variant benign|complicit|both`), repeats/sampling for confidence intervals, and a report that records the real driver and served model. `ethos scanner-eval` separately scores the enforcing PromptInjectScanner as precision/recall/F1.
- [x] **Turnkey Vibe-Coding Runbook (`AGENTS.md`)**: Fail-proof setup guide for Aryamaan's agent covering LM Studio, DeepSeek-R1, and local inference testing.
- [x] **Windows Packaging (`scripts/build_windows.ps1` & `.github/workflows/release-windows.yml`)**: WiX MSI installer, NSIS setup executable, standalone binary zip, and automated GitHub Actions release workflow.
- [x] **macOS Packaging (`scripts/build_macos.sh` & `.github/workflows/release-macos.yml`)**: Native DMG installer, `.app.tar.gz` bundle for Apple Silicon and Intel, native traffic lights, Cocoa menus, and GitHub Actions workflow.
- [x] **Linux Packaging (`scripts/build_linux.sh` & `.github/workflows/release-linux.yml`)**: Native `.deb` package, standalone `.AppImage`, x86_64 tarball, and automated GitHub Actions workflow.
- [x] **Test Verification**: **177 unit and integration tests across 29 test suites compile and pass with 0 warnings or failures.**

---

## 5. Research Program: Paper 1 (ACI Capability & Provenance Defense)

### 5.1 Title & Scope
* **Paper Title**: *Evaluating Tool Ergonomics, State Rollback, and Provenance Guardrails in Autonomous AI Software Engineering*
* **Core Hypothesis**: Purpose-built ACI tools with snapshot/rewind improve benchmark solve rates by `> 30%` while slashing token burn by `> 40%` compared to unstructured raw bash shells; boundary taint policies eliminate action-on-objectives prompt injection attacks without degrading task utility.

### 5.2 Four Evaluation Conditions (Holding Model Constant)

| Condition | Interface Harness | Observation Channel | State Management | Boundary Taint Policy |
| :---: | :--- | :--- | :--- | :--- |
| **A** | Raw Unstructured Shell | Raw stdout/stderr | None (terminal burn) | None |
| **B** | Structured Typed Tools | Folded Windowed Diff | None (linear history) | None |
| **C** | Structured Typed Tools | Folded Windowed Diff | **Snapshot & Rewind (`/rewind`)** | None |
| **D** | **Full Ethos ACI** | Folded Windowed Diff + Provenance | **Snapshot & Rewind** | **Taint Boundary Enforced** |

All four conditions are **implemented** in the v2 runner as `--condition raw-shell|structured|rewind|full` (A→D): `full` enforces every wall, while the others run the walls in shadow mode (decisions recorded, denied file ops let through and commands/network simulated) so the comparison can be measured on the same scenarios. A paired **McNemar** test across two conditions is available via `python scripts/make_tables.py --mcnemar full raw-shell ...`.

### 5.3 Codified Scope Cuts & Deprecations
To protect engineering velocity and ensure a publication-grade paper:
1. ❌ **Paper 2 as a separate paper is CUT**: Consolidated into Paper 1 as **Condition D**.
2. ❌ **SWE-bench Lite is replaced with Injection Datasets**: Evaluating boundary security across **InjecAgent**, **HackAPrompt**, **AgentHijack**, and **Synthetic Evasion**.
3. **Current execution scope**: Disposable Linux Docker commands, including Docker Desktop's Linux engine on Windows/macOS. Firecracker, native Windows Sandbox and platform-specific VM adapters are not wired into application execution.
4. ❌ **Sentry.io Cloud SaaS Tracing is CUT**: Local JSONL flight logs (`reports/flight_telemetry.jsonl`) capture all telemetry with zero external leakage.
5. ❌ **Multi-Modal Out-of-Scope Features (TTS Audio, Video Gen) are CUT**: Audio and video generation have no relevance to software engineering or taint research.

### 5.4 Evaluation status & why the earlier cross-model table was withdrawn

An earlier revision of this section published an 8-model matrix reporting
"100% BLOCKED" interception across every model and reasoning mode. **Those
numbers have been withdrawn and must not be cited.** A re-examination of the
stored reports (and the `paper/` critique) found that:

- the early report schema recorded **no field for which inference driver ran
  or which model was actually loaded**, and the runner silently fell back to a
  scripted rule-based driver when the local inference server was offline — so
  a run that never reached a model was scored as a success and counted as
  "protection";
- "interception" counted any tool-level policy block, which is a measure of
  **enforcement activity, not attacker-objective prevention**; and
- several of the single-rig ablation reports under `reports/ablation_*.json`
  carry no driver/model/runtime metadata at all.

The evaluation harness was rebuilt (**v2**, `src/aci/eval.rs`) to make results
defensible: it is fail-closed (a requested live provider that is unreachable
errors instead of falling back), it records the driver, endpoint and the model
the server actually served, and it scores attacker success with a
**machine-checkable oracle per case** (egress to the attacker host, `.env`
canary leak, protected-file modification, …) separated from a benign
false-positive rate and a task-utility measure. See
[`docs/eval-scenario-schema.md`](docs/eval-scenario-schema.md) for the contract
and [`docs/security-evaluation.md`](docs/security-evaluation.md) for the
measured results and limits.

**What can be stated:** the taint/egress policy is a deterministic property of
the runtime — once untrusted data is in the ledger, every network channel is
walled unless an allowlist re-opens it — and the red-team regression suites
(`tests/test_rust_redteam*.rs`) hold that boundary. What the current reports do
**not** establish is an attack-prevention rate across models; that requires
live-model runs through the v2 harness, which are produced with:

```bash
cargo run -- eval --dataset attacks --provider lmstudio --model deepseek-r1 \
  --condition full --variant both --repeats 3 --output reports/attacks_v2.json
python scripts/make_tables.py reports/*_v2_results.json        # Wilson-CI tables
```

---

## 6. Architecture & Mandatory Security Invariants

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          OPERATOR INTERFACES                                │
│   ┌───────────────────────────────────┐ ┌───────────────────────────────┐   │
│   │   Ratatui Terminal TUI            │ │   Tauri v2 Desktop App        │   │
│   │   (Cyber Obsidian: ethos tui)     │ │   (Windows, macOS, Linux)     │   │
│   │   cargo run -- tui    │ │   apps/desktop/               │   │
│   └─────────────────┬─────────────────┘ └───────────────┬───────────────┘   │
└─────────────────────┼───────────────────────────────────┼───────────────────┘
                      │                                   │
                      ▼                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          AXUM API DAEMON (Port 8000)                        │
│   - REST Endpoints (/health, /v1/sandboxes, /v1/metrics, /v1/models)        │
│   - Telemetry Event Ring Buffer & Provenance Graph Export                   │
│   - Provider Manager (LM Studio, Ollama, DeepSeek, models.dev Dynamic Sync) │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│   ACI HARNESS    │        │   TAINT ENGINE   │        │ CONTAINMENT WALLS│
│ (src/aci/)       │        │ (src/taint/)     │        │ (src/walls/)     │
│ - view_lines     │        │ - Provenance DAG │        │ - PromptInject   │
│ - edit_block     │◄──────►│ - Policy Profiles│◄──────►│ - Ouroboros      │
│ - State Tree DAG │        │ - Sensitive Paths│        │ - HalluScan      │
│ - AgentLoop      │        │ - Egress Filter  │        │ - Emergency Stop │
└────────┬─────────┘        └──────────────────┘        └──────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     SANDBOX RUNTIME & PERSISTENCE                           │
│   - Disposable Linux Docker commands; no automatic host fallback         │
│   - LocalIsolatedRuntime (Path canonicalization, Symlink traversal guards)  │
│   - Snapshot CoW Store with .ethos_sandbox marker safety verification       │
│   - PostgreSQL 16 & In-Process Session State Manager                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Invariants Every Agent & Developer Must Obey:
1. **Path Canonicalization & Symlink Escape Guard**: All filesystem operations must resolve through `resolve_path()` and verify that the canonicalized path starts with the sandbox root directory. Traversal escapes (`../`) and symlink escapes return an immediate `BLOCKED_BY_POLICY`.
2. **Safe Destructive Rewind Marker**: `restore_snapshot()` must verify the presence of the `.ethos_sandbox` (or `.taintbox_sandbox`) marker file before touching or deleting files.
3. **Shell Wrapper Mapping**: Any invocation of shell interpreters (`bash`, `sh`, `cmd`, `powershell`) must be mapped to `exec_privileged` with `-c` command argument inspection.
4. **Untrusted Egress Quarantine**: Downloads via `fetch()` are permanently labeled `UntrustedWeb`. Tainted data cannot be passed into network egress commands (`curl`, `wget`) without explicit allowlisting.
5. **Ouroboros Test Protection**: Any attempt to edit or delete test suites triggers `OuroborosWall` and is blocked immediately.

---

## 7. Production Slash Commands Reference

All commands can be invoked from the bottom dock or via the Command Palette (`Ctrl+P`):

| Command | Action & Architectural Effect |
| :--- | :--- |
| **`/init`** | Indexes workspace, computes SHA-256 baselines, validates `AGENTS.md`, and flags pre-existing injections. |
| **`/models`** | Queries `models.dev` dynamic catalog specifications (context windows, pricing, tool formats). |
| **`/models <id>`** | Hot-swaps the active inference model with **zero context loss**. |
| **`/diff`** | Computes character-exact line additions (`+`) and deletions (`-`) with surfaced taint provenance. |
| **`/attack [id]`** | Stages authentic adversarial scenarios from `data/injections/m365_indirect_attacks.json`. |
| **`/walls`** | Inspects active containment walls (PromptInjectScanner, Ouroboros, E-Stop, Network Gate). |
| **`/taint`** | Dumps the active bitmask provenance ledger and untrusted custody chains. |
| **`/rewind`** | Rolls back sandbox filesystem and taint state to the last clean snapshot. |
| **`/undo`** | Reverts the files changed by the last agent turn (per-turn snapshot). |
| **`/steps <n>`** | Shows or sets the per-turn step budget (default 25). |
| **`/new`** | Starts a fresh conversation, keeping the workspace and undo history. |
| **`/connect`** | Connects any models.dev provider (Ollama, LM Studio, OpenAI, Anthropic, OpenRouter, …). |
| **`/setup`** | Opens the interactive configuration wizard to select provider, model, API keys, and policy profile. |
| **`/clear`** | Clears the session feed (the conversation is kept). |
| **`/help`**, **`/exit`** | Command reference; quit. |

Each typed task runs the real multi-step agent loop in the background: tool
calls, command output, file diffs and policy blocks stream into the feed live,
**Esc** cancels after the current step, and **Tab** cycles the mode — `Build`
(may edit files) vs. read-only `Plan` / `Review` / `Audit`. `/attack [id]`
stages an adversarial scenario from the injection corpus so the walls can be
watched firing.

---

## 8. Multi-Platform Build & Quickstart

### Prerequisites
* **Rust**: MSRV 1.78+ (`rustup default stable`)
* **Cargo**
* *(Optional)* **Tauri CLI v2** (`cargo install tauri-cli --version "^2.0.0" --locked`)

### Build & Run Locally
```bash
# Clone and enter repo
git clone https://github.com/xyzmr114/ds440-ethos.git
cd ds440-ethos
git checkout main

# Run all 177 unit & integration tests (29 suites)
cargo test

# Launch the Cyber Obsidian Terminal TUI
cargo run --bin ethos -- tui

# Launch the Axum REST API Daemon (Port 8000)
cargo run -- daemon --port 8000

# Run System Diagnostic Doctor
cargo run -- doctor
```

### Running Benchmark Evaluation Suites

```bash
# Live run against a local model (fails loudly if the server is offline):
cargo run -- eval --dataset attacks --provider lmstudio --model deepseek-r1 \
  --condition full --variant both --repeats 3 --output reports/attacks_v2.json

# One injection family, a hosted provider, benign + complicit framings:
cargo run -- eval --dataset injecagent --provider anthropic --model claude-opus-5-5 \
  --variant both --output reports/injecagent_v2.json

# Everything (attacks + benign controls + capability) in one suite:
cargo run -- eval --dataset all --provider lmstudio --model deepseek-r1 --output reports/all_v2.json

# No model handy? An explicit, labelled smoke run (never cited as a result):
cargo run -- eval --dataset attacks --provider scripted --output reports/smoke.json

# Score the enforcing injection scanner on a labelled corpus:
cargo run -- scanner-eval --semantic

# Build Wilson-CI paper tables from v2 reports:
python scripts/make_tables.py reports/*_v2_results.json
```

Datasets: `injecagent` `hackaprompt` `agenthijack` `m365` `evasion` `modern`
`benign` `capability` `injected` `fetch` `tool_output` `injecagent-upstream`
`attacks` (all five local attack families) `all`. See
[`docs/eval-scenario-schema.md`](docs/eval-scenario-schema.md).

### Packaging Production Installers

#### Windows (WiX MSI + NSIS Setup + Portable CLI)
```powershell
.\scripts\build_windows.ps1
# Artifacts staged in: dist\windows\ (*.msi, *-setup.exe, ethos-windows-x64-cli.zip, SHA256SUMS.txt)
```

#### macOS (Apple Silicon & Intel DMG + .app)
```bash
chmod +x ./scripts/build_macos.sh
./scripts/build_macos.sh
# Artifacts staged in: dist/macos/ (*.dmg, *.app.tar.gz, SHA256SUMS.txt)
```

#### Linux (Debian Package + AppImage + Portable Tarball)
```bash
chmod +x ./scripts/build_linux.sh
./scripts/build_linux.sh
# Artifacts staged in: dist/linux/ (*.deb, *.AppImage, *.tar.gz, SHA256SUMS.txt)
```

---

## 9. Automated CI/CD Release Matrix

Pushes with tags matching `v*` (or manual triggers via GitHub Actions `workflow_dispatch`) automatically execute:
- [**`release-windows.yml`**](.github/workflows/release-windows.yml): Compiles `ethos.exe`, builds WiX MSI and NSIS installers, and uploads release assets.
- [**`release-macos.yml`**](.github/workflows/release-macos.yml): Compiles universal CLI, builds `.dmg` and `.app.tar.gz`, and generates SHA256 checksums.
- [**`release-linux.yml`**](.github/workflows/release-linux.yml): Compiles Linux binary, builds `.deb` and `.AppImage`, and creates GitHub Release entries.
- [**`ci.yml`**](.github/workflows/ci.yml): On every push/PR, runs `cargo check --all-targets`, `cargo test`, the security-eval unit tests, `scripts/validate_scenarios.py`, a no-network scripted eval smoke, and the Ethos prompt-injection self-scan (SARIF).

---

## 10. Technology Stack, Prior Art & Inspirations

The maintained [references and acknowledgments](docs/references.md) distinguish
dependencies, UI/code references (including OpenCode/OpenTUI), model candidates,
and dataset inspirations. See [security evaluation and TA answers](docs/security-evaluation.md)
for reproducible corpus sampling, current measurements, method tradeoffs and limits.
Optional [Lockit integration](docs/lockit-integration.md) supplies admitted
credentials through an operator-run launcher; it does not provide OS isolation.

Ethos stands on well-vetted infrastructure and borrows proven interaction
design. Crediting the load-bearing pieces:

### Core Runtime Stack (Rust 2021)
- **[`tokio`](https://tokio.rs)** — async runtime powering the daemon, agent loop, and eval drivers.
- **[`axum`](https://github.com/tokio-rs/axum)** — REST daemon (`/v1/*` API) with loopback-only binding.
- **[`ratatui`](https://ratatui.rs) + [`crossterm`](https://github.com/crossterm-rs/crossterm)** — the Cyber Obsidian Zen TUI (`ethos tui`): tabs, slash-command popups, and the models.dev catalog browser overlay.
- **[`sqlx`](https://github.com/launchbadge/sqlx)** — optional persistent session store (parameterized Postgres, schema in `migrations/`).
- **[`reqwest`](https://github.com/seanmonstar/reqwest)** — LLM provider + `fetch()` HTTP channel (content taint-tagged on ingest).
- **[`clap`](https://docs.rs/clap)**, **[`serde`](https://serde.rs)**, **[`uuid`](https://github.com/uuid-rs/uuid)**, **[`sha2`](https://github.com/RustCrypto/hashes) — CLI parsing, schemas, snapshot hashing.
- **[`tempfile`](https://github.com/Stebalien/tempfile)** — isolated sandbox workspaces.

### Sandboxing & Isolation
- **[Docker](https://docs.docker.com/engine/security/)** — the disposable command backend uses the local Linux engine, a pinned image and an ephemeral filtered workspace. See [confinement and limits](docs/container-execution.md). **[`gVisor`](https://gvisor.dev)** remains an optional separately configured Docker OCI runtime and legacy availability probe; finding `runsc` does not establish active gVisor confinement.

### Model Catalog
- **[models.dev](https://models.dev)** — live provider/model catalog (228+ providers, 8,300+ models), 7-day TTL cache; Ethos hardcodes no provider specs.

### Desktop & Distribution
- **[`Tauri v2`](https://tauri.app)** — native desktop shell; spawns the daemon as a sidecar and serves the shared web UI.
- **WiX MSI + NSIS** installers (Windows), `.dmg`/`.app` bundles (macOS), `.deb` + **AppImage** (Linux), built by the `v*`-tag release workflows.

### Agent UX & Interaction Design
- **[opencode](https://opencode.ai)** — the browser/TUI chrome Ethos's dashboard and Zen TUI borrow from: sidebar + tab layout, command palette (Ctrl+P), and the searchable per-provider model picker with favorites/recents.

### Semantic Safety Wall ("System 1" classifier slots)
`SemanticGuard` (`src/walls/semantic.rs`) is wired into the harness: every
write/exec/fetch is semantically scanned (`SEMANTIC_SCAN` telemetry) and the
agent loop annotates high-risk tool arguments with LLM-safe digests. The
`EmergencyStop` circuit breaker is active — three attack-class policy blocks
(secret access, wall tampering, escape attempts) wall every tool until an
operator reset (`POST /v1/sandboxes/:id/estop/reset`).

**Neural tier (shipped, opt-in).** Build with `--features semantic-ml` to add
pure-Rust transformer inference (`candle` + `tokenizers`); enable with
`ETHOS_SEMANTIC_NEURAL=1`. Weights load from `~/.ethos/models/<repo>/`
(downloaded on demand for catalog models; drop-in for local checkpoints).
Without the flag/env the wall uses the deterministic marker-density scorer as
a guaranteed fallback.

**Ethos-owned models (fine-tuned on the RTX 3060, three-tier acceptance):**

| Model | Backbone | Size | Frozen acceptance test |
| :--- | :--- | :--- | :--- |
| `ethos-guard-bert-base` | BERT-base (110M) | 418MB | **44/44 attacks (100% recall), 0/19 hard-negative FPs**; overall test 99.4% recall @ 0.6% FPR |
| `ethos-guard-laya` ("System 1" fast tier) | BERT-small (28M) | 110MB | 42/44 attacks (95.5%), 0/19 FPs; overall 96.3% @ 0.8% FPR |
| `meta-llama/Prompt-Guard-86M` | DeBERTa-v2 (gated) | — | ⏳ needs DeBERTa candle support |
| `protectai/deberta-v3-base-prompt-injection-v2` | DeBERTa-v3 | — | ⏳ same DeBERTa requirement |

**Interpretation:** 44/44 is classifier recall on 44 local historical attack
texts, not Rust test count or end-to-end attack prevention. `ethos-guard-laya`
is our BERT-small checkpoint nickname, not upstream Laya weights. In the new
13-attack development challenge both local classifiers flag 10/13; benign
false alarms are 2/6 for BERT-base and 3/6 for the compact model. Reproduce and
inspect per-case evidence in `reports/security_eval_all.json`.

The in-repo attack corpus (InjecAgent / HackAPrompt / locally named AgentHijack /
M365 / synthetic evasions) is a **historical acceptance regression set**. The
builder pins the raw attack records to the test split, but the training tools
generate corpus-derived paraphrases and acceptance-informed augmentations;
this does not establish a blind holdout. Use fresh, family-separated data for
final evaluation. The training corpus
mixes public corpora, LM Studio-generated paraphrases/framed attacks, and
repo docs/code as hard negatives (~13k records; `docs/semantic-guard-finetune-plan.md`).

**Training & verification pipeline** (all in `scripts/`):
`prepare_semantic_dataset.py` (dedup/split/manifest) →
`generate_semantic_data_lmstudio.py` + `augment_semantic_dataset.py` (domain
augmentation) → `train_semantic_guard.py` (3-class head, threshold
calibration) → `calibrate_semantic_guard.py` (FPR-budgeted operating point) →
`diagnose_semantic_guard.py` (miss analysis) → `parity_export.py` + the
ignored Rust test (`test_neural_parity_with_python`) prove **Rust↔Python
score parity ≤ 0.02** — the check that catches loader drift.

### Evaluation Datasets & Local Inference
- **[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)** and **[HackAPrompt](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset)** are references for locally adapted `data/injections/` cases. The correct **[AgentHijack](https://github.com/tmlr-group/AgentHijack)** is a desktop corruption benchmark; its mapping to the ten local text scenarios remains unverified. See [references](docs/references.md) and the [verified corpus inventory](docs/attack-campaign.md). Do not present the local 44-case collection as complete official benchmark coverage.
- **[LM Studio](https://lmstudio.ai)** (ports 1234/2277) and **[Ollama](https://ollama.com)** (port 11434) — local inference for live evals, with a deterministic offline driver fallback.
- **[Spider Cloud](https://spider.cloud)** — optional crawl/fetch backend for web ingestion.

---

The [public MCP lab](docs/mcp-public-evaluation.md) exercises the official
shadcn server, adversarial registry content, outside-project dummy reads and
a restricted Docker launch. Its policy replays are separate from live-agent
attack results; production MCP integration remains unfinished.

## 11. License

Public domain under [The Unlicense](LICENSE).
