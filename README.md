# Ethos: A Taint-Tracked Sandbox Runtime & Agent-Computer Interface

**Penn State University — DS 440 Capstone (Fall 2026)**  
**Instructor:** Dr. Robert Thomson (`rht5162@psu.edu`)  
**Repository:** [`xyzmr114/ds440-nittanystreet`](https://github.com/xyzmr114/ds440-nittanystreet) | **Dev Branch:** `harsh-dev`  
**Deliverables:** Production cross-platform desktop & CLI runtime, automated CI/CD release pipeline, and Empirical Research Paper 1.

---

## 1. Identity & Philosophy: Ethos

**Ethos** provides the **emotional intelligence, principled boundaries, and restraint that autonomous AI coding agents fundamentally lack**.

When frontier LLMs operate in unconstrained environments, they suffer from context burn, blindly execute indirect prompt injections, tamper with test suites, and exfiltrate secrets. An adversary injecting instructions into a third-party dependency, webpage, or git issue can hijack an autonomous coding agent to destroy the codebase or extract `.env` keys.

Ethos wraps autonomous agents in an ironclad Agent-Computer Interface (ACI) featuring:
- **Taint-Tracked I/O**: Mathematical bitmask provenance tracking where untrusted external data cannot trigger privileged tools without authorization.
- **Time-Travel Snapshot & Rewind**: Fast Copy-on-Write state checkpointing and causal DAG branching allowing Tree-of-Thought exploration and clean rollbacks on error.
- **Multi-Engine Isolation**: Native Google gVisor (`runsc`) user-space application-kernel sandbox on Linux/WSL2 with transparent `LocalIsolatedRuntime` CoW fallback.
- **Multi-Surface Interfaces**: Native Cyber Obsidian TUI (`ethos tui`), Tauri v2 cross-platform desktop app, and Axum REST API daemon on port 8000.

> **CLI Binary Note:** The primary binary is `ethos`, with `tbox` fully retained as a legacy and short typing alias (`cargo run --bin ethos -- ...` or `cargo run --bin tbox -- ...`).

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
│  - 100% of gVisor Application-Kernel Syscall Sandbox Integration           │
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
| **Harsh Rathi** | **Principal Engineer & Architect** | **100% of Software Engineering**: CLI runtime (`ethos` & `tbox`), TUI, Desktop GUI, REST API daemon, gVisor integration, Windows/macOS/Linux installers, GitHub Actions, Onboarding Wizard. Executes **InjecAgent** and **HackAPrompt** benchmarks. | **Active & Shipping** *(Not authoring Paper 1)* |
| **Aryamaan** | **Research Lead & Paper 1 Lead Author** | Paper 1 execution (*Evaluating Tool Ergonomics and Context Compression*). Experimental design, hypothesis validation, and **AgentHijack** benchmark evaluation. | **Paper 1 Lead** |
| **Ammar** | **Data & Literature Lead** | Literature review (SWE-agent, ExploitBench, gVisor), ingestion methodology, dataset documentation, and Paper 1 drafting. | **Paper 1 Co-Author** |
| **Akshat** | **Threat & Security Modeling** | Adversarial threat taxonomy (MITRE ATLAS, indirect injection), Condition D boundary defense evaluation, Paper 1 security section. | **Paper 1 Co-Author** |
| **Saathvik** | **Metrics & Empirical Analytics** | Telemetry data processing, token burn reduction curves, latency overhead tables, and final submission typesetting. | **Paper 1 Co-Author** |

---

## 4. Engineering Master Backlog & Execution Status

All engineering tasks belong strictly to **Harsh Rathi**.

### 4.1 Completed & Verified (Sprint 1 Production)
- [x] **Ethos Primary Binary (`src/bin/ethos.rs`)**: Standalone binary with `ethos` command line interface, retaining `tbox` as fully functional alias.
- [x] **Pure Rust ACI Harness (`src/aci/harness.rs`)**: 1-indexed `view_lines`, exact `edit_block`, pure-Rust `search_files`, `grep`, `fetch` with untrusted tagging, shell wrapper `-c` interceptor, and `fold_output` token compression.
- [x] **Snapshot & Rewind (`src/runtime/base.rs`)**: SHA-256 state hashing, CoW directory snapshotting, and safe destructive rollback guarded by `.taintbox_sandbox` marker.
- [x] **gVisor Syscall Isolation Runtime (`src/runtime/gvisor.rs`)**: Application-kernel user-space sandbox detection on Linux and WSL2 (`runsc`) with seamless `LocalIsolatedRuntime` fallback.
- [x] **Causal DAG State Tree (`src/aci/state_tree.rs`)**: Immutable branching history allowing Tree-of-Thought backtracking (`create_branch`, `switch_branch`, `commit`).
- [x] **Taint Provenance Engine (`src/taint/`)**: Bitmask severity tracking (`Trusted`, `Internal`, `Untrusted`, `Hostile`), worst-severity propagation, sensitive path protection (`.env`, `id_rsa`), and network egress allowlisting.
- [x] **Overkill Containment Walls (`src/walls/`)**: `PromptInjectScanner` (5 threat families), `OuroborosWall` (code immutability guard), `HalluScan` (VFS path validation), and `EmergencyStop` (high-severity circuit breaker).
- [x] **`models.dev` Dynamic Catalog (`src/config/models_dev.rs`)**: Live sync against 200+ providers and 7,600+ models with 7-day TTL caching, context window detection, and zero hardcoded specs.
- [x] **Cyber Obsidian Terminal TUI (`src/tui/zen.rs`)**: Ratatui 0.30 interface featuring floating slash command popup (`/`), `Ctrl+X` leader key mode, multi-line prompt editing, setup wizard, and cross-platform clipboard.
- [x] **Axum REST API Daemon (`src/api/routes.rs`)**: High-performance HTTP server on port 8000 exposing `/health`, `/v1/sandboxes`, `/v1/models`, `/v1/metrics`, and telemetry export.
- [x] **Tauri v2 Native Desktop Application (`apps/desktop/`)**: Native desktop GUI for Windows, macOS, and Linux with reactive context inspection and onboarding wizard.
- [x] **Three Injection Benchmark Datasets (`data/injections/`)**:
  - `injecagent_cases.json` (UIUC Kang Lab Indirect Injections)
  - `hackaprompt_cases.json` (Direct Jailbreaks & Evasions)
  - `agenthijack_cases.json` (UIUC Kang Lab Multi-Turn Hijacking)
- [x] **Automated Evaluation Runner (`ethos eval`)**: Dynamic dataset runner with `--provider`, `--model`, and `--output` flags generating structured research metrics.
- [x] **Turnkey Vibe-Coding Runbook (`AGENTS.md`)**: Fail-proof setup guide for Aryamaan's agent covering LM Studio, DeepSeek-R1, and local inference testing.
- [x] **Windows Packaging (`scripts/build_windows.ps1` & `.github/workflows/release-windows.yml`)**: WiX MSI installer, NSIS setup executable, standalone binary zip, and automated GitHub Actions release workflow.
- [x] **macOS Packaging (`scripts/build_macos.sh` & `.github/workflows/release-macos.yml`)**: Native DMG installer, `.app.tar.gz` bundle for Apple Silicon and Intel, native traffic lights, Cocoa menus, and GitHub Actions workflow.
- [x] **Linux Packaging (`scripts/build_linux.sh` & `.github/workflows/release-linux.yml`)**: Native `.deb` package, standalone `.AppImage`, x86_64 tarball, and automated GitHub Actions workflow.
- [x] **Test Verification**: **68 unit and integration tests across 17 test suites compile and pass with 0 warnings or failures.**

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

### 5.3 Codified Scope Cuts & Deprecations
To protect engineering velocity and ensure a publication-grade paper:
1. ❌ **Paper 2 as a separate paper is CUT**: Consolidated into Paper 1 as **Condition D**.
2. ❌ **SWE-bench Lite is replaced with Injection Datasets**: Evaluating boundary security across **InjecAgent**, **HackAPrompt**, and **AgentHijack**.
3. ❌ **Bare-Metal KVM MicroVMs (Firecracker / Hyper-V) are CUT**: Replaced with gVisor (`runsc`) on Linux/WSL2, Windows Sandbox on Windows, and `LocalIsolatedRuntime` on macOS.
4. ❌ **Sentry.io Cloud SaaS Tracing is CUT**: Local JSONL flight logs (`reports/flight_telemetry.jsonl`) capture all telemetry with zero external leakage.
5. ❌ **Multi-Modal Out-of-Scope Features (TTS Audio, Video Gen) are CUT**: Audio and video generation have no relevance to software engineering or taint research.

---

## 6. Architecture & Mandatory Security Invariants

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          OPERATOR INTERFACES                                │
│   ┌───────────────────────────────────┐ ┌───────────────────────────────┐   │
│   │   Ratatui Terminal TUI            │ │   Tauri v2 Desktop App        │   │
│   │   (Cyber Obsidian: ethos tui)     │ │   (Windows, macOS, Linux)     │   │
│   │   cargo run --bin ethos -- tui    │ │   apps/desktop/               │   │
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
│   - Google gVisor (runsc) User-Space Kernel Syscall Interception (Linux/WSL)│
│   - LocalIsolatedRuntime (Path canonicalization, Symlink traversal guards)  │
│   - Snapshot CoW Store with .taintbox_sandbox marker safety verification    │
│   - PostgreSQL 16 & In-Process Session State Manager                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Invariants Every Agent & Developer Must Obey:
1. **Path Canonicalization & Symlink Escape Guard**: All filesystem operations must resolve through `resolve_path()` and verify that the canonicalized path starts with the sandbox root directory. Traversal escapes (`../`) and symlink escapes return an immediate `BLOCKED_BY_POLICY`.
2. **Safe Destructive Rewind Marker**: `restore_snapshot()` must verify the presence of the `.taintbox_sandbox` marker file before touching or deleting files.
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
| **`/setup`** | Opens the interactive configuration wizard to select provider, model, API keys, and policy profile. |
| **`/clear`** | Clears the session feed and resets the greeting buffer. |

---

## 8. Multi-Platform Build & Quickstart

### Prerequisites
* **Rust**: MSRV 1.78+ (`rustup default stable`)
* **Cargo**
* *(Optional)* **Tauri CLI v2** (`cargo install tauri-cli --version "^2.0.0" --locked`)

### Build & Run Locally
```bash
# Clone and enter repo
git clone https://github.com/xyzmr114/ds440-nittanystreet.git
cd ds440-nittanystreet
git checkout harsh-dev

# Run all 68 unit & integration tests
cargo test

# Launch the Cyber Obsidian Terminal TUI
cargo run --bin ethos -- tui

# Launch the Axum REST API Daemon (Port 8000)
cargo run --bin ethos -- daemon --port 8000

# Run System Diagnostic Doctor
cargo run --bin ethos -- doctor
```

### Running Benchmark Evaluation Suites

```bash
# 1. Aryamaan: Run AgentHijack against local LM Studio DeepSeek-R1
cargo run --bin ethos -- eval --dataset agenthijack --provider lmstudio --model deepseek-r1 --output reports/agenthijack_results.json

# 2. Harsh: Run InjecAgent benchmark
cargo run --bin ethos -- eval --dataset injecagent --output reports/injecagent_results.json

# 3. Harsh: Run HackAPrompt benchmark
cargo run --bin ethos -- eval --dataset hackaprompt --output reports/hackaprompt_results.json

# 4. Evaluate all 3 datasets simultaneously
cargo run --bin ethos -- eval --dataset all
```

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
- [**`release-windows.yml`**](.github/workflows/release-windows.yml): Compiles `ethos.exe` & `tbox.exe`, builds WiX MSI and NSIS installers, and uploads release assets.
- [**`release-macos.yml`**](.github/workflows/release-macos.yml): Compiles universal CLI, builds `.dmg` and `.app.tar.gz`, and generates SHA256 checksums.
- [**`release-linux.yml`**](.github/workflows/release-linux.yml): Compiles Linux binary, builds `.deb` and `.AppImage`, and creates GitHub Release entries.
- [**`ci.yml`**](.github/workflows/ci.yml): Enforces `cargo test --all-targets` and formatting checks on all pull requests.

---

## 10. License

Public domain under [The Unlicense](LICENSE).
