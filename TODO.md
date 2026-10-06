# Ethos: Master Team Backlog, Roadmap & Sprint Assignments

**Sprint Cycle:** Sprint 1 Complete | Sprint 2 Active (Empirical Benchmarks & Paper 1 Integration)  
**Capstone Group:** (2) Nittany Street — Penn State DS 440 (Fall 2026)  
**Repository Branch:** `main` (Remote: [`xyzmr114/ds440-ethos`](https://github.com/xyzmr114/ds440-ethos))  
**Master Specification:** See [**`README.md`**](./README.md) and [**`AGENTS.md`**](./AGENTS.md)

> [!IMPORTANT]
> **Single Source of Truth**: This document supersedes and consolidates all prior disparate planning files (`KANBAN.md`, `STRETCH_GOALS.md`, and legacy sprint checklists) into a single, unified operational backlog.

---

## 1. Team Roster & Realigned Governance

To maximize engineering velocity and maintain research rigor, software development is fully decoupled from academic paper writing:

| Team Member | Environment | Primary Role | Core Deliverables & Domain Ownership | Paper 1 Status |
| :--- | :--- | :--- | :--- | :--- |
| **Harsh Rathi** | **macOS / Windows** | **Principal Engineer & Benchmark Lead** | **100% of Software Engineering & Benchmark Execution**: Standalone CLI runtime (`ethos` & `tbox`), Ratatui Cyber Obsidian TUI, Tauri v2 desktop GUI, Axum REST daemon, gVisor integration, Windows MSI/NSIS setup, macOS DMG/.app, Linux .deb/.AppImage, GitHub Actions CI/CD. Owns and executes **all 4 benchmark suites** (**InjecAgent**, **HackAPrompt**, **AgentHijack**, and **Synthetic Advanced Evasion**). | **0% Writing** *(Freed 100% for engineering & empirical benchmarks)* |
| **Aryamaan** | **Windows** | **Research Lead & Paper 1 Lead Author** | **Lead Author on Paper 1** (*Evaluating Tool Ergonomics, State Rollback, and Provenance Guardrails in Autonomous AI Software Engineering*). Coordinates related literature, experimental claims, and draft synthesis. | **Paper 1 Lead** |
| **Saathvik** | **Windows** | **Metrics & Empirical Analytics** | **Co-Author on Paper 1**. Processes telemetry datasets, generates token burn reduction curves, latency overhead comparisons, and final document typesetting. | **Paper 1 Co-Author** |
| **Ammar** | **Windows** | **Data & Literature Lead** | **Co-Author on Paper 1**. Literature review (SWE-agent, ExploitBench, gVisor), ingestion pipeline documentation, and dataset taxonomy writeups. | **Paper 1 Co-Author** |
| **Akshat** | **Windows** | **Threat & Security Modeling** | **Co-Author on Paper 1**. Adversarial attack taxonomy (MITRE ATLAS, indirect injection vectors, memory poisoning), Condition D boundary defense analysis. | **Paper 1 Co-Author** |

---

## 2. Multi-Agent Workflow Pipeline (Consolidated from Kanban)

Ethos tools and tasks progress through 5 strict lifecycle columns (viewable live in-app at `http://localhost:8000/?view=kanban` or via desktop app Hamburger Menu &rarr; **Agent Kanban**):

```text
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│   1. BACKLOG    │   2. PLANNING   │ 3. SANDBOX EXEC │ 4. TAINT AUDIT  │   5. VERIFIED   │
├─────────────────┼─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Unprioritized   │ Prompt parsing, │ Sandboxed tool  │ Byte-level      │ Invariants held,│
│ feature ideas & │ schema check,   │ execution in    │ provenance check│ audit recorded, │
│ attack vectors  │ policy profile  │ isolated tree   │ & egress gate   │ state committed │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

1. **Backlog**: Incoming tasks, synthetic adversarial vectors, and evaluation targets.
2. **Planning**: 2-phase intent triage, AST tool call parsing, and policy profile selection (`Strict`, `Permissive`, `AuditOnly`).
3. **Sandbox Exec**: Execution inside `LocalIsolatedRuntime` or gVisor (`runsc`) user-space sandbox with Copy-on-Write snapshot checkpoints.
4. **Taint Audit**: Taint propagation engine evaluates resource IDs against `RULE-001`, sensitive path blocks (`.env`, `id_rsa`), and network egress allowlists.
5. **Verified**: Execution completed with 0 invariant violations; state tree node committed to persistent ledger.

---

## 3. Codified Scope Cuts & Deprecations (Consolidated from Stretch Goals)

To protect delivery deadlines and eliminate unneeded complexity, the following scope cuts are codified and final:

| Cut Item | Original Proposal | Final Disposition | Architectural Rationale |
| :--- | :--- | :---: | :--- |
| **Paper 2 as a Separate Paper** | Two distinct capstone papers | **AXED / CONSOLIDATED** | Consolidated into **Paper 1 as Condition D** (Provenance & Boundary Defense). A single, definitive, publication-grade paper is significantly stronger than two fragmented drafts. |
| **SWE-bench Lite Evaluation** | Full SWE-bench benchmark run | **REPLACED** | Evaluating runtime boundary security and empirical telemetry across 4 targeted injection datasets (**InjecAgent**, **HackAPrompt**, **AgentHijack**, **Synthetic Evasion**) directly tests ACI safety without thousands of dollars in frontier API costs. |
| **Bare-Metal KVM MicroVMs** | Firecracker / Cloud-Hypervisor | **REPLACED** | Bare-metal virtualization introduces hardware dependency hell. Replaced with Google gVisor (`runsc`) user-space application-kernel sandbox on Linux/WSL2, Windows Sandbox on Windows, and `LocalIsolatedRuntime` on macOS. |
| **Cloud SaaS Tracing (Sentry.io)** | Cloud error telemetry | **AXED** | External SaaS adds API key exposure and privacy leakage. Local JSONL flight logs (`reports/flight_telemetry.jsonl`) capture high-fidelity execution telemetry with 0 external network requests. |
| **Probed Model Recalibration** | Dynamic 3-turn probe suite | **AXED** | Unnecessary runtime overhead for Paper 1 benchmarks, which hold models constant per condition. |
| **Multi-Modal Non-ACI Features** | TTS audio synthesis & video gen | **CUT** | Audio (Kokoro/ElevenLabs) and video generation have zero relevance to autonomous software engineering or taint tracking. |
| **Distributed Spider Crawlers** | Cloud crawling pools | **CUT** | Standard local HTTP requests and mock file scrapers are fully sufficient for testing untrusted inputs. |

---

## 4. Completed & Verified Milestones

### 4.1 Core Architecture & Multi-Surface Packaging
- [x] **Ethos Global Brand & Binary Architecture**: Consolidated under `ethos` with `tbox` retained as short typing alias.
- [x] **Pure Rust ACI Harness (`src/aci/harness.rs`)**: 1-indexed `view_lines`, exact `edit_block`, `search_files`, `grep`, `fetch` with untrusted tagging, shell `-c` interception, and `fold_output` context compression.
- [x] **Snapshot & Rewind Engine (`src/runtime/base.rs`)**: Copy-on-Write directory snapshotting and safe destructive rollback guarded by `.ethos_sandbox` marker.
- [x] **gVisor Syscall Sandbox (`src/runtime/gvisor.rs`)**: Automated `runsc` application-kernel sandbox on Linux/WSL2 with local fallback.
- [x] **Causal DAG State Tree (`src/aci/state_tree.rs`)**: Immutable branching history supporting Tree-of-Thought backtracking.
- [x] **Taint Provenance Engine (`src/taint/`)**: Bitmask severity tracking (`Trusted`, `Internal`, `Untrusted`, `Hostile`), worst-severity propagation, sensitive path protection (`.env`, `id_rsa`), and network egress allowlisting.
- [x] **Overkill Containment Walls (`src/walls/`)**: `PromptInjectScanner` (5 threat families), `OuroborosWall` (code immutability guard), `SemanticGuard` (in-memory intent scoring), and `EmergencyStop`.
- [x] **Cyber Obsidian Terminal TUI (`src/tui/zen.rs`)**: Ratatui interface with floating slash command popup (`/`), `Ctrl+X` leader key mode, multi-line prompt editing, setup wizard, and cross-platform clipboard.
- [x] **Axum REST API Daemon (`src/api/routes.rs`)**: Port 8000 endpoints (`/health`, `/v1/sandboxes`, `/v1/models`, `/v1/metrics`).
- [x] **Tauri v2 Desktop Application (`apps/desktop/`)**: Native cross-platform GUI for Windows, macOS, and Linux.
- [x] **Multi-Platform Installers**: Windows WiX MSI (`dist/windows/Ethos_0.1.0_x64_en-US.msi`) + NSIS Setup, macOS DMG/.app, Linux .deb/.AppImage.
- [x] **Test Verification**: 68 unit and integration tests across 17 test suites compile and pass with 0 warnings or failures.

### 4.2 Empirical Evaluation Sweeps Completed
- [x] **InjecAgent Benchmark**: 4 indirect injection vectors evaluated (100% intercepted by Ethos boundary policy).
- [x] **HackAPrompt Benchmark**: 10 canonical competition tiers evaluated live across 8 models with reasoning ablation.
- [x] **AgentHijack Benchmark**: 10 multi-turn trajectories evaluated live across models (100% defended).
- [x] **Synthetic Advanced Evasion Benchmark**: 10 modern red-team evasion vectors evaluated live (100% intercepted by Ethos boundary policy and Memory Guard).
- [x] **Cross-Model Empirical Sweep Across 8 Architectures**:
  - `DeepSeek-R1 0528` (8B) — Reasoning ON vs. Reasoning OFF (`</think>` prefill)
  - `Official Qwen 3.5 9B` (9B) — Reasoning ON vs. Reasoning OFF
  - `Uncensored Qwen 3.5 9B HauhauCS Aggressive` (9B) — Reasoning ON vs. Reasoning OFF
  - `Qwen 3 8B Base` (8.2B) — Reasoning ON vs. Reasoning OFF
  - `Google Gemma-4 12B` (12B) — Reasoning ON vs. Reasoning OFF
  - `Google Gemma-4 E4B` (7.5B) — Reasoning ON vs. Reasoning OFF
  - `NVIDIA Nemotron-3 4B` (4.0B) — Reasoning ON vs. Reasoning OFF
  - `Qwen 3 4B Base` (4.0B) — Direct baseline

---

## 5. Active Backlog & Next Steps

1. **Large Model Evaluations (Background Queue)**:
   - Monitor download completion in LM Studio for:
     - `nvidia/nemotron-3-nano-omni` (26.10 GB)
     - `qwen/qwen3.8-27b` (17.74 GB)
     - `prism-ml/bonsai-27b` (4.73 GB)
     - `meta/muse-glimmer` (18.16 GB)
   - Sequentially load, evaluate across the 4 benchmark datasets, and append results to `reports/`.
2. **Paper 1 Integration**:
   - Support Aryamaan, Saathvik, Ammar, and Akshat with empirical tables and figures from `reports/`:
     - *Table 1*: Cross-model attack success rate (ASR) comparison with reasoning ablation.
     - *Table 2*: Two-tier defense attribution (`defense_refused` vs. `defense_violations_blocked`).
     - *Table 3*: Latency and token burn across ACI vs. raw shell conditions.
     - *Figure 1*: The "Thinking Collapse" and "Deliberation Paradox" discovery charts.
