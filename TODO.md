# TaintBox: Team Backlog & Sprint Assignments

**Sprint Cycle:** Sprint 1 — Subsystem Expansion & Data Pipelines  
**Sprint Deadline:** September 15, 2026 (1-Week Target)  
**Capstone Group:** (2) Nittany Street — Penn State DS 440  
**Repository Branch:** `harsh-dev` (Production Merge Target: `main`)  

---

## 1. Team Roster & Organizational Roles

| Member | Role | Core Domain & Ownership |
|---|---|---|
| **Harsh Rathi** | **Scrum Master** | Agile Sprint Cadence, Backlog Prioritization, Kanban Velocity, Blocker Removal, Demo Orchestration, Stakeholder Alignment |
| **Aryamaan** | **Team Lead & Architect** | System Architecture, Rust Module Boundaries, ACI Primitives, ACI Harness Invariant Testing, **Lead Author on Paper 1 (ACI Capability Scaling)** |
| **Ammar** | **Data & Testing Lead** | Sandbox Virtualization (gVisor on Linux, Windows Sandbox, macOS default), Ingestion Pipelines (SWE-bench/Terminal-Bench), **CI/CD & Release Automation**, **Co-Author on Paper 1** |
| **Akshat** | **Attack & Security Lead** | Two-Tier Intent Classifier (TF-IDF + ONNX), Synthetic Adversarial Corpus Generator (Ollama Bunker), Harness Boundary Security Testing, **Co-Author on Paper 1** |
| **Saathvik** | **Dashboard & Backend Lead** | Axum REST API Daemon, PostgreSQL Session & History Persistence (`src/store/postgres.rs`), Web/Desktop Dashboard, **Co-Author on Paper 1** |

---

## 2. Explicit Sprint 1 Tasks & Deliverables (Due: Sept 16, 2026)

### 1. Harsh Rathi — Scrum Master & Process Operations
* **Primary Focus**: Sprint velocity, agile governance, and capstone deliverable readiness.
* **Explicit Deliverables**:
  * **Agile Governance & Kanban**: Maintain GitHub Projects Kanban board tracking items across *Backlog*, *In Progress*, *Review*, and *Done*.
  * **Sprint Cadence**: Run weekly standup syncs, document velocity, and coordinate dependencies between evaluation harness and dashboard telemetry.
  * **Demo Orchestration**: Coordinate live end-to-end demo runs of the `tbox` binary and desktop dashboard for faculty reviews.
  * **Course Milestone Alignment**: Ensure all DS 440 grading criteria, sponsor deliverables, and team contract expectations are met on schedule.

---

### 2. Aryamaan — Team Lead & Paper 1 (ACI Capability Scaling)
* **Primary Focus**: System architecture integrity, ACI harness testing, and leading Paper 1 execution.
* **Component**: `src/aci/`, `src/runtime/`, `docs/`, and `papers/paper1_aci.md`.
* **Explicit Deliverables**:
  * **ACI Architectural Enforcement & Harness Testing (Paper 1 Foundation)**:
    * Formalize and rigorously test `ACIHarness` structured tool execution pipeline (`view_lines`, `edit_block`, `search_files`, `grep`, `fetch`, `exec`).
    * Verify core harness invariants: zero context leaks across tool turns, deterministic window folding, and strict file isolation.
    * Implement and test Tree-of-Thought state branching algorithms in `src/aci/state_tree.rs`.
    * Verify rollback fidelity: state snapshot creation, hashing, and instantaneous rewind without dangling references.
  * **Paper 1 Lead Author**:
    * **Title**: *Evaluating Tool Ergonomics and Context Compression in Autonomous AI Software Engineering*
    * **Hypothesis**: Structured windowed tools with snapshot/rewind improve task completion by `> 30%` while slashing token burn by `> 40%` compared to unstructured raw bash shells.
    * **Experimental Setup**: Define 4 benchmark conditions holding frontier models constant:
      1. *Condition A*: Vanilla raw bash shell without structured observation.
      2. *Condition B*: Structured typed tools (`view_lines`, `edit_block`).
      3. *Condition C*: Structured tools with state snapshot and rollback (`/rewind`).
      4. *Condition D*: Full TaintBox ACI with provenance surfaced to model context.
    * **Draft Deliverables**: Complete Introduction, Methodology, System Design, and Evaluation Plan for Paper 1.

---

### 3. Ammar — Data, Testing & Production CI/CD Automation (Paper 1 Co-Author)
* **Primary Focus**: Bulletproof testing infrastructure, GitHub Actions release pipeline, and OS-targeted sandbox virtualization.
* **Component**: `.github/workflows/`, `src/runtime/`, `src/aci/dataset.rs`.
* **Explicit Deliverables**:
  * **Production CI/CD Automation (GitHub Actions)**:
    * **CI Matrix Workflow (`.github/workflows/ci.yml`)**:
      * Runs on every pull request to `harsh-dev` and `main`.
      * Cross-platform OS matrix: `ubuntu-latest`, `macos-latest`, `windows-latest`.
      * Steps: `cargo test --all-targets`, `cargo clippy -- -D warnings`, `cargo fmt --check`.
    * **Automated Release Workflows (`.github/workflows/release*.yml`)**:
      * Cross-compiles production binaries: `tbox-windows-x86_64.exe`, `tbox-linux-x86_64`, `tbox-macos-aarch64`.
      * Generates SHA256 checksums (`SHA256SUMS.txt`) and publishes official GitHub Releases.
  * **Dataset Ingestion Pipeline**:
    * Python & Rust ingestor loading **SWE-bench Lite** (`princeton-nlp/SWE-bench_Lite`) and **Terminal-Bench** (`laude-institute/terminal-bench`).
    * Populates isolated test sandboxes with initial Git repos, task descriptions, and unit test suites.
  * **Platform-Specific Sandbox Virtualization**:
    * **Linux**: Google gVisor (`runsc` user-space application kernel adapter).
    * **Windows**: Windows Sandbox / container isolation boundary.
    * **macOS**: Default native isolated runtime (`LocalIsolatedRuntime` with path traversal guards and directory containment).
    * *(Note: Firecracker MicroVMs / Linux KVM hardware prototypes are officially cut).*
  * **Paper 1 Co-Author**: Responsible for experimental test harness runs and container performance benchmarks.

---

### 4. Akshat — Attack Vectoring & Security Lead (Paper 1 Co-Author)
* **Primary Focus**: Query intent classification, synthetic attack corpus generation, and harness security testing for Paper 1.
* **Component**: `src/walls/classifier.rs`, `src/bunker/`, `data/injections/`, `papers/paper1_aci.md`.
* **Explicit Deliverables**:
  * **Two-Tier Runtime Query & Intent Classifier**:
    * *Tier 1*: Pure-Rust TF-IDF feature extraction + Random Forest classifier (`smartcore`) for `< 1ms` sub-turn triage (`BENIGN_QUERY`, `CODE_EDIT`, `SYSTEM_ADMIN`, `ADVERSARIAL_PROBE`).
    * *Tier 2*: ONNX Runtime transformer (DistilBERT / ModernBERT via `ort`) for deep semantic payload detection on ambiguous queries.
  * **Synthetic Adversarial Corpus Generator**:
    * CLI command `taintbox attackgen` connecting to local Ollama Bunker (`http://localhost:11434`) running `qwen2.5-coder` or `deepseek-r1`.
    * Generates benchmark test cases across the 4 threat families:
      1. *Direct Prompt Injection* (instruction overrides, jailbreaks, system prompt extraction).
      2. *Indirect Prompt Injection* (M365 email attacks, scraped HTML payloads, tool return poisoning).
      3. *Multi-Turn Conversational Injection* (role confusion, delayed payload triggers).
      4. *Tool Poisoning & Supply Chain* (tampered configs, dependency poisoning).
    * Formats outputs into standardized JSON in `data/injections/corpus_v1.json`.
  * **Harness Security & Condition D Validation**:
    * Test how the ACI harness performs against the synthetic attack suite when provenance is surfaced to the model (Condition D).
    * Verify boundary policy intercepts unauthorized egress and file tampering.
  * **Paper 1 Co-Author**: Author the Evaluation, Attack Robustness, and Ablation Study sections for Paper 1.

---

### 5. Saathvik — Dashboard & Backend Lead (Paper 1 Co-Author)
* **Primary Focus**: REST API daemon, PostgreSQL session/audit persistence, and dashboard frontend.
* **Component**: `src/api/routes.rs`, `src/store/postgres.rs`, `apps/desktop/ui/`.
* **Explicit Deliverables**:
  * **PostgreSQL Session History & Audit Persistence**:
    * Production database integration via `PostgresStore` (`src/store/postgres.rs` and `migrations/0001_init.sql`).
    * Persist multi-session execution history, turn-by-turn tool inputs/outputs, audit events (`AuditEvent`), and snapshot metadata (`SnapshotMetadata`).
  * **Axum REST API Completion**:
    * Complete endpoints for `/v1/sandboxes`, `/v1/tools/execute`, `/v1/metrics`, `/v1/taint/graph`, and `/v1/lab/execute`.
    * Server-Sent Events (SSE) stream broadcasting live telemetry and policy trip alerts.
  * **Web & Desktop Dashboard (OpenCode UI)**:
    * Maintain OpenCode-style Cyber Dark Obsidian interface with live SVG telemetry sparklines.
    * Integrated Session Inspector (File Explorer, Code View, Step-by-Step History, Snapshot Rewind).
  * **Paper 1 Co-Author**: Lead telemetry instrumentation, latency overhead quantification, token burn reduction metrics, and camera-ready figures for Paper 1.

---

## 3. Scope Cuts & Deprecations (Sprint 1 & Beyond)

To ensure team velocity and deliver a publication-grade Paper 1 for DS 440, the following items have been explicitly cut or de-prioritized:

1. ❌ **Paper 2 (Taint as Trust Boundary as a Separate Paper)**:
   - **Status**: **CUT**. Consolidated into Paper 1 as **Condition D** (*Full ACI with Provenance Surfaced to Model*).
   - **Rationale**: Splitting the team across two independent academic papers in one semester risks two incomplete drafts. Focusing 100% of the team on Paper 1 yields a much stronger, fully empirical capstone deliverable.
2. ❌ **Hardware MicroVMs (Firecracker / Linux KVM / Hyper-V)**:
   - **Status**: **CUT**. Linux utilizes gVisor (`runsc`), Windows uses Windows Sandbox, and macOS uses the default native isolated runtime.
   - **Rationale**: Bare-metal KVM MicroVM setup introduces severe friction and hardware dependencies. gVisor and native sandboxes provide container isolation without VM complexity.
3. ❌ **Cloud SaaS Tracing (Sentry.io)**:
   - **Status**: **AXED / CUT**.
   - **Rationale**: External SaaS dependency adds API key management and potential data leakage. Local JSONL event logging and PostgreSQL audit records capture all telemetry directly.
4. ❌ **Probed Dynamic Model Recalibration Engine (`recalibration.go` port)**:
   - **Status**: **AXED / CUT**.
   - **Rationale**: Dynamic 3-turn probing suite on mid-session model swaps is unnecessary for Paper 1, where benchmarks hold models constant per evaluation condition.
5. ❌ **Multi-Modal Out-of-Scope Features (TTS Audio, Image/Video Gen)**:
   - **Status**: **CUT**.
   - **Rationale**: Audio synthesis (Kokoro, ElevenLabs) and generative video (Runway, Kling) have no relevance to software engineering ACI or taint tracking research.
6. ❌ **Spider Cloud Distributed Crawling Pools**:
   - **Status**: **CUT**.
   - **Rationale**: Standard local HTTP requests and mock scrapers are sufficient for testing untrusted inputs.

---

## 4. Getting Started for Teammates

1. **Clone & Switch to Dev Branch**:
   ```bash
   git clone https://github.com/xyzmr114/ds440-nittanystreet.git
   cd ds440-nittanystreet
   git checkout harsh-dev
   ```

2. **Verify Environment & All Tests**:
   ```bash
   cargo test
   ```
   *(All 60 unit and integration tests across 17 test suites must pass).*

3. **Run the Optimized Terminal App**:
   ```bash
   cargo run --release --bin tbox
   ```
