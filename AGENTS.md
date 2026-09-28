# AGENTS.md — Ethos Autonomous Agent Workspace Specification & Vibe-Coding Runbook

> **Master Reference**: All architectural specifications, team responsibilities, runtime details, and engineering benchmarks are codified herein and in [**`README.md`**](./README.md).

---

## 1. Project Philosophy & Identity: Ethos

**Ethos** (*formerly TaintBox / Aegis*) provides the **emotional intelligence, principled boundaries, and restraint that autonomous AI coding agents lack**.

When frontier LLMs operate in unconstrained environments, they suffer from context burns, prompt injection vulnerabilities, and destructive side-effects. An injected instruction in a dependency or scraped webpage can trick an agent into exfiltrating secrets, wiping test suites, or establishing external reverse shells. 

Ethos wraps autonomous agents in an ironclad Agent-Computer Interface (ACI) featuring:
- **Taint-Tracked I/O**: Bitmask provenance tracking across all inputs, memory, and tool calls.
- **Snapshot & Rewind**: Fast Copy-on-Write state checkpointing and causal DAG branching.
- **Multi-Layer Containment Walls**: Active interception via `PromptInjectScanner`, `OuroborosWall`, `SensitivePath` isolation, and `EmergencyStop`.
- **gVisor Syscall Interception**: Hardware-grade user-space kernel sandbox isolation on Linux/WSL2 with local CoW fallback.

---

## 2. Division of Labor & Team Ownership

To guarantee maximum engineering quality and publication-grade empirical research, responsibilities are strictly divided:

| Team Member | Role | Core Deliverables & Ownership | Paper 1 Status |
| :--- | :--- | :--- | :--- |
| **Harsh Rathi** | **Principal Engineer & Architect** | **100% of Software Engineering**: CLI runtime (`ethos` & `tbox`), Ratatui TUI, desktop native apps (Tauri v2), Axum REST daemon, gVisor integration, Windows/macOS/Linux installers, GitHub Actions CI/CD. Co-leads benchmark testing; executes **InjecAgent** and **HackAPrompt**. | **0% Writing** *(Freed 100% for engineering)* |
| **Aryamaan** | **Research Lead & Paper 1 Lead Author** | **Lead Author on Paper 1** (*Evaluating Tool Ergonomics, State Rollback, and Provenance Guardrails in Autonomous AI Software Engineering*). Executes benchmark testing on **AgentHijack** using the Ethos test harness. | **Paper 1 Lead** |
| **Ammar** | **Data & Literature Lead** | Co-author on Paper 1. Literature review, dataset documentation, and evaluation methodology. | **Paper 1 Co-Author** |
| **Akshat** | **Threat & Security Modeling** | Co-author on Paper 1. Adversarial taxonomy (MITRE ATLAS, injection vectors), Condition D defense analysis. | **Paper 1 Co-Author** |
| **Saathvik** | **Metrics & Empirical Analytics** | Co-author on Paper 1. Telemetry data aggregation, token burn reduction curves, latency overhead tables. | **Paper 1 Co-Author** |

---

## 3. Turnkey Vibe-Coding Runbook for Aryamaan's Agent

*This section provides an explicit, fail-proof runbook for Aryamaan's AI agent. Follow these steps sequentially.*

### Step 1: Install & Set Up LM Studio
1. Download and install **LM Studio** from [https://lmstudio.ai/](https://lmstudio.ai/) (available for Windows, macOS, and Linux).
2. Launch LM Studio.
3. Navigate to the **Search** tab (magnifying glass icon on the left sidebar).
4. Search for: `DeepSeek-R1-Distill-Qwen-7B-GGUF` (or `deepseek-r1`).
5. Select and download the recommended quantization (e.g., `Q4_K_M` or `Q5_K_M`).
6. Click **Load Model** at the top bar once the download completes.

### Step 2: Start the LM Studio Local Inference Server
1. Navigate to the **Developer / Local Server** tab (`<->` icon on the left sidebar).
2. Ensure the loaded model is set to `deepseek-r1` (or your downloaded variant).
3. Toggle **Start Server**.
4. Confirm the server is running on port `1234`:
   - Endpoint URL: `http://localhost:1234/v1`
   - Verification command:
     ```bash
     curl http://localhost:1234/v1/models
     ```
   - You should receive a JSON response listing the active DeepSeek-R1 model.

*(Alternative: If using Ollama, run `ollama run deepseek-r1:8b` which listens on `http://localhost:11434/v1`.)*

### Step 3: Launch the Ethos API Daemon
In a terminal window inside the repository root (`ds440-nittanystreet` on branch `harsh-dev`):
```bash
# Build and run the Ethos Axum daemon on port 8000
cargo run --bin ethos -- daemon --port 8000
```
Verify the daemon is alive:
```bash
curl http://localhost:8000/health
# Response: {"status":"ok","daemon":"ethos","version":"0.1.0"}
```

### Step 4: Run the Assigned Benchmark Dataset (AgentHijack)
Aryamaan owns the **AgentHijack** multi-turn injection dataset. Run the evaluation command:

```bash
# Live evaluation against local LM Studio DeepSeek-R1
cargo run --bin ethos -- eval --dataset agenthijack --provider lmstudio --model deepseek-r1 --output reports/agenthijack_results.json
```

*Note: You can also run the evaluation without a running LLM server to test the security boundary against the benchmark test cases directly:*
```bash
cargo run --bin ethos -- eval --dataset agenthijack
```

### Step 5: Locate and Extract Results for Paper 1
1. Open the generated report: `reports/agenthijack_results.json`.
2. The report contains:
   - `total_cases`: Total evaluated test vectors.
   - `interception_rate`: Percentage of injection attacks successfully intercepted by Ethos (target: 100%).
   - `blocked_attacks`: Count of malicious tool executions halted.
   - `clean_tasks_passed`: Count of legitimate operations successfully executed.
   - `defense_breakdown`: Defense wall attribution (`PromptInjectScanner`, `OuroborosWall`, `TaintBoundary`, `PathTraversal`).
3. Send this JSON report and summary metrics to the Paper 1 writing team (Ammar, Akshat, Saathvik, and Aryamaan) for inclusion in Section 5 (Empirical Evaluation).

---

## 4. Benchmark Dataset Division of Labor

We test against three premier injection benchmark suites:

1. **InjecAgent** (UIUC Kang Lab) — **Harsh Rathi**
   - 4 tool-augmented indirect injection scenarios targeting exfiltration and file modification.
   - Staged in `data/injections/injecagent_cases.json`.
   - Command: `cargo run --bin ethos -- eval --dataset injecagent`

2. **HackAPrompt** (Direct Injection & Jailbreaks) — **Harsh Rathi**
   - 4 direct prompt injection and perimeter-evasion vectors.
   - Staged in `data/injections/hackaprompt_cases.json`.
   - Command: `cargo run --bin ethos -- eval --dataset hackaprompt`

3. **AgentHijack** (UIUC Kang Lab, Multi-Turn Hijacking) — **Aryamaan**
   - 3 multi-turn conversation and context hijacking vectors.
   - Staged in `data/injections/agenthijack_cases.json`.
   - Command: `cargo run --bin ethos -- eval --dataset agenthijack`

*(To evaluate all datasets simultaneously: `cargo run --bin ethos -- eval --dataset all`)*

---

## 5. Mandatory Security Invariants for AI Agents

All tools and runtime modifications must strictly adhere to these invariants:

1. **Path Canonicalization & Symlink Escape Guard**:
   All filesystem paths pass through `resolve_path()` to ensure they remain inside the sandbox root. Relative traversal attempts (`../`) and directory symlink escapes return an immediate `BLOCKED_BY_POLICY` error.
2. **Safe Destructive Rewind Marker**:
   `restore_snapshot()` must verify the presence of the `.ethos_sandbox` (or legacy `.taintbox_sandbox`) marker file before touching or deleting files in any directory.
3. **Shell Wrapper Inspection**:
   Any invocation of shell interpreters (`bash`, `sh`, `cmd`, `powershell`) with `-c` or `-Command` arguments must be inspected for network egress (`curl`, `wget`) and file deletion (`rm`, `del`).
4. **Untrusted Web & File Quarantine**:
   Content retrieved via `fetch()` is automatically tagged `UntrustedWeb`. Files seeded from external or untrusted sources carry `TrustLevel::Untrusted`. Tainted payloads cannot trigger privileged operations without explicit policy authorization.
5. **Ouroboros Test Immutability**:
   Any attempt by an agent to modify test files (`tests/`, `*_test.rs`, `test_*.py`) triggers `OuroborosWall` and is blocked immediately to prevent agents from gaming benchmarks by disabling tests.

---

## 6. Production Slash Commands Reference

| Command | Action & Architectural Effect |
| :--- | :--- |
| **`/init`** | Analyzes workspace, indexes files, validates `AGENTS.md`, and computes SHA-256 baseline hashes. |
| **`/models`** | Queries `models.dev` dynamic catalog specifications (context windows, pricing, tool support). |
| **`/models <id>`** | Hot-swaps the active inference model with zero context loss. |
| **`/diff`** | Computes character-exact line additions (`+`) and deletions (`-`) with surfaced taint provenance. |
| **`/attack [id]`** | Stages an adversarial injection scenario against the boundary policy engine. |
| **`/walls`** | Inspects containment wall status (PromptInjectScanner, Ouroboros, E-Stop, Network Gate). |
| **`/taint`** | Dumps the active bitmask provenance ledger and custody chains. |
| **`/rewind`** | Rolls back sandbox filesystem and taint state to the last clean snapshot. |
| **`/setup`** | Opens interactive provider, API key, model, and policy configuration wizard. |
| **`/clear`** | Clears the session feed and resets the greeting buffer. |

---

## 7. Execution CLI & Tool Reference

- **Primary Binary**: `cargo run --bin ethos -- [SUBCOMMAND]`
- **Legacy / Short Alias**: `cargo run --bin tbox -- [SUBCOMMAND]`
- **Available Subcommands**:
  - `tui`: Launch the Cyber Obsidian interactive terminal interface.
  - `daemon --port 8000`: Launch the Axum REST API server.
  - `eval --dataset <injecagent|hackaprompt|agenthijack|all>`: Run benchmark evaluation suites.
  - `run --task "<prompt>"`: Execute an autonomous agent task in an isolated sandbox.
  - `setup`: Launch interactive CLI onboarding and configuration wizard.
  - `doctor`: Run system diagnostic checks (sandbox, containment walls, gVisor detection).
