# TODO.md — Team Backlog & Sprint Assignments

> **Notice**: The sprint backlog, individual task assignments, engineering roadmap, and research deliverables are consolidated into [**`AGENTS.md`**](./AGENTS.md) and [**`README.md`**](./README.md).

### Summary of Realigned Responsibilities:
- **Harsh Rathi**: **100% of Software Engineering & Benchmark Execution** (CLI runtime, Ratatui TUI, Tauri v2 desktop apps, REST API, Windows WiX MSI/NSIS setup, macOS DMG/.app, Linux .deb/.AppImage, gVisor integration, GitHub Actions CI/CD). Owns and executes **all 3 benchmark datasets** (**InjecAgent**, **HackAPrompt**, **AgentHijack**). Completed live DeepSeek-R1 evaluation across all datasets. **0% writing on Paper 1**.
- **Aryamaan**: **Paper 1 Lead Author** (*Evaluating Tool Ergonomics, State Rollback, and Provenance Guardrails in Autonomous AI Software Engineering*). Assists with HackAPrompt research context and paper drafting.
- **Saathvik**: **Paper 1 Co-Author** (Empirical metrics, latency overhead quantification, token burn reduction curves).
- **Ammar**: **Paper 1 Co-Author** (Literature review, ingestion methodology, related works).
- **Akshat**: **Paper 1 Co-Author** (Threat modeling, adversarial attack vectors, Condition D boundary defense).

### Milestone Status (Oct 2026):
- [x] **Ethos Global Rename**: 100% completed across codebase, schema, and docs.
- [x] **Core Engineering**: All 68 Rust tests passing across 17 test suites (0 warnings).
- [x] **Installer Staging**: Native Windows MSI (`dist/windows/Ethos_0.1.0_x64_en-US.msi`) and NSIS installer built.
- [x] **Live Inference Engine**: LM Studio multi-port discovery (`2277`, `1234`) connected to `deepseek/deepseek-r1-0528-qwen3-8b`.
- [x] **Dataset Coverage**:
  - **InjecAgent**: 4 indirect injection vectors evaluated (100% intercepted by Ethos boundary policy).
  - **HackAPrompt**: 10 canonical competition levels evaluated live against DeepSeek-R1 (100% defended via model test-time reasoning refusal).
  - **AgentHijack**: 10 multi-turn trajectories evaluated live against DeepSeek-R1 (100% defended).
- [ ] **Paper 1 Drafting**: Aryamaan (Lead) + Saathvik, Ammar, Akshat incorporating empirical tables from `reports/`.
