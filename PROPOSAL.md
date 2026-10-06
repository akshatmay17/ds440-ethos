# DS 440 Capstone Project Proposal

## TaintBox: A Taint-Tracked Sandbox Runtime and Agent-Computer Interface for AI Agents

**Capstone Group:** (2) Nittany Street
**Course:** DS 440, Data Sciences Capstone
**Instructor:** Dr. Robert Thomson (Penn State University)
**Deliverable type:** Business grade technical report, working sandbox runtime, and two research papers

> This proposal supersedes both the earlier Cross Asset TCA proposal and
> the benchmark-only security draft, per instructor feedback on novelty
> and team direction. The TCA scaffolding remains in the repository as
> historical work.

---

## 1. Executive Summary

The agent-computer interface is the biggest capability lever in AI today.
The same model on a raw shell performs at one level, and on a
purpose-built execution harness performs at an entirely different one.
SWE-agent, ExploitBench, and BabyRun all demonstrate the same effect.
Meanwhile every agent deployment carries the same unresolved security
problem: untrusted content (emails, web pages, tool outputs) flows into
the model with no provenance, and prompt injection turns the agent's own
tools into the attacker's tools.

This project builds **TaintBox**, a sandbox execution API for AI agents
with three primitives nobody ships today:

1. **Snapshot and rewind.** The agent can time-travel its execution:
   run, observe, branch, rewind to any state. Structured typed tools
   replace the raw shell so the model stops burning context navigating a
   terminal.
2. **Taint-tracked I/O.** Every byte entering the box carries provenance.
   Taint metadata travels with the data, and policy fires at the tool
   boundary: tainted data cannot trigger privileged operations.
3. **Telemetry by construction.** Every execution is also an attack
   event stream, because the box sees what the agent reads, where it
   came from, and what it tries to do with it.

The deliverable is the runtime itself, an API and SDK shaped like the
sandbox companies developers already use, plus two papers:

- **Paper 1 (capability):** measure model performance across harness
  designs. Raw shell versus structured tools versus snapshot-rewind.
  The ACI matters more than the model tier.
- **Paper 2 (defense):** measure injection success with and without
  taint-tracked boundaries. Does provenance surfaced to the model plus
  boundary policy cut compromise rates in a way prompt hardening cannot?

This is the sandbox company playbook plus a research program on
something we invent. Not a benchmark for its own sake. Not a classifier
bolted on top. The runtime is the product, the papers are the proof.

---

## 2. Problem Formulation (Heilmeier Catechism)

### 2.1 What are we trying to do?

Build a sandbox execution runtime for AI agents that makes agents
measurably more capable (better harness) and measurably safer (taint
tracked boundaries), and prove both claims with controlled experiments.

### 2.2 How is it done today, and what is missing?

Sandbox companies (E2B, Daytona, gVisor based infra) sell execution
isolation: can the agent's code hurt the host. Their protection starts
the moment code executes, and their boxes are dumb Linux environments
with file and process APIs.

**Limitation 1: isolation is the wrong boundary for the biggest threat.**
The Copilot inbox attack executes no code. The agent reads a malicious
email and forwards the inbox. A sandbox changes nothing about that.
Sandboxes protect the host, not the data, not the user.

**Limitation 2: the harness is treated as plumbing.** Commercial
sandboxes give agents a shell and call it done. Research (SWE-agent,
ExploitBench, BabyRun) shows the agent-computer interface is one of the
largest capability levers available. Nobody productizes that insight.

**Limitation 3: no provenance.** Agent runtimes do not track where a
byte of content came from. Classic security solved this decades ago with
taint analysis. Perl shipped taint mode in the 1990s. No agent runtime
carries taint across the trust boundary today.

### 2.3 What is new in our approach?

1. **A productized ACI.** Structured typed tools, observation channels,
   and snapshot-rewind as first class primitives of the sandbox runtime,
   with the capability gains measured and published.
2. **Taint-tracked execution.** Provenance metadata on every read,
   write, and tool invocation, with policy enforcement at the boundary
   where tainted data meets privileged action.
3. **The runtime as research instrument.** Because the box observes
   everything, capability and safety experiments run on the same system
   with full instrumentation, no separate harness needed.

### 2.4 Who cares?

Agent platform vendors, security teams deploying agents (banks,
government, health), and researchers building the next generation of
agent benchmarks. For vendors, the capability story. For security
teams, the taint story. For researchers, an instrumented runtime that
makes both kinds of experiments cheap.

---

## 3. The Product: Sandbox API with Three Primitives

### 3.1 Runtime base

Firecracker or gVisor microVM per session. One agent, one box, hardware
level isolation, cold start in hundreds of milliseconds.

### 3.2 The ACI layer

The agent never sees a raw shell. It sees typed tools:

- `read(path)`, `write(path, content)` with provenance attached
- `exec(program, args, env)` returning structured stdout, stderr, exit
  code, and side effect observations
- `observe()` returning state diff since last step
- `snapshot()` and `rewind(snapshot_id)` for time-travel execution
- `fetch(url)` with the response tagged as untrusted by construction

### 3.3 The taint engine

- Every input carries a provenance record: source (email id, URL,
  user upload, internal), trust level, and chain of custody
- Taint propagates through reads, copies, and derived values
- Policy rules fire at tool boundaries: tainted data cannot trigger
  privileged actions (send email, transfer, delete, network egress)
  without explicit policy override
- The model receives taint status in its observation stream, so it can
  reason about provenance instead of guessing

### 3.4 Telemetry and audit

Every session emits a structured event log: reads with provenance,
executions with effects, policy decisions, rewind operations. The log is
the audit trail regulators will demand, and the dataset for our own
research.

### 3.5 Developer experience

REST API plus Python and TypeScript SDKs, E2B style: create sandbox,
run tools, read observations, destroy. Free tier for students and open
source, usage pricing for teams. Docs-led growth, the Spider.cloud
playbook. Open source the runtime, sell the hosted service and the
self-hosted distribution.

---

## 4. Research Plan: Two Papers

### 4.1 Paper 1: The ACI capability curve

Question: how much of agent performance is the model, and how much is
the interface?

Experiment: hold the model fixed, vary the harness.

| Condition | Interface |
|---|---|
| A | Raw shell, no observation channel |
| B | Typed tools, no snapshot |
| C | Typed tools plus snapshot-rewind |
| D | Full ACI with provenance surfaced to the model |

Benchmarks: agentic coding tasks (SWE-bench-lite subset, Terminal-Bench
subset), multi-step environment tasks, and a sandbox-specific task suite
we contribute. Models: three tiers (small open, mid open, frontier API)
to show the curve across model quality.

Claim to test: harness design explains a larger share of performance
variance than model tier within a plausible band.

### 4.2 Paper 2: Taint as the trust boundary

Question: does taint-tracked execution reduce prompt injection
compromise rates in ways prompt hardening cannot?

Experiment: the injection corpus (direct, indirect, multi-turn, tool
poisoning) run against agent configurations:

| Configuration | Defense |
|---|---|
| Baseline | No defenses |
| Hardened | Prompt hardening only |
| TaintBox | Taint tracking plus boundary policy |
| Full | TaintBox plus hardening |

Metrics: attack success rate, benign task completion (utility), false
positive policy blocks, and defense efficiency (ASR reduction per unit
latency cost).

Claim to test: policy at the provenance boundary blocks exfiltration and
action-on-objectives attacks that bypass prompt defenses, because the
block does not depend on the model understanding the attack.

### 4.3 Why the papers matter for the product

Paper 1 sells the capability story to platform vendors. Paper 2 sells
the security story to enterprise security teams. The same runtime, the
same instrumentation, two markets, and the open source release that
seeds both.

---

## 5. Architecture

```
Agent (any framework: LangChain, smolagents, SDKs)
        │
        ▼
[TaintBox API]  (auth, sessions, policy store)
        │
        ▼
[ACI layer]  (typed tools, observations, snapshot manager)
        │
        ▼
[Taint engine]  (provenance records, propagation, boundary policy)
        │
        ▼
[Runtime]  (Firecracker or gVisor microVM, per session)
        │
        ▼
[Telemetry]  (event stream, audit log, research dataset)
```

Components:

- `runtime/`: microVM manager, image builder, lifecycle
- `aci/`: tool schemas, observation protocol, snapshot store (overlayfs
  based)
- `taint/`: provenance ledger, propagation rules, policy engine
- `api/`: REST gateway, SDKs, rate limiting, auth
- `telemetry/`: structured event sink, audit export
- `eval/`: benchmark runners for both papers

## 6. Methodology

### 6.1 Harness design experiments

Full factorial over interface conditions, three model tiers, two
benchmarks. Fixed seeds, logged prompts, pinned model versions. Results
reported as performance curves with confidence intervals, plus ablation
of each ACI primitive (typed tools alone, snapshot alone, provenance
surfacing alone).

### 6.2 Taint experiments

The injection corpus: direct, indirect, multi-turn, and tool poisoning
families, generated with self-hosted open-weight attacker models
(frontier APIs refuse offensive generation, which is itself a named
finding about the defense ecosystem). Held out attack families for
detector evaluation where applicable. Judge model double sampling with
disagreement flags.

### 6.3 Evaluation metrics

| Metric | Definition |
|---|---|
| Task success rate | Benchmark tasks completed correctly per harness condition |
| Attack success rate | Injection goals achieved per defense configuration |
| Utility | Benign task completion under defense, must not collapse |
| Policy false positive rate | Benign actions blocked by the taint engine |
| Overhead | Latency and cost added by each ACI and taint feature |

### 6.4 Safety and ethics

Synthetic inboxes and test environments only. No real PII, no live
systems, no third-party targets. The runtime's policy engine is itself
the responsible disclosure mechanism: findings are released as benchmark
results and defense papers, not exploit writeups.

---

## 7. Bi-Weekly Sprint Schedule

| Sprint | Weeks | Focus | Deliverable |
|---|---|---|---|
| 1 | 1 to 2 | Runtime base (gVisor first, Firecracker stretch), typed tool ACI v1, CI | Progress Report 1: architecture, related work, literature review |
| 2 | 3 to 4 | Observation channel, snapshot and rewind, first capability runs | Progress Report 2: harness v1 benchmark numbers |
| 3 | 5 to 6 | Taint engine: provenance ledger, propagation, policy | Progress Report 3: taint v1, injection corpus v1 |
| 4 | 7 to 8 | Full factorial capability study, taint defense study | Progress Report 4: both experiments, first results |
| 5 | 9 to 10 | API polish, SDKs, docs site, telemetry export | Progress Report 5: developer experience release |
| 6 | 11 to 12 | Ablations, error analysis, limitations, papers drafted | Final report, open source release, oral |

---

## 8. Team Structure and Governance

| Role | Owner | Focus |
|---|---|---|
| Product Owner / Lead Author | Harsh | Vision, ACI design, paper 1 lead, sponsor alignment |
| Scrum Master / Process Lead | Aryamaan | Sprints, Kanban, progress reports |
| Data and Infrastructure Lead | Ammar | Runtime, taint engine, eval harness, CI |
| Attack and Security Lead | Akshat | Injection corpus, red team models, paper 2 lead |
| Evaluation and Reliability | Saathvik | Metrics, reproducibility, ablations, telemetry |

Weekly 10 minute sponsor briefings. About 5 to 6 hours per member per
week outside class. A tier target, zero missed reports, reproducible
code.

---

## 9. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| MicroVM complexity eats the semester | Core slips | gVisor first (single binary), Firecracker only as stretch |
| Snapshot storage blowup | Cost and flakiness | Overlayfs snapshots, size caps, prune policy |
| Taint false positives break agents | Utility collapse | Policy default deny only for privileged tools, tunable levels |
| Frontier APIs refuse attack generation | Corpus blocked | Self-hosted open-weight attacker models |
| Eval cost | Budget | Laptop scale benchmarks, API budget caps, local small models |
| Scope creep into production infra | Loses the research | The runtime stays a research instrument first, product second |

---

## 10. References

1. Yang, J. et al., "SWE-agent: Agent-computer interfaces enable
   automated software engineering", 2024.
2. ExploitBench contributors, "ExploitBench: Evaluating autonomous
   agents for exploiting software vulnerabilities", 2025.
3. E2B, "Open source AI code interpreter sandboxes", technical docs.
4. Agache, A. et al., "Firecracker: Lightweight virtualization for
   serverless applications", NSDI 2020.
5. Google, "gVisor: an application kernel for containers".
6. Perl documentation, "perlsec: taint mode", original taint tracking
   design.
7. Greshake, K. et al., "Not what you've signed up for: Compromising
   real-world LLM-integrated applications with indirect prompt
   injection", AISec 2023.
8. Willison, S., "Prompt injection attacks against GPT-3", 2022, and
   ongoing Copilot injection coverage.
9. Zhan, Q. et al., "Formalizing and benchmarking prompt injection
   attacks and defenses", USENIX Security 2024.
10. Liu, X. et al., "AgentBench: Evaluating LLMs as agents", ICLR 2024.
11. Shinn, N. et al., "Reflexion: Language agents with verbal
    reinforcement learning", 2023.
12. Microsoft Security Research, guidance on Copilot prompt injection
    and data exfiltration vectors.
