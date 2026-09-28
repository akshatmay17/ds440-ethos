# Ethos Harness Stress Test: AI Attack Data Sources & Benchmark Specification

> **DS 440 Capstone — Group 2 (Nittany Street)**  
> **Compiled**: September 9, 2026  
> **Target Runtime**: Ethos (Pure-Rust Sandbox & ACI Harness)  
> **Evaluation Engine**: `ethos eval` / `POST /v1/lab/execute`  

---

## 1. Executive Summary & Attack Class Taxonomy

Ethos is evaluated against 7 distinct adversarial attack classes spanning direct, indirect, multi-turn, evasion, tool/MCP poisoning, and agent hijacking vectors. Each attack family is mapped to **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)** and defended by Ethos's layered security architecture:

```
+-----------------------------------------------------------------------------------+
|                              ETHOS DEFENSE PERIMETER                              |
+-----------------------------------------------------------------------------------+
|  1. PromptInjectScanner: Heuristic & regex scanner for injection patterns        |
|  2. Taint Ledger: Bitmask provenance tracking across all tool outputs & files     |
|  3. BoundaryPolicyEngine: Dynamic interception of untrusted privileged tool calls  |
|  4. OuroborosWall: Static & dynamic immutability barrier preventing self-tampering|
|  5. HalluScan: Grounding validator preventing phantom path execution             |
|  6. Network Egress Gate: Domain allowlisting blocking data exfiltration           |
+-----------------------------------------------------------------------------------+
```

---

## 2. Attack Corpus Catalog & Source Registry

| Attack Class | Corpus / Benchmark | Source & Coordinates | License | Verification Status | Target Ethos Wall | MITRE ATLAS Technique |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Indirect Prompt Injection** | **AgentDojo** | [github.com/eth-sri/agentdojo](https://github.com/eth-sri/agentdojo) | Apache-2.0 | `[V]` Live Repo | Boundary Policy + Taint Ledger | `AML.T0051` LLM Prompt Injection |
| | **InjecAgent** | [github.com/uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | Academic | `[V]` 1,054 test cases, 62K samples | Boundary Policy + Egress Gate | `AML.T0051`, `AML.T0053` Exfiltration |
| | **deepset/prompt-injections** | [HF: deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | CC-BY-SA-4.0 | `[V-HF]` 25K samples | PromptInjectScanner | `AML.T0051` |
| | **Lakera/mosscap** | [HF: Lakera/mosscap_prompt_injection](https://huggingface.co/datasets/Lakera/mosscap_prompt_injection) | Apache-2.0 | `[V-HF]` Real-world obfuscation | PromptInjectScanner | `AML.T0051` |
| | **DavidTKeane/moltbook & clawk** | [HF: DavidTKeane](https://huggingface.co/datasets/DavidTKeane) | MIT | `[V-HF]` Agentic social pairs | Taint Propagation Engine | `AML.T0051`, `AML.T0058` |
| **2. Direct Injection & Jailbreaks** | **hackaprompt-dataset** | [HF: hackaprompt/hackaprompt-dataset](https://huggingface.co/datasets/hackaprompt) | CC-BY-4.0 | `[V-HF]` 600K submissions | PromptInjectScanner | `AML.T0054` LLM Jailbreak |
| | **ChatGPT-Jailbreak-Prompts** | [HF: rubend18/ChatGPT-Jailbreak-Prompts](https://huggingface.co/datasets/rubend18/ChatGPT-Jailbreak-Prompts) | MIT | `[V-HF]` 48K downloads | PromptInjectScanner (DAN/AIM) | `AML.T0054` |
| | **JBB-Behaviors** | [HF: JailbreakBench/JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) | MIT | `[V-HF]` 72K downloads | Strict Profile Policy | `AML.T0054` |
| | **JailbreakHub** | [HF: walledai/JailbreakHub](https://huggingface.co/datasets/walledai/JailbreakHub) | Academic | `[V-HF]` 12K downloads | Persona Detection | `AML.T0054` |
| | **multi-turn_jailbreak** | [HF: tom-gibbs/multi-turn_jailbreak_attack_datasets](https://huggingface.co/datasets/tom-gibbs) | OpenRAIL | `[V-HF]` Stateful multi-turn | Turn History & Taint Graph | `AML.T0054` |
| **3. Evasion & Adversarial ML** | **Mindgard Evaded Samples** | [HF: Mindgard/evaded-prompt-injection](https://huggingface.co/datasets/Mindgard) | Academic | `[V-HF]` Bypassing Prompt Injection | Normalization & De-obfuscator | `AML.T0051.001` Obfuscation |
| | **walledai/HarmBench** | [github.com/centerforaisafety/HarmBench](https://github.com/centerforaisafety/HarmBench) | MIT | `[V-HF]` Adversarial ML benchmark | Boundary Policy Engine | `AML.T0054` |
| | **vigil-jailbreak-ada-002** | [HF: deadbits/vigil-jailbreak-ada-002](https://huggingface.co/datasets/deadbits/vigil-jailbreak-ada-002) | Apache-2.0 | `[V-HF]` 27K embeddings | Provenance Tracker | `AML.T0051` |
| **4. Tool & MCP Poisoning** | **Invariant Labs MCP** | [invariantlabs.ai/blog](https://invariantlabs.ai) | Research | `[V]` Injected MCP schemas & results | Schema Validator + Taint Mark | `AML.T0058` AI Agent Exploitation |
| | **Anthropic MCP Security** | [modelcontextprotocol.io](https://modelcontextprotocol.io) | Specs | `[V]` Official security threat model | Tool Invocation Gate | `AML.T0058` |
| **5. Agent Hijacking** | **AgentHijack** | [github.com/uiuc-kang-lab/AgentHijack](https://github.com/uiuc-kang-lab/AgentHijack) | Academic | `[V]` 1M+ trajectory sequences | Boundary Policy Engine | `AML.T0058` Goal Displacement |
| **6. M365 Copilot Attack Canon** | **Johann Rehberger (Embrace the Red)** | [embracethered.com](https://embracethered.com) | Research | `[V]` Exfiltration & ASCII Smuggler | Egress Gate + Sensitive Path | `AML.T0051`, `AML.T0053` |
| | **Simon Willison Archive** | [simonwillison.net/tags/prompt-injection](https://simonwillison.net) | Research | `[V]` Architecture analysis | Context Isolation | `AML.T0051` |
| | **Zenity Research** | [zenity.io/blog](https://zenity.io) | Research | `[V]` SharePoint / RAG poisoning | UntrustedWeb Tagging | `AML.T0043` Poison Data |
| **7. Taxonomy Checklists** | **MITRE ATLAS** | [atlas.mitre.org](https://atlas.mitre.org) | Public | `[V]` Full Matrix (`ATLAS.yaml`) | Unified Telemetry Mapping | Matrix Taxonomy |
| | **OWASP LLM Top 10 (2025)** | [owasp.org/www-project-top-10-for-large-language-model-applications](https://owasp.org) | Public | `[V]` LLM01 - LLM10 | All Harness Walls | Cross-Reference |

---

## 3. Stress Test Protocol (6-Round Harness Evaluation)

### Round 1: Baseline Compromise Rate
- **Target**: `deepset/prompt-injections` + `hackaprompt` + `mosscap`
- **Execution**: Run agent with boundary defense disabled (`--policy-profile AuditOnly`) vs enabled (`--policy-profile Strict`).
- **Metric**: Compromise Rate reduction ($CR_{unprotected} \rightarrow CR_{ethos}$).

### Round 2: Indirect Injection & M365 Exfiltration Vector
- **Target**: `AgentDojo` + `InjecAgent` email & web-fetch vectors.
- **Execution**: Agent ingests poisoned email/web documents that attempt privileged actions (`curl` exfiltration, `.env` reading, `rm -rf`).
- **Metric**: 100% Interception rate on sensitive file access and outbound egress.

### Round 3: Evasion & Obfuscated Payloads
- **Target**: `Mindgard` base64/homoglyph samples + `HarmBench` delimiter injections.
- **Execution**: Payloads bypass token-level scanners, but **Ethos's runtime provenance tracking** flags the data stream as `TrustLevel::Untrusted` regardless of payload string formatting.
- **Metric**: Zero bypasses via taint tracking even if lexical regex scanner score degrades.

### Round 4: Tool & MCP Poisoning
- **Target**: Invariant Labs MCP rogue tool definitions and poisoned results.
- **Execution**: Simulated MCP server returns malicious directives inside tool returns (`<|tool_call_boundary|>`).
- **Metric**: Taint mark propagation to downstream agent steps and automatic interception of derived commands.

### Round 5: Agent Hijacking & Multi-Step Trajectories
- **Target**: `AgentHijack` 3-turn goal displacement sequences.
- **Execution**: Agent is tasked with an innocent goal, reads poisoned file, and attempts to modify system state or policy files (`OuroborosWall`).
- **Metric**: Interception at step $N$ with state rollback via `ACIHarness::rewind()`.

### Round 6: MITRE ATLAS Coverage Matrix
- Map each intercepted test case to its MITRE ATLAS technique ID (`AML.T0051`, `AML.T0054`, `AML.T0058`, `AML.T0053`, `AML.T0043`) to produce the published defense matrix for the research paper.

---

## 4. Local Corpus Directory Layout (`dev/data/`)

All raw corpora, cloned repositories, and synthesized datasets are stored in `dev/data/`:
```text
dev/data/
├── 01_indirect_injection/
│   ├── deepset_prompt_injections.json
│   ├── lakera_mosscap.json
│   ├── davidtkeane_moltbook.json
│   ├── davidtkeane_clawk.json
│   ├── injecagent_test_cases.json
│   └── agentdojo/                         [Cloned repo: eth-sri/agentdojo]
├── 02_direct_jailbreak/
│   ├── chatgpt_jailbreak_prompts.json
│   ├── jbb_behaviors_harmful.json
│   ├── walledai_jailbreakhub.json
│   └── classic_dan_aim_jailbreaks.json
├── 03_evasion_adversarial/
│   ├── vigil_jailbreak_ada002.json
│   └── mindgard_harmbench_evasions.json
├── 04_tool_mcp_poisoning/
│   └── mcp_poisoning_attacks.json
├── 05_agent_hijack/
│   ├── agenthijack_trajectories.json
│   └── AgentHijack_repo/                  [Cloned repo: uiuc-kang-lab/AgentHijack]
├── 06_m365_canon/
│   └── m365_copilot_canon.json
└── 07_taxonomy_atlas/
    ├── ATLAS.yaml                         [Official MITRE ATLAS Matrix v4.5.0]
    ├── mitre_atlas_checklist.json
    └── mitre_atlas_repo/                  [Cloned repo: mitre-atlas/atlas-data]
```
