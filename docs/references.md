# References and project acknowledgments

Reviewed October 14, 2026. Distinguish linked dependencies, optional integrations,
model candidates, dataset inspirations, and adapted UI ideas. A mention is not
evidence that upstream code or weights are actually loaded.

## Direct Rust dependencies

The root and desktop Cargo manifests declare the following packages. Exact
resolved versions and transitive dependencies are recorded in the root and
desktop Cargo lockfiles. Optional neural packages are enabled by `semantic-ml`.

| Package | Upstream documentation |
| --- | --- |
| `tokio` | [tokio](https://docs.rs/tokio) |
| `axum` | [axum](https://docs.rs/axum) |
| `tower` | [tower](https://docs.rs/tower) |
| `tower-http` | [tower-http](https://docs.rs/tower-http) |
| `serde` | [serde](https://docs.rs/serde) |
| `serde_json` | [serde_json](https://docs.rs/serde_json) |
| `serde_yaml` | [serde_yaml](https://docs.rs/serde_yaml) |
| `uuid` | [uuid](https://docs.rs/uuid) |
| `chrono` | [chrono](https://docs.rs/chrono) |
| `tracing` | [tracing](https://docs.rs/tracing) |
| `tracing-subscriber` | [tracing-subscriber](https://docs.rs/tracing-subscriber) |
| `tempfile` | [tempfile](https://docs.rs/tempfile) |
| `sha2` | [sha2](https://docs.rs/sha2) |
| `hex` | [hex](https://docs.rs/hex) |
| `dotenvy` | [dotenvy](https://docs.rs/dotenvy) |
| `anyhow` | [anyhow](https://docs.rs/anyhow) |
| `thiserror` | [thiserror](https://docs.rs/thiserror) |
| `reqwest` | [reqwest](https://docs.rs/reqwest) |
| `sqlx` | [sqlx](https://docs.rs/sqlx) |
| `clap` | [clap](https://docs.rs/clap) |
| `regex` | [regex](https://docs.rs/regex) |
| `ratatui` | [ratatui](https://docs.rs/ratatui) |
| `crossterm` | [crossterm](https://docs.rs/crossterm) |
| `candle-core` | [candle-core](https://docs.rs/candle-core) |
| `candle-nn` | [candle-nn](https://docs.rs/candle-nn) |
| `candle-transformers` | [candle-transformers](https://docs.rs/candle-transformers) |
| `tokenizers` | [tokenizers](https://docs.rs/tokenizers) |
| `windows-sys` (Windows file identity checks) | [windows-sys](https://docs.rs/windows-sys) |
| `tauri` | [tauri](https://docs.rs/tauri) |
| `tauri-build` | [tauri-build](https://docs.rs/tauri-build) |

Core inference is implemented with Hugging Face
[Candle](https://github.com/huggingface/candle) and
[Tokenizers](https://github.com/huggingface/tokenizers).
The terminal UI uses [Ratatui](https://ratatui.rs) and
[Crossterm](https://github.com/crossterm-rs/crossterm).
The desktop shell uses [Tauri](https://tauri.app).

## UI design and code provenance

- [OpenCode](https://github.com/anomalyco/opencode): acknowledged for agent UI
  and interaction patterns (sidebar, command palette and model picker).
  Local source comments identify these influences.
- [OpenTUI](https://github.com/anomalyco/opentui): acknowledged as a
  user-reported upstream UI/code reference. It is not a linked dependency in
  the current Rust/static-HTML manifests. The exact copied/adapted fragments,
  upstream revisions and associated notices have not been mapped in this
  checkout. Do not claim that this audit established a direct OpenTUI runtime.
- When adding or identifying adapted source, record the local path, upstream
  path/commit and retained attribution alongside the code. This references
  page does not complete that source-provenance audit.

## Model training and candidates

- [PyTorch](https://pytorch.org), [Transformers](https://github.com/huggingface/transformers),
  [Datasets](https://github.com/huggingface/datasets), and [NumPy](https://numpy.org):
  local training/evaluation tooling.
- [BERT-base uncased](https://huggingface.co/google-bert/bert-base-uncased):
  base recorded in the local `ethos-guard-bert-base` card.
- [BERT-small](https://huggingface.co/google/bert_uncased_L-4_H-512_A-8):
  base recorded in the local `ethos-guard-laya` card; this is an Ethos-trained
  classifier, not upstream Laya weights.
- [BERT-tiny](https://huggingface.co/prajjwal1/bert-tiny): local tiny-model
  training candidate.
- [mrm8488 BERT-tiny injection classifier](https://huggingface.co/mrm8488/bert-tiny-ft-prompt-injection):
  the Rust loader's default neural repository when no checkpoint is selected.
- [Upstream Laya](https://huggingface.co/convaiinnovations/laya):
  System 1 decision-model reference; current upstream architectures require a
  compatible backend before comparison with Ethos's BERT classifiers.
- [Meta Prompt Guard](https://huggingface.co/meta-llama/Prompt-Guard-86M) and
  [ProtectAI DeBERTa](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2):
  catalog/candidate models; enum names do not establish loader compatibility.
- Public training sources listed in `prepare_semantic_dataset.py` include
  [deepset prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections),
  [jackhhao jailbreak-classification](https://huggingface.co/datasets/jackhhao/jailbreak-classification),
  [Lakera Gandalf](https://huggingface.co/datasets/lakera/gandalf_ignore_instructions),
  [Stanford Alpaca](https://huggingface.co/datasets/tatsu-lab/alpaca), and
  [Databricks Dolly](https://huggingface.co/datasets/databricks/databricks-dolly-15k).
  Follow source dataset/model cards for provenance and terms.

## Runtime, inference services and distribution

- [gVisor](https://gvisor.dev): a separate runtime adapter/probe exists.
  Detection of `runsc` is not evidence of confinement of agent commands.
- [Docker Engine](https://docs.docker.com/engine/security/) and
  [container run options](https://docs.docker.com/reference/cli/docker/container/run/):
  disposable command backend. [Alpine](https://hub.docker.com/_/alpine) supplies
  the pinned minimal probe image; no compilers are included. Default commands
  are disabled until an operator configures a backend. See [implementation](container-execution.md).
- [models.dev](https://models.dev): provider/model catalog.
- [LM Studio](https://lmstudio.ai) and [Ollama](https://ollama.com):
  optional local model endpoints.
- [Spider](https://spider.cloud): optional web ingestion service.
- [PostgreSQL](https://www.postgresql.org): optional persistent session store.
- [Lockit](https://github.com/Ishaannarang22/lockit):
  optional credential-admission launcher integration; see [setup and limits](lockit-integration.md).
- [WiX](https://github.com/wixtoolset/wix), [NSIS](https://nsis.sourceforge.io),
  and [AppImage](https://appimage.org): installer/bundle tooling referenced by
  desktop distribution.
- [GitHub Actions](https://github.com/features/actions): CI and release workflows.
  Exact action versions are in `.github/workflows/`.

## Attack datasets and research

Local `data/injections/` JSON contains 44 authored/adapted cases. Their
names do not establish official benchmark coverage, source row IDs or
faithful reproduction. Preserve a mapping to upstream rows before making
benchmark-comparison claims.

- [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent):
  indirect attacks delivered through tools; four local cases carry this name.
- [HackAPrompt dataset](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset):
  prompt attack reference; ten local cases carry the name.
- [AgentHijack repository](https://github.com/tmlr-group/AgentHijack) and
  [project](https://agenthijack.github.io/): Sun, Zhu, Li, Liu, Hu and Han,
  *AgentHijack: Benchmarking Computer Use Agent Robustness to Common Environment
  Corruptions*, ICML 2026. Pinned revision
  `1191fcef2b43985987424b5f73aa36603a8233a3` has 369 desktop task definitions and
  nine corruption types; configs are downloaded, but the VM evaluation has not
  run. It builds on [OSWorld](https://github.com/xlang-ai/OSWorld).
  The ten locally named `agenthijack_cases.json` text scenarios still have no
  established mapping to those tasks. The older `uiuc-kang-lab` attribution
  was incorrect.
- [BIPIA](https://github.com/microsoft/BIPIA):
  indirect-injection research referenced in local scenario descriptions.
- [Embrace The Red](https://embracethered.com/blog/):
  Johann Rehberger's published agent-security research is cited by local
  email/memory scenarios; exact post-to-case mapping remains to be recorded.
- [AgentDojo](https://github.com/ethz-spylab/agentdojo):
  reference for executable attacker/defender tasks and explicit outcomes;
  not currently imported as an Ethos dependency.
- [AdaptiveAttackAgent](https://github.com/uiuc-kang-lab/AdaptiveAttackAgent):
  official implementation of *Adaptive Attacks Break Defenses Against Indirect
  Prompt Injection Attacks on LLM Agents*, Findings of NAACL 2025; inspected
  revision `7ea08cf4424e689079c6bc6348e28fbb84a090eb`. GCG and multi-model
  gradient optimization reference. Bundled InjecAgent cases overlap the imported
  corpus; they are not an additional independent dataset. The Ethos adapter
  imports exported case JSON as data; upstream gradient training has not run.
- [TRAP](https://github.com/uiuc-focal-lab/TRAP), Kang, Yeon and Singh,
  *Targeted Redirecting of Agentic Preferences* (2025),
  [paper](https://arxiv.org/abs/2505.23518): inspected revision
  `cfd955aa3624ddc527da52b5cc31955292eddba2`. CLIP/Stable Diffusion semantic
  image perturbation and VLM preference evaluation reference. Neither its
  training nor its evaluation has run through Ethos. Ordinary text-in-image
  fixtures do not reproduce TRAP.
- [Skill-Inject](https://arxiv.org/abs/2602.20156) and
  [its implementation](https://github.com/aisa-group/skill-inject):
  skill-file attack evaluation reference.
- [From Untrusted Input to Trusted Memory](https://arxiv.org/abs/2606.04329):
  memory-poisoning evaluation reference.
- [Anthropic: mitigating prompt injections in browser use](https://www.anthropic.com/research/prompt-injection-defenses):
  reference for adaptive evaluation and residual risk.
- Synthetic evasion fixtures and the new development challenges are local
  Ethos work. Their results must be labeled separately from official datasets.

- [shadcn/ui MCP server](https://ui.shadcn.com/docs/mcp),
  [source](https://github.com/shadcn-ui/ui/tree/main/packages/shadcn/src/mcp):
  MIT-licensed public MCP test subject, npm package `shadcn@4.21.5`.
  Uses the [Model Context Protocol TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk).
  No shadcn server code was copied into Ethos. The npm lock and
  [lab evaluation](mcp-public-evaluation.md) record the tested dependency version.

See [security-evaluation.md](security-evaluation.md) for measured results,
method choices, limitations and the distinction between classifiers and
end-to-end prevention.

