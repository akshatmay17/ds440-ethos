# Verified attack-source inventory

This replaces the earlier speculative registry. Its claimed 600K local attack
rows, 1M AgentHijack trajectories and `dev/data/` downloads were not established
by the checkout. A proposed benchmark protocol is not a measured result.

| Source | Actual local data | Status |
| --- | --- | --- |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | `data/upstream/injecagent/test_cases_*.json`: 1,054 base cases and 1,054 enhanced variants | Downloaded at pinned revision; instrumented campaigns available |
| [HackAPrompt](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset) | Public card under `data/upstream/hackaprompt/`; ten locally adapted texts under `data/injections/` | Full official parquet is gated; HTTP 401, not downloaded |
| [AgentHijack](https://github.com/tmlr-group/AgentHijack) | `data/upstream/agenthijack/verified/evaluation_examples/examples/`: 369 task JSON files | Nine corruption types; OSWorld/VM evaluation not run |
| Local historical acceptance collection | `data/injections/*.json`: 44 texts in five files | Classifier regression cases, not full official benchmark trials |
| Local modern challenges | `data/security/modern_attacks.json`; generated attachment fixtures under `data/campaigns/attachments/` | Development evaluation; not a blind holdout |

The three originally named datasets are InjecAgent, HackAPrompt and AgentHijack.
The older `uiuc-kang-lab/AgentHijack` URL was incorrect. Ten local fixtures named
AgentHijack have no verified mapping to the actual desktop benchmark.

Run `python scripts/fetch_attack_corpora.py --agenthijack` to fetch pinned
definitions and generate `reports/upstream_corpus_manifest.json`, including
per-file hashes and upstream task IDs. Raw corpora and fixtures are ignored by
Git. Authorized HackAPrompt access must be obtained before evaluating that
corpus; no replacement dataset is silently substituted.

See [campaign results, commands and oracle limits](../docs/attack-campaign.md),
[the project explanation](../docs/security-evaluation.md), and
[references and acknowledgments](../docs/references.md). Do not combine dataset
rows, training examples, corruption combinations and runtime interceptions into
one denominator. Report unsuccessful or ungraded trials explicitly.
