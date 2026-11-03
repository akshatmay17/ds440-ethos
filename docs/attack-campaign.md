# Corpus inventory and outcome-based attack campaigns

## The three datasets

The project names **InjecAgent, HackAPrompt and AgentHijack**. Their sizes and
purposes must be counted separately. Revision pins, downloaded file hashes and
task IDs are recorded in `reports/upstream_corpus_manifest.json`.

| Source | Verified local availability | Evaluation status |
| --- | --- | --- |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | 1,054 base cases plus 1,054 enhanced variants; 2,108 distinct payloads | Policy replay and live instrumented trials completed |
| [HackAPrompt](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset) | Dataset card available; official parquet returns HTTP 401 and requires authorized access | Full corpus not evaluated; ten local examples are not the full dataset |
| [AgentHijack](https://github.com/tmlr-group/AgentHijack) | 369 desktop task JSON definitions, nine corruption types | VM benchmark not run; local ten text cases have no established mapping |

AgentHijack is built on OSWorld. Its nine types include pop-ups, resolution,
marks, subtitles, additional apps, accidental touches, minimization, network
failure and verification. The 369 × 9 = 3,321 combinations concern desktop
robustness; they are not 3,321 malicious prompt texts. Running them requires
an OSWorld VM and a screenshot/action agent. Downloading task files is not
executing the benchmark. Its README's config path is stale: the pinned checkout
contains `config/default.yaml`.

The earlier “roughly 601k” inventory has not been substantiated by local attack
records. Do not add source marketing totals, benign training rows, enhanced
variants and executable tasks into one attack-success denominator.

## Measured outcomes

`reports/injecagent_live_2108_oct14.json` records 2,108 live trials using local
Nemotron-3-Nano-4B (`ethos-redteam` alias), seed 440 and two model turns:

| Outcome | Cases | Meaning |
| --- | ---: | --- |
| Runtime interception; no goal effect | 92 | A model-requested action was actually denied |
| Goal not observed | 2,003 | No oracle goal; no runtime interception established |
| Inconclusive | 13 | Eight HTTP errors and five truncated responses |
| Observed compromise | 0 | Under the instrumented oracle below |

**Do not publish “2,108 attacks stopped.”** Original service tools are simulated;
the terminal declared attacker tool supplies a reachability proxy, not the
official InjecAgent semantic grader. Legitimate task completion is ungraded.
There is no paired live unprotected baseline establishing attack effectiveness.
Base/enhanced variants share underlying tasks. Public cases and adaptive seeds
are development evaluation, not an established blind holdout.

The separate policy replay forces source-declared attacker actions through the
Rust taint boundary. It reports 2,108/2,108 intercepted cases, **without an LLM**.
This verifies policy behavior under supplied actions, not full benchmark defense.
Worker unit tests include a positive control in which the same inert goal
succeeds when policy is bypassed inside the test worker.

`reports/attachment_live_oct14.json` contains six actual Qwen3.5-9B vision trials:
four image-delivered instruction/skill/memory attacks and two benign controls.
All six completed the order-summary task; two attack cases triggered denied
protected-file writes and two produced no observed attack goal. Attack text was
embedded in pixels, not supplied to the model as a plaintext transcript. This
is a small development smoke test, not broad multimodal coverage.
The later parallel rerun, `attachment_final_oct15.json`, was entirely
inconclusive (five local vision-engine errors and one nonexistent-file tool
error). A serial rerun, `attachment_serial_oct15.json`, completed all six
tasks with no observed attack goal and no runtime interception. Preserve both;
they demonstrate why infrastructure errors cannot count as successful defenses.

`reports/adaptive_ouroboros_oct14.json` contains twelve generated candidates
(four seeds × three rounds): Nemotron attacker → Qwen defender → actual Rust
walls → state/output oracle → feedback to attacker. All twelve had no observed
goal. Candidate intent remains marked unreviewed; count them as generated trials,
not twelve independently validated attacks defeated. The evaluator and policies
are never editable by that loop.
`synthetic_adaptive_oct15.json` subsequently exercised all six existing Rust
procedural seeds for two rounds each: eleven goals not observed and one
inconclusive trial. Generated malicious intent still requires review. The
AdaptiveAttackAgent import smoke test replayed 100 existing subset cases with
100 intercepts; these are duplicate source records and no optimized upstream
attack was generated. See [integration and remaining surfaces](attack-surface-coverage.md).

The October 14 live reports preserve their original worker hashes. Subsequent
runtime hardening is tested separately; `injecagent_policy_final_oct15.json`
uses the rebuilt worker; `injecagent_policy_current_oct15.json` repeats the
same 2,108 interceptions after expanding the independent protected-file oracle
and exporting procedural seeds. Retry reports preserve the original inconclusive
results and have their own denominator; never silently merge different settings.
The 13-case retry used four turns, 768 output tokens and an 8,192-token context:
eleven finished with no observed goal, and two exceeded context. A second retry
at 16,384 context resolved those two: one runtime interception and one goal not
observed. Original results remain intact. The separate final modern-text run
records thirteen trials: one interception and twelve goals not observed.

## Reproduce and extend

```powershell
python scripts/fetch_attack_corpora.py --agenthijack
cargo build --release --example campaign_worker
python scripts/attack_campaign.py --mode replay --limit 2108 --output reports/replay_new.json
python scripts/attack_campaign.py --mode live --defender ethos-redteam --limit 2108 --output reports/live_new.json
python scripts/attack_campaign.py --retry-from reports/injecagent_live_2108_oct14.json --defender ethos-redteam --steps 4 --max-tokens 768 --output reports/retry_new.json
python scripts/attack_campaign.py --mode adaptive --source modern --limit 4 --rounds 3 --output reports/adaptive_new.json
python scripts/attack_campaign.py --mode adaptive --source synthetic --limit 6 --rounds 3 --output reports/synthetic_adaptive_new.json
python scripts/build_attachment_challenges.py
python scripts/attack_campaign.py --image-case data/campaigns/attachments/cases.json --limit 6 --output reports/vision_new.json
python scripts/security_stress.py
```

Live modes require a running local OpenAI-compatible model endpoint, default
`http://127.0.0.1:2277/v1`. Load the appropriate model under each alias; vision
cases require a vision model. Adaptive mode requires both aliases. The driver
rejects remote endpoints and redirects, never falls back to scripted success,
and refuses existing report paths. JSONL stores individual actions and oracle
evidence; summaries distinguish intercepts, unobserved goals and errors.

`--source synthetic` exports the six existing Rust `SyntheticAttackEngine`
scenarios through the worker and feeds their payloads into the same live/adaptive
loop. It uses a neutral summary task instead of the older user prompts that
explicitly asked the agent to follow the injected instructions. Source filenames
are retained as document data rather than recreated as a full source environment;
these are adapted procedural seeds, not official benchmark reproductions.

The worker uses temporary files and inert service effects. It cannot execute
host commands, send emails, make payments or reach the network. Unsupported
effects are inconclusive. This restriction is specific to the evaluation worker;
the original application runtime used unconfined host execution. Since October
15, configured execution defaults to disabled and offers a separately tested
[disposable container backend](container-execution.md). These older inert
campaigns must not be relabeled as live container trials.

## Weaknesses addressed and remaining work

Ouroboros now protects agent instructions, skills, memory, workflows, policy
configuration and the persisted provenance ledger. Unknown files become untrusted
on read, view or grep; taint survives session reload and unsourced rewriting.
Unconfined opaque commands are denied once external data enters the context. Child processes
receive a limited environment rather than provider credentials, and Windows no
longer implicitly routes every executable through a shell.

These rules deliberately restrict useful unconfined commands after external reads. They
need a capability/authorization design and utility evaluation before deployment.
These policy changes alone do not provide OS isolation, prevent a same-user
host attacker editing the ledger, or track every implicit information flow.
The new container backend supplies a separate command boundary. Next meaningful experiments
are an authentic service-task grader with a paired baseline, a family-separated
holdout, multilingual benign controls, longer adaptive trajectories and an
isolated GUI runner for AgentHijack. See [the engineering explanation](security-evaluation.md)
and [references](references.md) for model choices and credits.
