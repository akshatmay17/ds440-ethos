# Attack-surface coverage and gaps

Ethos does **not** cover every attack surface. This inventory distinguishes
enforcement from regression tests, live development trials and untested systems.
It maps the categories raised in the user-supplied
[article](https://dev.to/trixsec/ai-jailbreaking-in-2026-prompt-tricks-agent-hijacks-countermeasures-3dna)
to local evidence. The article is a topic checklist, not benchmark evidence;
its general success-rate and SDK claims have not been adopted as facts.

## Current coverage

| Surface | Evidence in Ethos | Remaining gap |
| --- | --- | --- |
| Role-play, fake developer authority | Scanner patterns and BERT regression texts; runtime checks apply independently | No universal harmful-content prevention; semantic scores remain advisory |
| Scrambled words, encoding, Unicode | Homoglyph normalization, obfuscation fixtures, provenance-aware tool rules | Not a comprehensive typoglycemia/encoding fuzzer; encoded secrets may evade value matching |
| Indirect documents and tool responses | 2,108 live InjecAgent instrumented trials: 92 actual runtime-intercepted cases | Original semantic service grader and clean-task utility are missing |
| Gradual conversation escalation, fabricated prior assistant agreement | Turn history and action gates exist | No faithful Crescendo/Echo Chamber campaign or long-context repeated-run evaluation |
| Instruction and skill poisoning | Ouroboros blocks AGENTS/CLAUDE/GEMINI/SKILL/MEMORY files and skill directories; inert regression probes | Trusted installation, supply-chain verification and operator edit workflows are not implemented |
| Persistent memory poisoning | Persisted file provenance, rewrite/rewind/reload regressions and memory-file protections | No vector-database/RAG memory store, retrieval-rank poisoning, signed promotion or multi-writer integrity test |
| MCP tool descriptions and protocol abuse | [Real shadcn STDIO lab](mcp-public-evaluation.md), malicious registry response, native outside-file positive control, restricted Docker comparison and six forced ACI effects | No production MCP broker, dynamic schema-pinning lifecycle, OAuth/session isolation or malicious executable-server evaluation |
| Secret leakage | Known-value tool-result filtering, secret-bearing outbound argument rejection, limited child environment; final agent summaries now redacted | Unknown, split, transformed or encoded secrets; general proprietary data loss; all streaming/export channels not audited |
| Unauthorized command execution | Application supports only disabled/Docker; disposable non-root commands, no network/host mount/fallback; live regressions | Unconfined adapters exist only for explicit library tests/baselines; Docker/kernel escape resistance and brokered external capabilities remain untested |
| AI-generated adaptive attacks | Separate local attacker/defender, actual walls and fresh inert workspace per candidate | Small development trials; goal intent needs review; no reasoning-on/off comparison or broad repeated trials |
| Fuzzing and optimized suffix search | Regression cases and an exported-case adapter for AdaptiveAttackAgent | No full grammar/property fuzzer or upstream GCG optimization run |
| Image-based instructions | Six earlier vision trials, including four attacks and two benign controls | Later rerun exposed local vision-engine errors; no broad multimodal claim |
| Visual preference manipulation | TRAP source reviewed and cited | No TRAP perturbation experiment or GUI action runner; text scanners cannot establish coverage |

## What computer-use attacks add

A desktop agent reads webpages, email, screenshots and application dialogs,
then performs clicks or tool actions with user privileges. This gives an
attacker places to influence perception and subsequent decisions. The
[TRAP implementation](https://github.com/uiuc-focal-lab/TRAP) studies semantic
image perturbations and image-choice preferences. It is distinct from placing
an explicit instruction in an invoice image.

Taint can restrict a privileged action after reading an external image. It
cannot establish that the model chose the correct image, recipient or button.
If an action is already permitted, selecting the wrong target may still succeed.
That requires task-specific invariants, verified recipient/destination binding
and checks on actual effects. A better image classifier alone does not supply
authorization. Our current campaign tests do not reproduce an OSWorld desktop.

## AdaptiveAttackAgent interoperability

At inspected commit `7ea08cf4424e689079c6bc6348e28fbb84a090eb`, the
[upstream project](https://github.com/uiuc-kang-lab/AdaptiveAttackAgent) loads
Llama/Vicuna causal model weights and optimizes adversarial strings using model
gradients. Its detector variants can optimize against another classifier.
This differs from our local black-box LLM proposal/feedback loop. LM Studio's
GGUF chat endpoint does not expose the gradients needed to run upstream GCG.

The four bundled full test files contain the same 2,108 InjecAgent payloads
already imported. Two 50-row subsets are duplicates within that collection.
Do not add those 100 rows or the whole fork to the independent corpus count.
Upstream `extract_adv_string` exports complete case lists, including unchanged
cases. The Ethos adapter preserves original goals and source-file hashes and
can select only rows carrying an optimized string:

```powershell
python scripts/attack_campaign.py --upstream-cases path/to/generated_dh_data.json path/to/generated_ds_data.json --optimized-only --mode live --defender ethos-redteam --output reports/imported_adaptive_new.json
```

Optimizer JSONL loss logs are not the exported case format. No optimizer code
is executed by this adapter. Imported cases still use the instrumented proxy
oracle, so they cannot establish official benchmark parity.

## Highest-priority gaps

1. Expand the tested disposable command boundary to reviewed developer images and a broker for narrowly authorized external effects.
2. Add faithful conversational and persistent-retrieval attacks with task-specific goals and benign controls.
3. Expand the public MCP lab to production transport integration, malicious server lifecycles, schema changes and remote sessions.
4. Complete an output-channel and transformed-secret audit; exact-value redaction is useful but bounded.
5. Evaluate visual decisions and trusted target binding separately from text-in-image injection.

The official [MCP security policy](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/SECURITY.md)
describes configured STDIO server process launching as intended behavior,
with isolation and access restrictions supplied by the deployment. That is
more specific than treating all MCP SDKs as an unsanitized-shell vulnerability.
Similarly, no article-wide percentage predicts Ethos's protection rate. Use
our [measured campaign outcomes](attack-campaign.md) and preserve failures.

The October 15 [container implementation](container-execution.md) closes the
earlier unconditional host-exec default. It does not establish MCP, GUI, retrieval
memory or unrestricted shell-baseline coverage. Historical attack reports retain
their original runtime/build identity; do not relabel them as container trials.
The subsequent [secret-boundary review](secret-boundary-review.md) found and
fixed a hard-link read/write bypass. This demonstrates why those coverage rows
must not be read as proof that no bypass exists.

The [public shadcn MCP lab](mcp-public-evaluation.md) now tests real STDIO server calls and a restricted container comparison. Its forced ACI follow-up checks are not live-agent ASR or production MCP integration.
