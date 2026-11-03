# Injection datasets

Converted from upstream benchmarks into the schema used by `data/injections/*.json`.
Every file is a flat JSON array. Each element has the same ten keys, so one loader reads all of them.

```
id, name, attacker_goal, attack_type, severity, target_tool,
poisoned_file, poisoned_content, agent_prompt, expected_action
```

## Files

| File | Cases | Source | Licence |
|---|---|---|---|
| `injecagent_full.json` | 2108 | InjecAgent (Zhan et al., ACL 2024 Findings) `uiuc-kang-lab/InjecAgent` | MIT |
| `agentdojo_cases.json` | 561 | AgentDojo (Debenedetti et al., NeurIPS 2024) `ethz-spylab/agentdojo` | MIT |
| `bipia_email_cases.json` | 3750 | BIPIA (Yi et al., 2023) `microsoft/BIPIA` | MIT |
| `../capability/injected.json` | 6 | authored here | project licence |
| `../channels/fetch_cases.json` | 8 | authored here | project licence |
| `../channels/tool_output_cases.json` | 8 | authored here | project licence |

Total: 6441 cases.

## How each one was built

**InjecAgent.** Both the base and the enhanced test sets are included, 510 data stealing and 544 direct harm each, because every payload differs between the two, so they are distinct cases rather than duplicates. `poisoned_content` is the tool response that carries the injection. `target_tool` is the attacker tool the case tries to reach. 62 distinct attacker tools and 17 user tools survive conversion.

**AgentDojo.** The package ships attack templates and goals as Python rather than as a data file, so the goals are extracted with an AST pass over the four suites, including the f-string placeholders resolved from class variables. All 27 injection tasks are crossed with all 86 user tasks for 561 pairs. The carrier text is the longest injection vector in each suite, and the attack string is AgentDojo's `ImportantInstructions` template. `target_tool` is `unknown` because the goal does not name a tool.

**BIPIA.** The email test set holds 50 contexts. The text attack set holds 75 attacker tasks across 15 categories. The full cross product is included.

## Caveats

The AgentDojo and BIPIA conversions are reconstructions of how those benchmarks assemble an attack at runtime, not official releases of attack instances. The rows are faithful to the published construction, but if you need numbers that match their papers exactly, run their harnesses.

Leftover `{_PLACEHOLDER}` tokens in a small number of AgentDojo user prompts mean the original resolves that value from environment state rather than from a class variable. They are left untouched rather than filled with invented values.

## Rebuilding

Sources were cloned at:

- `github.com/uiuc-kang-lab/InjecAgent`
- `github.com/ethz-spylab/agentdojo`
- `github.com/microsoft/BIPIA`
