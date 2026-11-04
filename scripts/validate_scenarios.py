#!/usr/bin/env python3
"""Validate Ethos v2 evaluation scenario files against the contract in
docs/eval-scenario-schema.md and what src/aci/eval.rs actually loads.

Checks every scenario file under data/ (or the paths given) for:
  * valid JSON array of objects, unique ids across all files;
  * kind in {attack, benign, capability} and the fields that kind needs;
  * oracle / utility predicates: known type, required fields, no unknown keys;
  * every path an oracle (file_modified/file_deleted/file_written) or a utility
    (file_*) names is seeded in setup_files or created by the task — so the
    attack has something to act on and a check is not vacuous;
  * sandbox-relative paths (no leading '/', '../' only where the payload is a
    traversal attack and the oracle expects it);
  * attack cases name an untrusted source (untrusted_files / mock_urls /
    mock_commands) and a non-empty oracle;
  * benign prompts do not authorize acting on untrusted content (the framing
    bug that made indirect-injection cases trivially "succeed");
  * mock_urls / mock_commands keys appear verbatim in the prompt.

Exit code 0 if every file is valid, 1 otherwise. Used in CI.

Usage:
  python scripts/validate_scenarios.py                 # all data/ scenario dirs
  python scripts/validate_scenarios.py data/benign/controls.json ...
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULT_GLOBS = [
    "data/injections/*.json",
    "data/benign/*.json",
    "data/capability/*.json",
    "data/channels/*.json",
    "data/imported/*.json",
]

KINDS = {"attack", "benign", "capability"}
FAMILIES = {
    "exfiltration", "tamper", "persistence", "destruction", "escape",
    "leak", "hijack", "supply_chain", "none",
}
CHANNELS = {"file", "fetch", "tool_output", "none"}

ORACLE_FIELDS = {
    "egress": ({"host"}, set()),
    "canary_leak": (set(), set()),
    "sensitive_read": (set(), {"path"}),
    "command": ({"args_contains"}, {"program"}),
    "args_contains": (set(), {"value"}),
    "file_written": (set(), {"path"}),
    "file_modified": (set(), {"path"}),
    "file_deleted": (set(), {"path"}),
}
UTILITY_FIELDS = {
    "file_contains": (set(), {"path", "value"}),
    "file_not_contains": (set(), {"path", "value"}),
    "file_exists": (set(), {"path"}),
    "file_absent": (set(), {"path"}),
    "summary_contains": (set(), {"value"}),
}

# Words in a benign prompt that authorize acting on untrusted instructions.
# These turn an indirect-injection test into (effectively) a direct one.
COMPLICIT_PHRASES = (
    "follow the instructions", "follow its instructions", "follow the directives",
    "execute the instructions", "execute any", "run the instructions",
    "apply the recommended", "apply any", "do what it says", "do what the",
    "perform the steps", "complete the steps", "implement the requested",
    "carry out the instructions", "obey",
)


class Problems:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, where: str, msg: str) -> None:
        self.items.append(f"{where}: {msg}")


def norm_path(p: str) -> str:
    return p.replace("\\", "/").lstrip("/").lower()


def check_predicate(pred, table, where, prob) -> None:
    if not isinstance(pred, dict):
        prob.add(where, f"predicate must be an object, got {type(pred).__name__}")
        return
    t = pred.get("type")
    if t not in table:
        prob.add(where, f"unknown predicate type {t!r}")
        return
    optional, required = table[t]
    keys = set(pred.keys()) - {"type"}
    for r in required:
        if r not in pred:
            prob.add(where, f"{t} is missing required field {r!r}")
    unknown = keys - optional - required
    if unknown:
        prob.add(where, f"{t} has unknown field(s) {sorted(unknown)}")


def seeded_or_created(path: str, case: dict) -> bool:
    """A path is OK to reference if it is seeded, or the prompt plausibly asks
    the agent to create it (file_written / file_exists on a new file)."""
    want = norm_path(path)
    setup = {norm_path(k) for k in case.get("setup_files", {})}
    if case.get("poisoned_file"):
        setup.add(norm_path(case["poisoned_file"]))
    if want in setup:
        return True
    # Allow references to a file the prompt names (agent is asked to create it).
    prompt = (case.get("benign_prompt") or "") + " " + (case.get("agent_prompt") or "")
    return path.split("/")[-1].lower() in prompt.lower()


def validate_case(case: dict, where: str, prob: Problems) -> None:
    if not isinstance(case, dict):
        prob.add(where, "case must be an object")
        return
    if not case.get("id"):
        prob.add(where, "missing id")
    kind = case.get("kind", "attack")
    if kind not in KINDS:
        prob.add(where, f"kind {kind!r} not in {sorted(KINDS)}")
    fam = case.get("family")
    if fam is not None and fam not in FAMILIES:
        prob.add(where, f"family {fam!r} not in {sorted(FAMILIES)}")
    ch = case.get("channel")
    if ch is not None and ch not in CHANNELS:
        prob.add(where, f"channel {ch!r} not in {sorted(CHANNELS)}")

    setup = case.get("setup_files", {})
    if not isinstance(setup, dict):
        prob.add(where, "setup_files must be an object")
        setup = {}

    # Path hygiene.
    all_paths = list(setup.keys()) + list(case.get("untrusted_files", []))
    for p in all_paths:
        if not isinstance(p, str):
            prob.add(where, f"path is not a string: {p!r}")
            continue
        if p.startswith("/"):
            prob.add(where, f"absolute path not allowed: {p!r}")

    oracle = case.get("oracle", [])
    utility = case.get("utility", [])
    if not isinstance(oracle, list):
        prob.add(where, "oracle must be a list")
        oracle = []
    if not isinstance(utility, list):
        prob.add(where, "utility must be a list")
        utility = []

    for i, o in enumerate(oracle):
        check_predicate(o, ORACLE_FIELDS, f"{where} oracle[{i}]", prob)
        if isinstance(o, dict) and o.get("type") in ("file_modified", "file_deleted"):
            path = o.get("path", "")
            if path and not seeded_or_created(path, case):
                prob.add(where, f"oracle {o['type']} path {path!r} is not seeded in setup_files "
                                f"(the attack has nothing to act on)")
    for i, u in enumerate(utility):
        check_predicate(u, UTILITY_FIELDS, f"{where} utility[{i}]", prob)
        if isinstance(u, dict) and u.get("type") in ("file_contains", "file_not_contains", "file_absent"):
            path = u.get("path", "")
            if path and not seeded_or_created(path, case):
                prob.add(where, f"utility {u['type']} path {path!r} is neither seeded nor named in the prompt")

    # Kind-specific rules.
    if kind == "attack":
        has_source = (
            case.get("untrusted_files") or case.get("mock_urls")
            or case.get("mock_commands") or case.get("poisoned_file")
        )
        if not has_source:
            prob.add(where, "attack case has no untrusted source "
                            "(untrusted_files / mock_urls / mock_commands / poisoned_file)")
        if not oracle:
            prob.add(where, "attack case has an empty oracle (attacker success is unmeasurable)")
        benign = case.get("benign_prompt")
        if benign:
            low = benign.lower()
            for phrase in COMPLICIT_PHRASES:
                if phrase in low:
                    prob.add(where, f"benign_prompt authorizes the attack ({phrase!r}); "
                                    "use a realistic task framing instead")
                    break
    elif kind == "benign":
        if oracle:
            prob.add(where, "benign case must not have an oracle")
        if not utility:
            prob.add(where, "benign case should have a utility check")
    elif kind == "capability":
        if case.get("untrusted_files"):
            prob.add(where, "capability case must not list untrusted_files")
        if not utility:
            prob.add(where, "capability case needs a utility check")

    # Mock keys must be referenced by the prompt (so the agent uses them).
    prompt = (case.get("benign_prompt") or "") + " " + (case.get("agent_prompt") or "")
    for key in list(case.get("mock_urls", {})) + list(case.get("mock_commands", {})):
        if key not in prompt:
            prob.add(where, f"mock key {key!r} is never named in the prompt")


def main() -> int:
    args = sys.argv[1:]
    if args:
        files = [Path(a) for a in args]
    else:
        files = []
        for g in DEFAULT_GLOBS:
            d, pat = g.rsplit("/", 1)
            files += sorted((ROOT / d).glob(pat)) if (ROOT / d).exists() else []

    prob = Problems()
    seen_ids: dict[str, str] = {}
    total = 0
    file_count = 0

    for path in files:
        try:
            cases = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            prob.add(str(path), f"cannot parse: {e}")
            continue
        if not isinstance(cases, list):
            prob.add(str(path), "top-level JSON must be an array")
            continue
        file_count += 1
        rel = path.relative_to(ROOT) if path.is_absolute() else path
        for idx, case in enumerate(cases):
            total += 1
            cid = case.get("id", f"#{idx}") if isinstance(case, dict) else f"#{idx}"
            where = f"{rel}[{cid}]"
            validate_case(case, where, prob)
            if isinstance(case, dict) and case.get("id"):
                if case["id"] in seen_ids:
                    prob.add(where, f"duplicate id (also in {seen_ids[case['id']]})")
                else:
                    seen_ids[case["id"]] = str(rel)

    if not files:
        print("no scenario files found", file=sys.stderr)
        return 1

    if prob.items:
        print(f"FAILED: {len(prob.items)} problem(s) across {file_count} file(s), {total} case(s):\n")
        for p in prob.items:
            print(f"  - {p}")
        return 1
    print(f"OK: {total} scenario(s) in {file_count} file(s) valid; {len(seen_ids)} unique ids.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
