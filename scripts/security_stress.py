#!/usr/bin/env python3
"""Run Rust component attack suites and save per-test outcomes. No LLM needed."""
import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUITES = {
    "filesystem_alias_boundary": "test_rust_file_aliases",
    "agent_loop_final_output": "test_rust_agent_loop",
    "instruction_memory_lockit": "test_rust_modern_attacks",
    "exec_paths_unicode": "test_rust_redteam3",
    "daemon_policy_secrets": "test_rust_redteam2",
    "taint_egress_rewind": "test_rust_redteam",
    "redaction": "test_rust_redaction",
    "agent_secret_visibility": "test_rust_secret_visibility",
    "provenance": "test_rust_advanced_taint",
    "state_tree": "test_rust_state_tree",
    "snapshot_tools": "test_rust_aci_tools",
    "daemon": "test_rust_api_server",
    "session_schema": "test_rust_postgres_store",
    "semantic_smoke": "test_rust_semantic_guard",
    "synthetic_regression": "test_rust_synthetic_engine",
    "walls": "test_rust_walls",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=ROOT / "reports/security_stress.json")
    ap.add_argument("--timeout", type=int, default=300, help="seconds per suite, including compilation")
    args = ap.parse_args()
    report = {"created_at": datetime.now(timezone.utc).isoformat(),
              "git_rev": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "mode": "deterministic_component_regressions", "suites": [],
              "limitations": ["Not live-agent attack success or exhaustive component coverage",
                              "Postgres suite checks schema only; no live database isolation test",
                              "semantic smoke tests do not prove neural checkpoint behavior",
                              "gVisor, installers, real MCP servers and multimodal input are not exercised"]}
    failed = False
    for component, suite in SUITES.items():
        command = ["cargo", "test", "--test", suite, "--", "--color", "never"]
        try:
            run = subprocess.run(command, cwd=ROOT, text=True, encoding="utf-8", errors="replace",
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=args.timeout)
            tests = [{"name": n, "outcome": outcome} for n, outcome in
                     re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)[^\n]*$", run.stdout, re.MULTILINE)]
            entry = {"component": component, "suite": suite, "command": command,
                     "exit_code": run.returncode, "tests": tests, "output": run.stdout}
            failed |= run.returncode != 0 or not tests
        except subprocess.TimeoutExpired:
            entry = {"component": component, "suite": suite, "error": "timeout", "tests": []}
            failed = True
        report["suites"].append(entry)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"{suite}: {len(entry['tests'])} tests; exit={entry.get('exit_code', 'timeout')}", flush=True)
    counts = {}
    for suite in report["suites"]:
        for test in suite["tests"]:
            counts[test["outcome"]] = counts.get(test["outcome"], 0) + 1
    report["counts"] = counts
    report["passed"] = not failed
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(counts), f"report={args.output}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
