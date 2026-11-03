#!/usr/bin/env python3
"""Turn `ethos eval` reports into paper tables.

Reads one or more report JSON files (globs are fine, quoted or not) and prints
one row per (dataset, provider, model, condition, variant):

  attack runs, payload read %, attempted %, attack success rate (ASR) with a
  Wilson 95% CI, blocked %, benign false-positive rate with a Wilson CI,
  benign utility %, capability utility %, utility under attack %, and the
  number of invalid runs.

Rules (docs/eval-scenario-schema.md section 3):
  * Runs with `valid == false` are excluded from every denominator. Their
    count is shown in the "Invalid" column.
  * Reports with `"driver": "scripted"` are refused unless you pass
    --include-scripted. Those rows are then marked "SCRIPTED – not a model result".
  * Legacy v1 reports (no `schema_version`) produce a warning row that carries
    only the blocked-case counts, with the note "legacy: driver unknown".
  * Adaptive rounds (`adaptive_round` > 0) of one (scenario, trial, variant,
    condition) are collapsed into one attack unit. The attack counts as
    attempted, succeeded or read if any round did, and as blocked only if
    some round was blocked and none succeeded. Utility is taken from round 0.
    Use --per-round to count every round separately.

Denominators: payload read %, attempted %, ASR and blocked % use valid attack
units. FPR uses valid benign runs. Utility % uses the runs whose `utility_ok`
is not null.

Usage:
  python3 scripts/make_tables.py reports/*_results.json
  python3 scripts/make_tables.py 'reports/run_*.json' --by-source
  python3 scripts/make_tables.py r1.json r2.json --label injecagent --label benign --csv -o t.csv
  python3 scripts/make_tables.py reports/x.json --latex

Stdlib only.
"""

from __future__ import annotations

import argparse
import csv
import glob
import io
import json
import math
import re
import sys
from pathlib import Path

Z95 = 1.959963984540054
SCRIPTED_NOTE = "SCRIPTED – not a model result"
LEGACY_NOTE = "legacy: driver unknown"


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float] | None:
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def rate(k: int, n: int) -> float | None:
    return k / n if n else None


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def expand_inputs(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pat in patterns:
        matches = sorted(glob.glob(pat)) if any(c in pat for c in "*?[") else [pat]
        if not matches:
            print(f"warning: no file matches {pat!r}", file=sys.stderr)
        for m in matches:
            p = Path(m)
            if p.suffix == ".jsonl" or p.name.endswith(".traces.jsonl"):
                continue
            if p not in paths:
                paths.append(p)
    return paths


def dataset_label(path: Path) -> str:
    name = path.name[:-5] if path.name.endswith(".json") else path.name
    name = re.sub(r"(_eval)?_results$", "", name)
    return name or path.stem


def truthy(v) -> bool:
    return bool(v) and v not in ("false", "False", 0)


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

class Bucket:
    __slots__ = ("attack", "read", "attempted", "succeeded", "blocked",
                 "benign", "fp", "benign_util_ok", "benign_util_n",
                 "cap", "cap_util_ok", "cap_util_n", "uua_ok", "uua_n", "invalid")

    def __init__(self):
        for s in self.__slots__:
            setattr(self, s, 0)


def collapse_adaptive(results: list[dict], default_condition: str) -> list[dict]:
    """Merge adaptive rounds of the same attack unit (see module docstring)."""
    units: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    passthrough: list[dict] = []
    for r in results:
        if r.get("kind", "attack") != "attack":
            passthrough.append(r)
            continue
        key = (r.get("scenario_id"), r.get("trial", 0), r.get("variant"),
               r.get("condition", default_condition))
        if key not in units:
            units[key] = []
            order.append(key)
        units[key].append(r)

    merged: list[dict] = []
    for key in order:
        rounds = units[key]
        if len(rounds) == 1:
            merged.append(rounds[0])
            continue
        valid = [r for r in rounds if r.get("valid", True) is not False]
        if not valid:
            merged.append(dict(rounds[0], valid=False, _invalid_rounds=len(rounds)))
            continue
        base = min(valid, key=lambda r: r.get("adaptive_round") or 0)
        out = dict(base)
        for f in ("payload_read", "attack_attempted", "attack_succeeded", "attack_blocked"):
            out[f] = any(truthy(r.get(f)) for r in valid)
        # A unit is "blocked" only if no round got through.
        out["attack_blocked"] = out["attack_blocked"] and not out["attack_succeeded"]
        out["_invalid_rounds"] = len(rounds) - len(valid)
        merged.append(out)
    return passthrough + merged


def add_result(b: Bucket, r: dict) -> None:
    invalid_rounds = int(r.get("_invalid_rounds", 0) or 0)  # set by collapse_adaptive
    if r.get("valid", True) is False:
        b.invalid += invalid_rounds or 1
        return
    b.invalid += invalid_rounds
    kind = r.get("kind", "attack")
    util = r.get("utility_ok")
    if kind == "attack":
        b.attack += 1
        b.read += truthy(r.get("payload_read"))
        b.attempted += truthy(r.get("attack_attempted"))
        b.succeeded += truthy(r.get("attack_succeeded"))
        b.blocked += truthy(r.get("attack_blocked"))
        if util is not None:
            b.uua_n += 1
            b.uua_ok += truthy(util)
    elif kind == "benign":
        b.benign += 1
        b.fp += truthy(r.get("false_positive"))
        if util is not None:
            b.benign_util_n += 1
            b.benign_util_ok += truthy(util)
    elif kind == "capability":
        b.cap += 1
        if util is not None:
            b.cap_util_n += 1
            b.cap_util_ok += truthy(util)


def rows_for_v2(report: dict, label: str, by_source: bool, per_round: bool, scripted: bool) -> list[dict]:
    provider = str(report.get("provider", "?"))
    model = str(report.get("model", "?"))
    condition = str(report.get("condition", "?"))
    variant = str(report.get("variant", "?"))
    results = report.get("results") or []
    if not per_round:
        results = collapse_adaptive(results, condition)

    groups: dict[tuple, Bucket] = {}
    sources: dict[tuple, dict[str, Bucket]] = {}
    for r in results:
        key = (label, provider, model, str(r.get("condition", condition)), str(r.get("variant") or variant))
        b = groups.setdefault(key, Bucket())
        add_result(b, r)
        if by_source and r.get("kind", "attack") == "attack":
            src = str(r.get("source") or "?")
            add_result(sources.setdefault(key, {}).setdefault(src, Bucket()), r)

    note = SCRIPTED_NOTE if scripted else ""
    rows = []
    for key in sorted(groups):
        rows.append(make_row(key, groups[key], "(all)" if by_source else None, note, attack_only=False))
        if by_source:
            for src in sorted(sources.get(key, {})):
                rows.append(make_row(key, sources[key][src], src, note, attack_only=True))
    return rows


def make_row(key: tuple, b: Bucket, source: str | None, note: str, attack_only: bool) -> dict:
    label, provider, model, condition, variant = key
    row = {
        "dataset": label, "provider": provider, "model": model,
        "condition": condition, "variant": variant,
        "attack_runs": b.attack,
        "payload_read": b.read, "attempted": b.attempted,
        "succeeded": b.succeeded, "blocked": b.blocked,
        "benign_runs": None if attack_only else b.benign,
        "false_positive": None if attack_only else b.fp,
        "benign_util_ok": None if attack_only else b.benign_util_ok,
        "benign_util_n": None if attack_only else b.benign_util_n,
        "cap_runs": None if attack_only else b.cap,
        "cap_util_ok": None if attack_only else b.cap_util_ok,
        "cap_util_n": None if attack_only else b.cap_util_n,
        "uua_ok": b.uua_ok, "uua_n": b.uua_n,
        "invalid": b.invalid,
        "note": note,
        "legacy": False,
    }
    if source is not None:
        row["source"] = source
    return row


def legacy_row(report: dict, label: str, by_source: bool) -> dict:
    results = report.get("results") or []
    blocked = report.get("defense_violations_blocked")
    if blocked is None:
        blocked = sum(1 for r in results if truthy(r.get("exfiltration_blocked")))
    row = {
        "dataset": label,
        "provider": str(report.get("provider", "?")),
        "model": str(report.get("model", "?")),
        "condition": "?", "variant": "?",
        "total": report.get("total_scenarios", len(results)),
        "legacy_blocked": blocked,
        "legacy_refused": report.get("defense_refused"),
        "note": LEGACY_NOTE,
        "legacy": True,
    }
    if by_source:
        row["source"] = "(all)"
    return row


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def pct(k, n) -> str:
    if n is None or k is None or not n:
        return "–"
    return f"{100.0 * k / n:.1f}"


def pct_ci(k, n) -> str:
    if n is None or k is None or not n:
        return "–"
    lo, hi = wilson(k, n)
    return f"{100.0 * k / n:.1f} [{100 * lo:.1f}, {100 * hi:.1f}] ({k}/{n})"


HEADERS = ["Dataset", "Provider", "Model", "Condition", "Variant", "Attack runs",
           "Payload read %", "Attempted %", "ASR % [95% CI]", "Blocked %",
           "Benign FPR % [95% CI]", "Benign utility %", "Capability utility %",
           "Utility under attack %", "Invalid", "Note"]


def display_cells(row: dict, by_source: bool) -> list[str]:
    head = [row["dataset"], row["provider"], row["model"], row["condition"], row["variant"]]
    if by_source:
        head.append(row.get("source", ""))
    if row["legacy"]:
        refused = row.get("legacy_refused")
        blocked = f"{row['legacy_blocked']}/{row['total']} blocked"
        if refused is not None:
            blocked += f", {refused} refused"
        return head + [f"{row['total']} cases", "–", "–", "–", blocked, "–", "–", "–", "–", "–", row["note"]]
    a = row["attack_runs"]
    return head + [
        str(a),
        pct(row["payload_read"], a),
        pct(row["attempted"], a),
        pct_ci(row["succeeded"], a),
        pct(row["blocked"], a),
        pct_ci(row["false_positive"], row["benign_runs"]),
        pct(row["benign_util_ok"], row["benign_util_n"]),
        pct(row["cap_util_ok"], row["cap_util_n"]),
        pct(row["uua_ok"], row["uua_n"]),
        str(row["invalid"]),
        row["note"],
    ]


def headers(by_source: bool) -> list[str]:
    h = list(HEADERS)
    if by_source:
        h.insert(5, "Source")
    return h


def render_markdown(rows: list[dict], by_source: bool) -> str:
    h = headers(by_source)
    lines = ["| " + " | ".join(h) + " |", "|" + "|".join("---" for _ in h) + "|"]
    for row in rows:
        cells = [c.replace("|", "\\|") for c in display_cells(row, by_source)]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


CSV_FIELDS = ["dataset", "provider", "model", "condition", "variant", "source",
              "attack_runs", "payload_read", "attempted", "succeeded", "asr", "asr_ci_low", "asr_ci_high",
              "blocked", "benign_runs", "false_positive", "fpr", "fpr_ci_low", "fpr_ci_high",
              "benign_util_ok", "benign_util_n", "cap_runs", "cap_util_ok", "cap_util_n",
              "uua_ok", "uua_n", "invalid", "legacy_total", "legacy_blocked", "legacy_refused", "note"]


def render_csv(rows: list[dict], by_source: bool) -> str:
    buf = io.StringIO()
    fields = [f for f in CSV_FIELDS if by_source or f != "source"]
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for row in rows:
        out = dict(row)
        if row["legacy"]:
            out["legacy_total"] = row["total"]
        else:
            for name, k, n in (("asr", row["succeeded"], row["attack_runs"]),
                               ("fpr", row["false_positive"], row["benign_runs"])):
                ci = wilson(k, n) if n else None
                out[name] = f"{k / n:.4f}" if n else ""
                out[f"{name}_ci_low"] = f"{ci[0]:.4f}" if ci else ""
                out[f"{name}_ci_high"] = f"{ci[1]:.4f}" if ci else ""
        w.writerow({k: ("" if v is None else v) for k, v in out.items()})
    return buf.getvalue()


def latex_escape(s: str) -> str:
    repl = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#",
            "_": r"\_", "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\^{}",
            "–": "--"}
    return "".join(repl.get(ch, ch) for ch in s)


def render_latex(rows: list[dict], by_source: bool) -> str:
    h = headers(by_source)
    cols = "l" * (6 if by_source else 5) + "r" * (len(h) - (6 if by_source else 5) - 1) + "l"
    out = [r"\begin{tabular}{" + cols + "}", r"\toprule",
           " & ".join(latex_escape(x) for x in h) + r" \\", r"\midrule"]
    for row in rows:
        out.append(" & ".join(latex_escape(c) for c in display_cells(row, by_source)) + r" \\")
    out += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(out)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("reports", nargs="+", help="report JSON paths or globs")
    ap.add_argument("--label", action="append", default=[],
                    help="dataset label (once for all inputs, or once per input in order); "
                         "default: derived from the filename")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--csv", action="store_true", help="CSV output (raw counts, rates and CIs)")
    fmt.add_argument("--latex", action="store_true", help="LaTeX tabular output (booktabs)")
    ap.add_argument("-o", "--output", type=Path, help="write to this file instead of stdout")
    ap.add_argument("--include-scripted", action="store_true",
                    help="include driver=scripted reports (rows are marked as not model results)")
    ap.add_argument("--by-source", action="store_true", help="break attack rows down by result source")
    ap.add_argument("--per-round", action="store_true", help="do not collapse adaptive rounds")
    args = ap.parse_args()

    paths = expand_inputs(args.reports)
    if not paths:
        print("error: no input reports", file=sys.stderr)
        return 2
    if len(args.label) not in (0, 1, len(paths)):
        ap.error(f"--label given {len(args.label)} times for {len(paths)} input files")

    rows: list[dict] = []
    refused = 0
    for i, path in enumerate(paths):
        label = (args.label[i] if len(args.label) == len(paths) and len(paths) > 1
                 else args.label[0] if args.label else dataset_label(path))
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"warning: skip {path}: {e}", file=sys.stderr)
            continue
        if not isinstance(report, dict) or not isinstance(report.get("results"), list):
            print(f"warning: skip {path}: not an ethos eval report (no results[] list)", file=sys.stderr)
            continue
        version = report.get("schema_version")
        if version is None:
            print(f"warning: {path} is a legacy v1 report ({LEGACY_NOTE}); only blocked-case counts shown",
                  file=sys.stderr)
            rows.append(legacy_row(report, label, args.by_source))
            continue
        if int(version) != 2:
            print(f"warning: skip {path}: unsupported schema_version {version}", file=sys.stderr)
            continue
        scripted = str(report.get("driver", "")).lower() == "scripted"
        if scripted and not args.include_scripted:
            print(f"refused: {path} was produced by the scripted driver (not a model result); "
                  f"pass --include-scripted to show it anyway", file=sys.stderr)
            refused += 1
            continue
        if report.get("driver") is None:
            print(f"warning: {path} has no 'driver' field", file=sys.stderr)
        rows.extend(rows_for_v2(report, label, args.by_source, args.per_round, scripted))

    if not rows:
        print("error: nothing to tabulate" + (f" ({refused} scripted report(s) refused)" if refused else ""),
              file=sys.stderr)
        return 1

    if args.csv:
        text = render_csv(rows, args.by_source)
    elif args.latex:
        text = render_latex(rows, args.by_source)
    else:
        text = render_markdown(rows, args.by_source)
        text += ("\n\nASR, blocked %, attempted % and payload read % are over valid attack runs "
                 "(adaptive rounds collapsed" + (", disabled by --per-round" if args.per_round else "")
                 + "). FPR is over valid benign runs. Utility % is over runs where utility was measured. "
                 "CIs are Wilson 95%. Invalid runs are excluded from every denominator.")
    if args.output:
        args.output.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
