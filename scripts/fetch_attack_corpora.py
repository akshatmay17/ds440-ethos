#!/usr/bin/env python3
"""Fetch revision-pinned public benchmark data, without executing upstream code."""
import argparse
import hashlib
import json
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INJEC_REV = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
HACK_REV = "25b87fbedfb86840abaf8cd09af7a029208a971a"
HIJACK_REV = "1191fcef2b43985987424b5f73aa36603a8233a3"


def agenthijack_inventory(output):
    archive = output / "agenthijack" / f"{HIJACK_REV}.zip"
    entry = fetch(f"https://codeload.github.com/tmlr-group/AgentHijack/zip/{HIJACK_REV}", archive)
    tasks, files = [], []
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            relative = Path(*Path(member.filename).parts[1:])
            name = relative.as_posix()
            if not (name in ("README.md", "config/default.yaml", "LICENSE", "LICENCE") or
                    (name.startswith("evaluation_examples/examples/") and name.endswith(".json"))):
                continue
            destination = output / "agenthijack" / "verified" / relative
            if not destination.resolve().is_relative_to((output / "agenthijack" / "verified").resolve()):
                raise ValueError("unsafe archive member")
            content = source.read(member)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            files.append({"path": name, "sha256": hashlib.sha256(content).hexdigest()})
            if name.endswith(".json"):
                row = json.loads(content)
                tasks.append({"path": name, "id": row.get("id")})
    return {"repository": "https://github.com/tmlr-group/AgentHijack", "revision": HIJACK_REV,
            "archive": entry, "task_definitions": len(tasks), "tasks": tasks, "files": files,
            "corruptions": ["pop_ups", "resolution", "marks", "subtitle", "multi_apps",
                            "accidental_touch", "app_minimization", "network_error", "verification"],
            "execution_status": "not_run_requires_OSWorld_VM_and_GUI_agent",
            "local_named_cases_mapping": "unverified; local ten text cases are not these desktop tasks"}


def fetch(url, path):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".partial")
        with urllib.request.urlopen(url, timeout=120) as response, temporary.open("wb") as out:
            while block := response.read(1024 * 1024):
                out.write(block)
        temporary.replace(path)
    with path.open("rb") as f:
        checksum = hashlib.file_digest(f, "sha256").hexdigest()
    return {"url": url, "path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size, "sha256": checksum}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=ROOT / "data/upstream")
    ap.add_argument("--agenthijack", action="store_true", help="also fetch and inventory pinned desktop task definitions")
    args = ap.parse_args()
    entries = []
    for name in ["test_cases_dh_base.json", "test_cases_ds_base.json", "test_cases_dh_enhanced.json", "test_cases_ds_enhanced.json", "../LICENCE"]:
        local = "LICENSE" if name == "../LICENCE" else name
        url = f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{INJEC_REV}/" + ("LICENCE" if name == "../LICENCE" else f"data/{name}")
        entry = fetch(url, args.output / "injecagent" / local)
        if local.endswith(".json"):
            entry["records"] = len(json.loads((ROOT / entry["path"]).read_text(encoding="utf-8")))
        entries.append(entry)
    for name in ["hackaprompt.parquet", "README.md"]:
        url = f"https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset/resolve/{HACK_REV}/{name}"
        try:
            entry = fetch(url, args.output / "hackaprompt" / name)
        except urllib.error.HTTPError as error:
            entries.append({"url": url, "status": "unavailable", "http_status": error.code})
            continue
        if name.endswith(".parquet"):
            import pyarrow.parquet as pq
            entry["records"] = pq.ParquetFile(ROOT / entry["path"]).metadata.num_rows
        entries.append(entry)
    report = {"injecagent_revision": INJEC_REV, "hackaprompt_revision": HACK_REV, "files": entries,
              "notes": ["Base/enhanced are variants of underlying InjecAgent tasks, not independent tasks.",
                        "AgentHijack is tmlr-group/AgentHijack; desktop corruption tasks are not text injection rows.",
                        "Record counts, unique payload counts and executable attack scenarios are different denominators."]}
    if args.agenthijack:
        report["agenthijack"] = agenthijack_inventory(args.output)
    destination = ROOT / "reports/upstream_corpus_manifest.json"
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
