#!/usr/bin/env python3
"""LM Studio data generation for SemanticGuard training.

Uses a local LM Studio server (OpenAI-compatible API, default
http://localhost:1234/v1) to synthesize training text:

  --kind benign-agent     benign agent-context tasks/files (hard negatives)
  --kind hard-negative    security docs / configs that *discuss* injection
  --kind paraphrase-attack  paraphrases of the in-repo Ethos attack corpus
                             (positives that keep the injection intent)

Output: JSONL {"text", "label", "source"} appended to --out
(default data/semantic_guard/generated.jsonl), labels matching the 3-class
scheme (0=BENIGN, 1=INJECTION, 2=JAILBREAK) so prepare_semantic_dataset.py
can merge the file via --extra.

Requires only the standard library. Run when the GPU is free.

Usage:
  python scripts/generate_semantic_data_lmstudio.py --kind benign-agent --count 200 \
      --model deepseek-r1 --out data/semantic_guard/generated_benign.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INJECTION_DIR = ROOT / "data" / "injections"

BENIGN, INJECTION, JAILBREAK = 0, 1, 2

SYSTEM_PROMPT = (
    "You are a dataset generator for a prompt-injection classifier. "
    "Return ONLY a JSON array of strings. No prose, no markdown fences."
)

PROMPTS = {
    "benign-agent": (
        "Generate {n} diverse, realistic benign task snippets a coding agent might receive: "
        "user instructions, commit messages, README excerpts, code comments, log lines, "
        "configuration text. Some may mention security topics (env files, API keys, curl, "
        "tests) in a NORMAL, non-adversarial way. Output JSON array of {n} strings."
    ),
    "hard-negative": (
        "Generate {n} realistic security documentation or configuration excerpts that MENTION "
        "prompt injection, exfiltration, .env files, curl commands, or credentials in a benign, "
        "descriptive way (documentation, tutorials, changelogs, policy text, example configs). "
        "These must NOT contain actual instructions to attack. Output JSON array of {n} strings."
    ),
    "paraphrase-attack": (
        "Paraphrase each of the following prompt-injection payloads, preserving the adversarial "
        "intent (instruction override, exfiltration, or goal displacement) while varying wording, "
        "tone, formatting, and framing. Output JSON array of {n} strings — the paraphrases.\n\n"
        "PAYLOADS:\n{seeds}"
    ),
}


def post_chat(base_url: str, model: str, messages: list[dict], temperature: float) -> str:
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=600) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body["choices"][0]["message"]["content"]


def parse_string_array(text: str) -> list[str]:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        text = text[text.find("["):] if "[" in text else text
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    return [s.strip() for s in data if isinstance(s, str) and len(s.strip()) >= 8]


def load_attack_seeds(limit: int) -> list[str]:
    seeds = []
    for path in sorted(INJECTION_DIR.glob("*.json")):
        try:
            for case in json.loads(path.read_text(encoding="utf-8")):
                poison = str(case.get("poisoned_content", "")).strip()
                if len(poison) >= 20:
                    seeds.append(poison)
        except Exception:  # noqa: BLE001
            continue
    return seeds[:limit]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="http://localhost:1234/v1")
    ap.add_argument("--model", default="deepseek-r1")
    ap.add_argument("--kind", choices=tuple(PROMPTS), required=True)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--batch", type=int, default=10, help="examples per request")
    ap.add_argument(
        "--out", type=Path,
        default=ROOT / "data" / "semantic_guard" / "generated.jsonl",
    )
    ap.add_argument("--temperature", type=float, default=0.9)
    args = ap.parse_args()

    label = {"benign-agent": BENIGN, "hard-negative": BENIGN, "paraphrase-attack": INJECTION}[args.kind]
    seeds = load_attack_seeds(8) if args.kind == "paraphrase-attack" else []
    if args.kind == "paraphrase-attack" and not seeds:
        raise SystemExit("no attack seeds found in data/injections")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    attempts = 0
    with args.out.open("a", encoding="utf-8") as f:
        while written < args.count and attempts < args.count:
            attempts += 1
            n = min(args.batch, args.count - written)
            user = PROMPTS[args.kind].format(n=n, seeds="\n---\n".join(seeds))
            try:
                reply = post_chat(
                    args.base_url, args.model,
                    [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": user}],
                    args.temperature,
                )
            except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
                print(f"  ! request failed ({e}); is LM Studio serving {args.base_url}?", file=sys.stderr)
                break
            items = parse_string_array(reply)
            if not items:
                print("  ! could not parse model output; retrying…", file=sys.stderr)
                continue
            for text in items[:n]:
                f.write(json.dumps({
                    "text": text,
                    "label": label,
                    "source": f"lmstudio:{args.model}:{args.kind}",
                }, ensure_ascii=False) + "\n")
                written += 1
            print(f"  + {written}/{args.count}")

    print(f"wrote {written} records -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
