# Public MCP server evaluation

The October 15 lab exercised the official **shadcn MCP server, package 4.21.5**,
using real STDIO JSON-RPC initialization, tool discovery and calls. It did not
install a server into the user's global MCP configuration or use real credentials.
The upstream [MCP documentation](https://ui.shadcn.com/docs/mcp) describes its
registry tools. The package is MIT licensed; see [references](references.md).

## Observed behavior

| Probe | Observed result | Meaning |
| --- | --- | --- |
| Retrieve official `@shadcn/button` | Returned component type, files and dependencies | Real public service utility control |
| Retrieve local malicious registry item | Attacker description reached the MCP tool result | Registry text remains an indirect injection surface; receiving text alone is not compromise |
| Native server views `../private-record.json` | Returned a dummy canary from outside its project directory | A process working directory is not a filesystem sandbox |
| Suggest installation for an item containing `; echo MCP_COMMAND_MARKER` | Shell syntax appeared unchanged in the returned command | The tool returns text; an agent must not automatically authorize its execution |
| Invalid arguments and unknown tool | Returned tool/protocol errors | Ordinary failures, not attacks stopped |
| Real server inside restricted Docker container | Initialized and answered its audit-checklist tool | Isolation did not merely prevent startup |
| Same outside-file request inside container | Returned a local-file error, no canary | Private host fixture was never mounted |
| Registry HTTP request inside offline container | Failed | Offline isolation also removes online registry utility |

The native outside-file read is an **intentionally successful positive control**.
It demonstrates deployment authority, not an upstream vulnerability claim.
The test also inspects the running container: network mode `none`, read-only
root and input mounts, UID/GID 65534, dropped capabilities, 512 MiB memory and
64-process limit. It uses a digest-pinned Node image, never a Docker socket mount.

## Ethos follow-up checks

The actual malicious MCP response was adapted into an untrusted external file
for the existing Rust ACI campaign worker. Six forced follow-up actions were
denied: instruction overwrite, memory overwrite, skill overwrite, `.env` read,
tainted network egress and a secret-reading shell command. The outcome oracle
also checked that protected files did not change. Exec and network effects in
that worker are inert.

These are policy replays, **not live LLM attacks**. They do not measure whether
an agent would follow the injected instruction, and are not an end-to-end MCP
integration with production Ethos.

## Reproduce

Node, Cargo, Python and a local Linux Docker engine are required. Dependency
lifecycle scripts are disabled. The committed npm lock pins transitive packages.

```powershell
New-Item -ItemType Directory -Force data/upstream/mcp-shadcn
Copy-Item config/mcp-lab/package*.json data/upstream/mcp-shadcn/
npm.cmd ci --prefix data/upstream/mcp-shadcn --ignore-scripts --no-audit --no-fund
cargo build --release --example campaign_worker
docker pull node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
python scripts/mcp_public_stress.py --container-image node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 --output reports/mcp_new.json
python -m unittest discover -s tests -p test_mcp_public_stress.py
```

Use a fresh report filename. The report retains raw responses, source/lock/worker
hashes, container configuration and per-check interpretations. Earlier reports
remain preserved, including the failed initial Windows absolute-path probe and
the first container launch with an incorrect module mount path.

## Remaining boundary

The restricted persistent STDIO launcher is an **experimental test-lab launcher**.
Production Ethos still has no MCP transport, server lifecycle broker, schema
change approval or OAuth/session implementation. Online registries need a
narrow network broker; simply enabling general container egress would weaken
this offline boundary. This evaluation does not cover compromised dependencies,
container escapes, tool-schema replacement, remote OAuth or hostile skill scripts.
