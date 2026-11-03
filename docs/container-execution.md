# Disposable command execution

Application ACI constructors now default to **execution disabled**. File tools,
snapshots and policy checks still work. An operator can select the new Docker
backend. If Docker, its daemon or the pinned image is unavailable, a command
returns an error; it never falls back to a host process.

## Enable locally

Start a local Linux Docker engine. The supplied Alpine profile is a minimal
shell/probe environment, not a Rust/Python development image. Pull its exact
digest explicitly and configure the parent process:

```powershell
docker pull alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
$env:ETHOS_EXEC_BACKEND = 'docker'
$env:ETHOS_EXEC_IMAGE = 'alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8'
cargo run -- doctor
```

Alternatively copy `config/exec.container.json` to an operator-controlled file
outside every agent workspace, then set `ETHOS_EXEC_CONFIG` to its absolute
path. JSON controls timeout, memory, CPU, PID and retained-output limits.
Unknown fields and invalid limits fail validation. `oci_runtime: "runsc"` can
select a separately configured Docker gVisor runtime; its availability and
security are not established by the default runc tests.

Execution settings, Docker's absolute client path and its client environment
are captured before project `.env` loading. Project `.env` files cannot enable
host execution or change process launch paths. The example JSON in this repo
is a template, not automatically discovered configuration. Embedded library
callers should call `ExecutionSettings::configured()` before loading project
environment files, or supply trusted settings explicitly.

## Command boundary

Each invocation gets a new Linux container with network disabled, all Linux
capabilities dropped, non-root UID/GID 65534, no privilege escalation, a read-only
root filesystem, bounded scratch tmpfs, memory/CPU/PID limits and a wall-clock
timeout. Host arguments are passed as separate arguments to a fixed launcher;
attacker strings are never interpolated into its shell script.

The real workspace is never mounted. A filtered temporary copy is mounted
read-only at `/input`; the container copies it into disposable `/workspace`.
Sensitive paths, known secret-bearing copies, symlinks, Git internals, build
caches and internal provenance/snapshot files are excluded. Staging is limited
to 16 MiB per file and 64 MiB total. Credential recognition remains bounded;
unknown secrets in ordinary files may be staged.

Commands can compile or modify their disposable copy, but **those filesystem
changes are discarded**. Use ACI write/edit tools for durable source changes.
Preinstall required compilers/dependencies in a reviewed image and pin its
digest; runtime dependency downloads cannot work with networking disabled.

Scratch commands can run after external reads. Their results are marked
untrusted and persisted in the provenance ledger. Host execution retains the
existing taint restrictions. Explicit network, sensitive-path and instruction
guards still apply. Observations and command audit events identify the actual
backend, e.g. `docker_disposable` or `exec_disabled`.

The application rejects the `local` backend. `new_local_with_*` library
constructors remain explicitly unconfined component-test/baseline adapters;
they must not be reported as sandboxed execution. A positive control now
demonstrates encoded dummy-secret leakage through that adapter.
Component regression tests deliberately select these adapters or inert runtimes;
the separate live suite checks the real configured container route.

## Verify

```powershell
python scripts/container_stress.py --output reports/container_check_new.json
cargo check --all-targets
cargo test
```

The live script checks daemon/image availability, records source hashes and
engine/image identity, and runs all eleven container regressions plus the five
file-alias regressions, including ignored live tests. Missing infrastructure
is a failure, never a successful defense.
CI pulls the pinned image and runs the same suite. Tests cover configured ACI
routing, output taint/reload, secret staging, non-root execution, read-only
mounts, absent host mounts/socket, denied egress, discarded writes, limits and
failure without fallback. They do not prove resistance to container/kernel
exploits, malicious Docker daemons, every output channel or GUI/MCP attacks.

Docker's daemon and selected image remain trusted infrastructure. A remote
Docker context is outside this local bind-mount deployment profile. This change
does not isolate the host-side file-fetch client, model endpoint or daemon API.
See [Docker's run reference](https://docs.docker.com/reference/cli/docker/container/run/)
and the [remaining attack surfaces](attack-surface-coverage.md).

The [secret-boundary follow-up](secret-boundary-review.md) records a reproduced
hard-link read/write bypass, its filesystem fix, and six actual obfuscated-read
probes. A passing test count is bounded regression evidence, not a blanket
security claim.
