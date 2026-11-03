# Optional Lockit integration

[Lockit](https://github.com/Ishaannarang22/lockit) manages encrypted developer
secrets and project admission. Ethos applies runtime policy and output
redaction after a project receives credentials. These address different stages
of the same workflow.

The integration consists of optional launchers plus `.lockit` path protection.
It is not a Rust dependency or a vendored copy. No vault was created, keys
imported, admission granted, or Lockit binary installed during this change.

## Operator setup

Install a reviewed official Lockit release using its
[installation instructions](https://github.com/Ishaannarang22/lockit/blob/master/packages/cli/README.md).
From the Ethos checkout, initialize a project and choose reference-based storage:

```powershell
lockit init
lockit secure on
lockit admit OPENAI_API_KEY
lockit status
pwsh -File scripts/run_with_lockit.ps1 daemon --port 8000
```

Admission is an operator action through Lockit's own gate. Do not automate
approval or supply secret values on the command line. On Unix:

```sh
sh scripts/run_with_lockit.sh daemon --port 8000
```

Both wrappers invoke `lockit run -- cargo run -- ...` from this checkout and
propagate the child exit status. They refuse a missing Lockit installation or
project configuration. They do not initialize, admit or silently fall back to
plaintext credentials. Actual vault/biometric interoperability requires an
installed Lockit and has not been exercised here.

## What is protected

Ethos now treats `.lockit` paths, including `key`, `store.json` and project
`vault.json`, as sensitive. Agent reads, writes, and literal exec references
are denied. The value-free admission map is still authorization metadata.
The new regression suite uses dummy local files; it does not inspect your
real vault.

## Limits and the next isolation improvement

Lockit's default mode may materialize plaintext in `.env`; secure mode uses
references resolved by `lockit run`. The child process necessarily receives
the admitted values. Ethos currently launches local exec children in the host
user context in explicitly unconfined Rust test/baseline adapters. The
application now rejects that backend; commands default to disabled, with an
optional disposable [Docker boundary](container-execution.md). The raw adapters
still lack OS confinement and must not be used as a credential security boundary.
Masked terminal output alone cannot prevent credential misuse or network
transmission. Keep credentials least-privilege and move toward a credential
broker outside the agent's execution context and enforced process isolation.

See Lockit's own [threat model](https://github.com/Ishaannarang22/lockit/blob/master/docs/threat-model.md)
for platform-specific gates and limits. Cite Lockit as an optional integration,
not as evidence that Ethos has complete secret isolation.
