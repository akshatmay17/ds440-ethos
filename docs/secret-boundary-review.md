# Secret boundary review: adversarial file access

The earlier container tests did not establish complete secret protection.
Reviewing the user's report of a teammate reading `.env` exposed a second,
independent problem in the host-side structured file tools.

## Reproduced before the fix

1. A hard link named `ordinary-notes.txt` pointed to a dummy `.env` file.
   `read` returned `SUCCESS`: the raw requested name passed path policy.
   Redaction hid the fixture value, but the file-access gate had been bypassed.
2. Writing through a harmless hard-link name returned `SUCCESS` and modified
   the same protected file. Redaction cannot prevent this integrity violation.
3. The explicit unconfined library adapter could compute the name `.env`, read
   a dummy file and emit its base64 contents. Exact-value redaction did not
   catch the transformed value. This is now an intentional positive-control
   test, not a successful defense.

All reproductions used temporary directories and dummy canaries. They did not
inspect, print, modify or transmit the user's real secrets.

## Changes

The file boundary rejects multiply linked regular files, symbolic links and
Windows reparse points. It checks each relative path component and rejects
parent traversal, Windows alternate streams, reserved devices and normalized
short-name aliases. Windows hard-link counts are obtained from the opened
file's information; Unix uses filesystem link metadata. File listings omit
unsupported aliases, and snapshot creation refuses hard-linked files rather
than silently omitting them from a purported complete backup.

The application accepts only `disabled` and `docker` execution backends.
`ETHOS_EXEC_BACKEND=local` is rejected. The explicitly unconfined Rust adapters
remain available for component tests and controlled baselines; they are not an
agent-selectable application feature.

Deliberate filesystem denials now return `BLOCKED_BY_POLICY` with the
`FILESYSTEM-BOUNDARY` rule through file tools and daemon routes. Ordinary
missing-file and I/O errors remain `ERROR` and do not count as interceptions.
The circuit breaker records deliberate boundary violations.

## Review of Akshat's change

Commit `0a77ca2` added RT-22 through RT-26 redaction regressions, including
wildcard/computed-name reads, copied values and inherited environment variables.
Those tests demonstrate known-value filtering after a read. They do not establish
that the child process cannot read or encode the source. The unconfined positive
control above captures that distinction.

## Regression evidence

`tests/test_rust_file_aliases.rs` exercises read, write, line views, edit,
grep, fetch-write and the actual daemon read/write routes. Fixtures assert
that protected file contents remain unchanged, not merely that a warning exists.
Platform-specific tests cover Windows stream/device paths or Unix symbolic links.

`live_obfuscated_reads_run_but_cannot_reach_the_fixture_secret` runs six actual
ACI/Docker probes: computed-name `cat`, partial read, base64, hexadecimal output,
wildcard enumeration and a copied-secret file. Each probe must print its execution
marker and return `SUCCESS`; a pre-execution refusal or broken container cannot
pass. The output oracle checks plaintext, base64 and hexadecimal fixture forms.
The filtered container workspace lacks both the protected source and the known
secret-bearing copy.

Run the component suite and live suite separately:

```powershell
cargo test --test test_rust_file_aliases
python scripts/container_stress.py --output reports/secret_boundary_new.json
```

The eleven container-suite checks include five live Docker tests and an
unconfined positive control. They are not eleven independently stopped attacks.

## Limits

This does not establish complete DLP, arbitrary encoding detection, immunity to
kernel/container exploits or safety against a hostile same-user host process
swapping filesystem objects concurrently. File metadata checks and subsequent
I/O are not a fully handle-relative, race-free filesystem implementation.
Unknown or already transformed secrets in ordinary files may evade staging
recognition. A user's ordinary terminal remains outside Ethos's agent boundary.
The pushed redaction change has been inspected; the teammate's exact original
command and route are not recorded there as a standalone reproducer.
See [container limits](container-execution.md).

## Current validation

`reports/secret_boundary_verified_oct15.json` records **16 passing checks**:
eleven container-suite checks (five requiring live Docker) plus five file-alias
regressions. It records source hashes and Docker/image identity.
`reports/security_stress_verified_oct15.json` records **121 passing component
tests across 16 suites**. `cargo check --all-targets` and the default `cargo test`
suite passed. These counts include benign controls and an intentionally successful
unconfined leak; they are not counts of independently stopped attacks.

## MCP and skill boundary

A skill document is untrusted input, while a skill script or STDIO MCP server
can execute native code. Filename policy on `SKILL.md` alone cannot confine that
code. Ethos currently has no implemented MCP server lifecycle boundary; do not
claim MCP isolation from these tests. Future integrations must start outside the
credential-bearing host environment, receive only filtered files, and route
privileged effects through the same checked broker. The subsequent [public MCP lab](mcp-public-evaluation.md) exercises real shadcn
STDIO calls, malicious registry responses, outside-file authority and a restricted
container comparison. Production integration, remote sessions and malicious
executable servers remain untested.

