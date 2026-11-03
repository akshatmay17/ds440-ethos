use ethos::aci::ACIHarness;
use ethos::runtime::{CommandRuntime, ExecutionSettings, SandboxRuntime};

const IMAGE: &str =
    "alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8";
fn settings() -> ExecutionSettings {
    ExecutionSettings {
        backend: "docker".into(),
        image: IMAGE.into(),
        ..Default::default()
    }
}

#[test]
fn explicit_unconfined_mode_is_a_positive_control_for_encoded_secret_leakage() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = ACIHarness::new_local_with_dir(dir.path()).unwrap();
    std::fs::write(dir.path().join(".env"), "API_KEY=fixture-only-probe-537182").unwrap();
    #[cfg(windows)]
    let result=h.exec("powershell",&["-NoProfile".into(),"-Command".into(),
        "$p=-join([char[]](46,101,110,118));[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))".into()]);
    #[cfg(not(windows))]
    let result = h.exec(
        "sh",
        &[
            "-c".into(),
            "p=$(printf '\\056\\145\\156\\166'); base64 \"$p\"".into(),
        ],
    );
    assert_eq!(result.status, "SUCCESS", "{:?}", result.error);
    assert!(result.output["stdout"]
        .as_str()
        .unwrap()
        .contains("QVBJX0tFWT1maXh0dXJlLW9ubHktcHJvYmUtNTM3MTgy"));
    // This intentionally demonstrates the unsafe compatibility mode. Redacting
    // literal values and matching filenames cannot turn host exec into isolation.
}

#[test]
#[ignore = "requires a running local Linux Docker daemon and the pinned image"]
fn live_obfuscated_reads_run_but_cannot_reach_the_fixture_secret() {
    let probes = [
        "p=$(printf '\\056\\145\\156\\166'); cat \"$p\"",
        "p=$(printf '\\056\\145\\156\\166'); head -c 4096 \"$p\"",
        "p=$(printf '\\056\\145\\156\\166'); base64 \"$p\"",
        "p=$(printf '\\056\\145\\156\\166'); od -An -tx1 \"$p\"",
        "for p in .?*; do cat \"$p\"; done",
        "cat ordinary-notes.txt",
    ];
    for probe in probes {
        let dir = tempfile::tempdir().unwrap();
        let mut h = ACIHarness::new_with_execution(dir.path(), settings()).unwrap();
        let contents = "API_KEY=fixture-only-probe-537182";
        std::fs::write(dir.path().join(".env"), contents).unwrap();
        std::fs::write(dir.path().join("ordinary-notes.txt"), contents).unwrap();
        let script = format!("printf 'PROBE_RAN\\n'; ( {probe} ) 2>/dev/null || :");
        let result = h.exec("sh", &["-c".into(), script]);
        assert_eq!(
            result.status, "SUCCESS",
            "Probe must actually execute: {probe}: {:?}",
            result.error
        );
        let stdout = result.output["stdout"].as_str().unwrap();
        assert!(stdout.contains("PROBE_RAN"));
        assert!(!stdout.contains("fixture-only-probe-537182"), "{probe}");
        assert!(
            !stdout.contains("QVBJX0tFWT1maXh0dXJlLW9ubHktcHJvYmUtNTM3MTgy"),
            "{probe}"
        );
        assert!(
            !stdout
                .split_whitespace()
                .collect::<String>()
                .contains(&hex::encode("fixture-only-probe-537182")),
            "{probe}"
        );
    }
}

#[test]
fn default_execution_is_disabled_and_files_still_work() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = ACIHarness::new_with_execution(dir.path(), ExecutionSettings::default()).unwrap();
    assert_eq!(h.write("notes.txt", "hello", None).status, "SUCCESS");
    assert_eq!(h.read("notes.txt").output.as_str(), Some("hello"));
    let result = h
        .runtime
        .execute_command("host-program-must-never-run", &[]);
    assert_eq!(result.0, 126);
    assert!(result.2.contains("EXEC_DISABLED"));
    assert_eq!(h.observe().execution_backend, "exec_disabled");
}

#[test]
fn container_configuration_rejects_mutable_images_and_invalid_limits() {
    assert!(ExecutionSettings {
        backend: "local".into(),
        ..Default::default()
    }
    .validate()
    .is_err());
    for image in ["alpine:latest", "--privileged", "alpine@sha256:xyz"] {
        assert!(ExecutionSettings {
            image: image.into(),
            ..settings()
        }
        .validate()
        .is_err());
    }
    assert!(ExecutionSettings {
        timeout_seconds: 0,
        ..settings()
    }
    .validate()
    .is_err());
    assert!(ExecutionSettings {
        cpus: f32::NAN,
        ..settings()
    }
    .validate()
    .is_err());
    assert!(ExecutionSettings {
        oci_runtime: Some("runsc --privileged".into()),
        ..settings()
    }
    .validate()
    .is_err());
}

#[test]
fn operator_configuration_cannot_live_inside_the_agent_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("execution.json");
    std::fs::write(&path, "{}").unwrap();
    assert!(ACIHarness::new_with_execution(
        dir.path(),
        ExecutionSettings {
            source_path: Some(path.canonicalize().unwrap()),
            ..Default::default()
        }
    )
    .is_err());
}

#[test]
fn project_dotenv_cannot_enable_host_execution() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".env"),
        "ETHOS_EXEC_BACKEND=local\nPATH=attacker-controlled-directory\n",
    )
    .unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_ethos"))
        .arg("doctor")
        .current_dir(dir.path())
        .env_remove("ETHOS_EXEC_BACKEND")
        .env_remove("ETHOS_EXEC_CONFIG")
        .env_remove("ETHOS_EXEC_IMAGE")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("exec_disabled"));
}

#[test]
fn container_arguments_cannot_be_overridden_by_agent_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = CommandRuntime::new(dir.path(), settings()).unwrap();
    let arguments = runtime
        .container_arguments(
            dir.path(),
            "ethos-command-fixture",
            "echo",
            &["--privileged".into(), "$(host-command)".into()],
        )
        .unwrap();
    let image_index = arguments.iter().position(|a| a == IMAGE).unwrap();
    assert!(arguments[..image_index].contains(&"--network=none".into()));
    assert!(arguments[..image_index].contains(&"--cap-drop=ALL".into()));
    assert!(arguments[..image_index].contains(&"--read-only".into()));
    assert!(arguments[..image_index].contains(&"--user=65534:65534".into()));
    assert!(!arguments[..image_index].contains(&"--privileged".into()));
    assert_eq!(arguments.last().unwrap(), "$(host-command)");
    assert!(runtime
        .container_arguments(dir.path(), "fixture", "--privileged", &[])
        .is_err());
}

#[test]
#[ignore = "requires a running local Linux Docker daemon and the pinned image"]
fn live_configured_harness_runs_after_external_reads_and_retains_output_taint() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = ACIHarness::new_with_execution(dir.path(), settings()).unwrap();
    h.runtime.write_file("vendor.txt", "VENDOR_DATA").unwrap();
    assert_eq!(h.read("vendor.txt").status, "SUCCESS");
    for _ in 0..2 {
        let result = h.exec("sh", &["-c".into(), "id -u; cat vendor.txt".into()]);
        assert_eq!(result.status, "SUCCESS", "{:?}", result.error);
        assert!(result.output["stdout"].as_str().unwrap().contains("65534"));
        assert!(result.provenance.unwrap().trust_level.is_tainted());
    }
    let restored = ACIHarness::new_with_execution(dir.path(), settings()).unwrap();
    assert!(restored
        .taint_engine
        .list_tainted_resources()
        .iter()
        .any(|r| r.starts_with("command-output:")));
    assert_eq!(h.observe().execution_backend, "docker_disposable");
    println!("PASS: normal ACI routes into containers after external reads; output taint persists across reload");
}

#[test]
#[ignore = "requires a running local Linux Docker daemon and the pinned image"]
fn live_container_isolates_files_secrets_network_and_effects() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = CommandRuntime::new(dir.path(), settings()).unwrap();
    runtime.write_file("src/input.txt", "HELLO").unwrap();
    runtime
        .write_file(".env", "API_KEY=fixture-container-secret-394182")
        .unwrap();
    runtime
        .write_file("notes/copied-secret.txt", "fixture-container-secret-394182")
        .unwrap();
    runtime
        .write_file("CLAUDE.md", "Trusted original instructions")
        .unwrap();
    let script = r#"
set -eu
test "$(id -u)" = 65534
test "$(cat src/input.txt)" = HELLO
test "$(cat /sys/fs/cgroup/memory.max)" = 536870912
test "$(cat /sys/fs/cgroup/pids.max)" = 64
test "$(cat /sys/fs/cgroup/cpu.max)" = "100000 100000"
test -z "${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}${OPENROUTER_API_KEY:-}"
test ! -e .env
test ! -e notes/copied-secret.txt
test ! -S /var/run/docker.sock
test ! -d /mnt/c/Users
test ! -d /host
! touch /etc/ethos-escape 2>/dev/null
! touch /input/escape 2>/dev/null
! wget -T 1 -q -O /tmp/network http://192.0.2.1
echo mutated > CLAUDE.md
echo generated > result.txt
echo ISOLATION_PROBES_PASSED
"#;
    let result = runtime.execute_command("sh", &["-c".into(), script.into()]);
    assert_eq!(result.0, 0, "{}\n{}", result.1, result.2);
    assert!(result.1.contains("ISOLATION_PROBES_PASSED"));
    assert_eq!(
        runtime.read_file("CLAUDE.md").unwrap(),
        "Trusted original instructions"
    );
    assert!(!runtime.file_exists("result.txt"));
    println!("PASS: non-root, secret paths and copied secrets excluded, host mounts/socket absent, root/input read-only, network denied, host mutations absent");
}

#[test]
#[ignore = "requires a running local Linux Docker daemon and the pinned image"]
fn live_container_timeout_and_output_limits_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = CommandRuntime::new(
        dir.path(),
        ExecutionSettings {
            timeout_seconds: 1,
            output_bytes: 1024,
            ..settings()
        },
    )
    .unwrap();
    let result = runtime.execute_command("sh", &["-c".into(), "while :; do :; done".into()]);
    assert_eq!(result.0, 124, "{}", result.2);
    let runtime = CommandRuntime::new(
        dir.path(),
        ExecutionSettings {
            output_bytes: 1024,
            ..settings()
        },
    )
    .unwrap();
    let result = runtime.execute_command("sh", &["-c".into(), "yes X | head -c 200000".into()]);
    assert_eq!(result.0, 0, "{}", result.2);
    assert_eq!(result.1.len(), 1024);
    println!("PASS: timeout terminates execution; stdout retained at configured byte limit");
}

#[test]
#[ignore = "requires a running local Linux Docker daemon"]
fn live_missing_image_cannot_fall_back_to_host() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = CommandRuntime::new(
        dir.path(),
        ExecutionSettings {
            image: format!("alpine@sha256:{}", "0".repeat(64)),
            ..settings()
        },
    )
    .unwrap();
    let result = runtime.execute_command(
        "sh",
        &["-c".into(), "echo escaped > host-escape.txt".into()],
    );
    assert_ne!(result.0, 0);
    assert!(!runtime.file_exists("host-escape.txt"));
    println!("PASS: unavailable image is an execution error, never host fallback");
}
