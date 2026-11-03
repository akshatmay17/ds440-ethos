//! Disposable Linux command containers. Host workspace changes are never imported.
use super::base::{LocalIsolatedRuntime, SandboxRuntime};
use serde::Deserialize;
use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
static SETTINGS: std::sync::OnceLock<Result<ExecutionSettings, String>> =
    std::sync::OnceLock::new();

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionSettings {
    pub backend: String,
    pub image: String,
    pub timeout_seconds: u64,
    pub memory_mb: u32,
    pub cpus: f32,
    pub pids: u32,
    pub output_bytes: usize,
    pub oci_runtime: Option<String>,
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
    #[serde(skip)]
    pub docker_binary: Option<PathBuf>,
    #[serde(skip)]
    pub client_environment: Vec<(String, std::ffi::OsString)>,
}
impl Default for ExecutionSettings {
    fn default() -> Self {
        Self {
            backend: "disabled".into(),
            image: String::new(),
            timeout_seconds: 30,
            memory_mb: 512,
            cpus: 1.0,
            pids: 64,
            output_bytes: 65536,
            oci_runtime: None,
            source_path: None,
            docker_binary: find_docker(),
            client_environment: client_environment(),
        }
    }
}
impl ExecutionSettings {
    /// Freeze operator configuration before loading project .env files.
    pub fn configured() -> anyhow::Result<Self> {
        SETTINGS
            .get_or_init(|| Self::from_environment().map_err(|error| error.to_string()))
            .as_ref()
            .map(Clone::clone)
            .map_err(|error| anyhow::anyhow!(error.clone()))
    }
    pub fn from_environment() -> anyhow::Result<Self> {
        // Never discover security configuration in the agent-controlled cwd.
        let mut settings = if let Some(path) = std::env::var_os("ETHOS_EXEC_CONFIG") {
            let path = std::fs::canonicalize(path)?;
            let mut settings: Self = serde_json::from_slice(&std::fs::read(&path)?)?;
            settings.source_path = Some(path);
            settings
        } else {
            Self::default()
        };
        if let Ok(backend) = std::env::var("ETHOS_EXEC_BACKEND") {
            settings.backend = backend;
        }
        if let Ok(image) = std::env::var("ETHOS_EXEC_IMAGE") {
            settings.image = image;
        }
        settings.docker_binary = find_docker();
        settings.client_environment = client_environment();
        settings.validate()?;
        Ok(settings)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            ["disabled", "docker"].contains(&self.backend.as_str()),
            "Application execution backend must be disabled or docker; unconfined host execution is not available"
        );
        anyhow::ensure!(
            (1..=300).contains(&self.timeout_seconds),
            "Execution timeout must be 1..300 seconds"
        );
        anyhow::ensure!(
            (64..=16384).contains(&self.memory_mb)
                && self.cpus.is_finite()
                && (0.1..=16.0).contains(&self.cpus),
            "Invalid container resource limits"
        );
        anyhow::ensure!(
            (1..=1024).contains(&self.pids) && (1024..=1048576).contains(&self.output_bytes),
            "Invalid PID/output limits"
        );
        if self.backend == "docker" {
            let (repository, digest) = self.image.rsplit_once("@sha256:").ok_or_else(|| {
                anyhow::anyhow!(
                    "Container image must be pinned as repository@sha256:<64 hex digits>"
                )
            })?;
            anyhow::ensure!(
                !repository.is_empty()
                    && !repository.starts_with('-')
                    && repository
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "./:_-".contains(c))
                    && digest.len() == 64
                    && digest.bytes().all(|c| c.is_ascii_hexdigit()),
                "Invalid pinned container image"
            );
        }
        if let Some(runtime) = &self.oci_runtime {
            anyhow::ensure!(
                !runtime.is_empty()
                    && runtime
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-".contains(c)),
                "Invalid OCI runtime name"
            );
        }
        Ok(())
    }
}

pub struct CommandRuntime {
    inner: LocalIsolatedRuntime,
    settings: ExecutionSettings,
}
impl CommandRuntime {
    pub fn new(root: impl AsRef<Path>, settings: ExecutionSettings) -> anyhow::Result<Self> {
        settings.validate()?;
        let inner = LocalIsolatedRuntime::new(root)?;
        if settings.backend == "docker" {
            if let Some(binary) = &settings.docker_binary {
                anyhow::ensure!(
                    !binary.starts_with(inner.root_dir().unwrap().canonicalize()?),
                    "Docker client must be outside the agent workspace"
                );
            }
        }
        Ok(Self { inner, settings })
    }

    fn stage(&self) -> anyhow::Result<tempfile::TempDir> {
        let stage = tempfile::tempdir()?;
        let input = stage.path().join("files");
        std::fs::create_dir(&input)?;
        let root = self.inner.root_dir().unwrap().canonicalize()?;
        let policy = crate::taint::policy::TaintPolicyConfig::default();
        let redactor = crate::walls::redaction::SecretRedactor::collect(Some(&root), |path| {
            policy.is_path_sensitive(path)
        });
        let mut bytes = 0u64;
        for relative in self.inner.list_files() {
            let normalized = relative.replace('\\', "/").to_lowercase();
            if policy.is_path_sensitive(&relative)
                || normalized.split('/').any(|p| {
                    matches!(
                        p,
                        ".git"
                            | "target"
                            | "node_modules"
                            | ".ethos_snapshots"
                            | ".taintbox_snapshots"
                    )
                })
                || normalized.starts_with(".ethos")
                || normalized.starts_with(".taintbox")
            {
                continue;
            }
            let source = root.join(&relative);
            let metadata = std::fs::symlink_metadata(&source)?;
            if !metadata.is_file() || !source.canonicalize()?.starts_with(&root) {
                continue;
            }
            anyhow::ensure!(
                metadata.len() <= 16 * 1024 * 1024,
                "Staging file exceeds 16 MiB limit"
            );
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or_else(|| anyhow::anyhow!("Staging size overflow"))?;
            anyhow::ensure!(
                bytes <= 64 * 1024 * 1024,
                "Command workspace exceeds 64 MiB limit"
            );
            let content = std::fs::read(&source)?;
            if redactor.value_contains_secret(&serde_json::json!(String::from_utf8_lossy(&content)))
            {
                continue;
            }
            let destination = input.join(&relative);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&destination, content)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if metadata.permissions().mode() & 0o111 != 0 {
                    0o755
                } else {
                    0o644
                };
                std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(mode))?;
                let mut parent = destination.parent();
                while let Some(directory) = parent.filter(|d| d.starts_with(&input)) {
                    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))?;
                    parent = directory.parent();
                }
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o755))?;
        }
        Ok(stage)
    }

    pub fn container_arguments(
        &self,
        stage: &Path,
        name: &str,
        program: &str,
        args: &[String],
    ) -> anyhow::Result<Vec<String>> {
        anyhow::ensure!(
            !program.is_empty() && !program.starts_with('-') && !program.contains('\0'),
            "Invalid command program"
        );
        let canonical = stage.canonicalize()?.to_string_lossy().into_owned();
        // Docker Desktop expects ordinary Windows paths, not verbatim prefixes.
        let source = canonical.strip_prefix("\\\\?\\").unwrap_or(&canonical);
        anyhow::ensure!(
            !source.contains(',') && !source.contains('\n'),
            "Unsupported staging path"
        );
        let mut command = vec![
            "run".into(),
            "--rm".into(),
            "--pull=never".into(),
            "--name".into(),
            name.into(),
            "--network=none".into(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges:true".into(),
            "--user=65534:65534".into(),
            "--ipc=private".into(),
            "--pids-limit".into(),
            self.settings.pids.to_string(),
            "--memory".into(),
            format!("{}m", self.settings.memory_mb),
            "--memory-swap".into(),
            format!("{}m", self.settings.memory_mb),
            "--cpus".into(),
            self.settings.cpus.to_string(),
            "--ulimit=nofile=256:256".into(),
            "--stop-timeout=1".into(),
            "--mount".into(),
            format!("type=bind,source={source},target=/input,readonly"),
            "--tmpfs=/workspace:rw,nosuid,nodev,size=134217728,mode=1777".into(),
            "--tmpfs=/tmp:rw,nosuid,nodev,size=67108864,mode=1777".into(),
            "--env=HOME=/tmp".into(),
            "--env=TMPDIR=/tmp".into(),
            "--env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ];
        if let Some(runtime) = &self.settings.oci_runtime {
            command.extend(["--runtime".into(), runtime.clone()]);
        }
        command.extend([
            "--entrypoint=/bin/sh".into(),
            self.settings.image.clone(),
            "-c".into(),
            "cp -R /input/. /workspace/ && cd /workspace && exec \"$@\"".into(),
            "ethos-command".into(),
            program.into(),
        ]);
        command.extend_from_slice(args);
        Ok(command)
    }
}

fn find_docker() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .filter(|path| path.is_absolute())
        .map(|path| path.join(name))
        .find(|path| path.is_file())
        .and_then(|path| path.canonicalize().ok())
}

fn client_environment() -> Vec<(String, std::ffi::OsString)> {
    [
        "PATH",
        "SystemRoot",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
        "TEMP",
        "TMP",
    ]
    .into_iter()
    .filter_map(|key| std::env::var_os(key).map(|value| (key.into(), value)))
    .collect()
}

fn docker_command(settings: &ExecutionSettings) -> anyhow::Result<Command> {
    let binary = settings
        .docker_binary
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("CONFINEMENT_UNAVAILABLE: Docker client not installed"))?;
    let mut command = Command::new(binary);
    command.env_clear();
    // These configure the trusted daemon client, never the container environment.
    command.envs(settings.client_environment.iter().cloned());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    Ok(command)
}

fn drain(mut source: impl Read, limit: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let mut buffer = [0u8; 8192];
    while let Ok(count) = source.read(&mut buffer) {
        if count == 0 {
            break;
        }
        let retain = count.min(limit.saturating_sub(result.len()));
        result.extend_from_slice(&buffer[..retain]);
    }
    result
}

fn bounded(mut command: Command, seconds: u64, limit: usize) -> (i32, String, String) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return (
                126,
                String::new(),
                format!("CONFINEMENT_UNAVAILABLE: {error}"),
            )
        }
    };
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || drain(stdout, limit));
    let err = std::thread::spawn(move || drain(stderr, limit));
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code().unwrap_or(1),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break 124;
            }
        }
    };
    let output = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
    let mut errors = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
    if code == 124 {
        errors.push_str("\nCONFINEMENT_TIMEOUT: command was terminated");
    }
    (code, output, errors)
}

impl SandboxRuntime for CommandRuntime {
    fn validate_file_access(&self, path: &str) -> anyhow::Result<()> { self.inner.validate_file_access(path) }
    fn execution_backend(&self) -> &'static str {
        match self.settings.backend.as_str() {
            "docker" => "docker_disposable",
            _ => "exec_disabled",
        }
    }
    fn read_file(&self, p: &str) -> anyhow::Result<String> {
        self.inner.read_file(p)
    }
    fn write_file(&self, p: &str, c: &str) -> anyhow::Result<()> {
        self.inner.write_file(p, c)
    }
    fn file_exists(&self, p: &str) -> bool {
        self.inner.file_exists(p)
    }
    fn list_files(&self) -> Vec<String> {
        self.inner.list_files()
    }
    fn root_dir(&self) -> Option<PathBuf> {
        self.inner.root_dir()
    }
    fn create_snapshot(&self, id: &str) -> anyhow::Result<HashMap<String, String>> {
        self.inner.create_snapshot(id)
    }
    fn restore_snapshot(&self, id: &str) -> anyhow::Result<()> {
        self.inner.restore_snapshot(id)
    }
    fn execute_command(&self, program: &str, args: &[String]) -> (i32, String, String) {
        if self.settings.backend != "docker" {
            return (
                126,
                String::new(),
                "EXEC_DISABLED: configure a pinned Docker execution image; no host fallback".into(),
            );
        }
        let stage = match self.stage() {
            Ok(stage) => stage,
            Err(error) => {
                return (
                    126,
                    String::new(),
                    format!("CONFINEMENT_STAGING_FAILED: {error}"),
                )
            }
        };
        let name = format!("ethos-command-{}", uuid::Uuid::new_v4());
        let arguments =
            match self.container_arguments(&stage.path().join("files"), &name, program, args) {
                Ok(args) => args,
                Err(error) => return (126, String::new(), error.to_string()),
            };
        let mut command = match docker_command(&self.settings) {
            Ok(command) => command,
            Err(error) => return (126, String::new(), error.to_string()),
        };
        command.args(arguments);
        let result = bounded(
            command,
            self.settings.timeout_seconds,
            self.settings.output_bytes,
        );
        if result.0 == 124 {
            if let Ok(mut cleanup) = docker_command(&self.settings) {
                cleanup.args(["rm", "--force", &name]);
                let _ = bounded(cleanup, 5, 1024);
            }
        }
        result
    }
}
