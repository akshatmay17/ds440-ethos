//! Google gVisor (runsc) user-space kernel sandbox runtime.
//! Provides application-kernel hardware-grade syscall interception on Linux/WSL2
//! with transparent fallback to LocalIsolatedRuntime on Windows and macOS.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::runtime::base::{LocalIsolatedRuntime, SandboxRuntime};

#[derive(Debug, Clone)]
pub struct GVisorRuntime {
    inner: LocalIsolatedRuntime,
    runsc_bin: Option<PathBuf>,
}

impl GVisorRuntime {
    pub fn new<P: AsRef<Path>>(root_dir: P) -> anyhow::Result<Self> {
        let inner = LocalIsolatedRuntime::new(root_dir)?;
        let runsc_bin = Self::detect_runsc();
        Ok(Self { inner, runsc_bin })
    }

    pub fn is_gvisor_available(&self) -> bool {
        self.runsc_bin.is_some()
    }

    pub fn runsc_path(&self) -> Option<&Path> {
        self.runsc_bin.as_deref()
    }

    fn detect_runsc() -> Option<PathBuf> {
        // Probe system PATH for native runsc
        if let Ok(output) = Command::new("runsc").arg("--version").output() {
            if output.status.success() {
                return Some(PathBuf::from("runsc"));
            }
        }

        // On Windows, probe if runsc is available within WSL2
        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = Command::new("wsl.exe").args(["which", "runsc"]).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Some(PathBuf::from("wsl:runsc"));
                    }
                }
            }
        }

        None
    }
}

impl SandboxRuntime for GVisorRuntime {
    fn read_file(&self, rel_path: &str) -> anyhow::Result<String> {
        self.inner.read_file(rel_path)
    }

    fn write_file(&self, rel_path: &str, content: &str) -> anyhow::Result<()> {
        self.inner.write_file(rel_path, content)
    }

    fn file_exists(&self, rel_path: &str) -> bool {
        self.inner.file_exists(rel_path)
    }

    fn list_files(&self) -> Vec<String> {
        self.inner.list_files()
    }

    fn execute_command(&self, program: &str, args: &[String]) -> (i32, String, String) {
        if let Some(runsc) = &self.runsc_bin {
            if runsc.to_string_lossy() == "wsl:runsc" {
                // Execute via WSL2 runsc
                let mut cmd = Command::new("wsl.exe");
                cmd.arg("runsc").arg("do");
                if let Some(root) = self.inner.root_dir() {
                    let root_str = root.to_string_lossy();
                    if root_str.len() >= 2 && root_str.chars().nth(1) == Some(':') {
                        let drive = root_str.chars().next().unwrap().to_ascii_lowercase();
                        let rest = root_str[2..].replace('\\', "/");
                        cmd.arg(format!("/mnt/{}{}", drive, rest));
                    } else {
                        cmd.arg(".");
                    }
                } else {
                    cmd.arg(".");
                }
                cmd.arg(program).args(args);
                if let Ok(out) = cmd.output() {
                    let code = out.status.code().unwrap_or(1);
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    return (code, stdout, stderr);
                }
            } else {
                // Native Linux runsc
                let mut cmd = Command::new(runsc);
                cmd.arg("do");
                if let Some(root) = self.inner.root_dir() {
                    cmd.arg(root);
                } else {
                    cmd.arg(".");
                }
                cmd.arg(program).args(args);
                if let Ok(out) = cmd.output() {
                    let code = out.status.code().unwrap_or(1);
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    return (code, stdout, stderr);
                }
            }
        }

        // Default isolated execution
        self.inner.execute_command(program, args)
    }

    fn create_snapshot(&self, snapshot_id: &str) -> anyhow::Result<HashMap<String, String>> {
        self.inner.create_snapshot(snapshot_id)
    }

    fn restore_snapshot(&self, snapshot_id: &str) -> anyhow::Result<()> {
        self.inner.restore_snapshot(snapshot_id)
    }

    fn root_dir(&self) -> Option<PathBuf> {
        self.inner.root_dir()
    }
}
