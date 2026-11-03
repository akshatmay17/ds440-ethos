use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// An intentional filesystem policy denial, distinct from an I/O failure.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct FileBoundaryViolation(pub String);

macro_rules! require_file_boundary {
    ($condition:expr, $message:expr) => {
        if !$condition { return Err(FileBoundaryViolation($message.to_owned()).into()); }
    };
}

/// Reject aliases at the filesystem boundary rather than guessing their target
/// from the spelling provided to a tool. Multiple names must not bypass policy.
fn check_file_identity(path:&Path)->anyhow::Result<()> {
    let metadata=fs::symlink_metadata(path)?;
    require_file_boundary!(!metadata.file_type().is_symlink(),"Symbolic links are not supported by agent file tools");
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt,io::AsRawHandle};
        require_file_boundary!(metadata.file_attributes() & 0x400 == 0,"Reparse points are not supported by agent file tools");
        if metadata.is_file() {
            let file=fs::File::open(path)?;
            let mut information=std::mem::MaybeUninit::<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION>::uninit();
            // The owned file keeps the handle valid; Windows initializes the
            // complete information structure only when the call succeeds.
            let success=unsafe {windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(file.as_raw_handle(),information.as_mut_ptr())};
            anyhow::ensure!(success!=0,"Cannot establish file identity: {}",std::io::Error::last_os_error());
            let information=unsafe {information.assume_init()};
            require_file_boundary!(information.nNumberOfLinks==1,"Hard-linked files are not supported by agent file tools");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.is_file() { require_file_boundary!(metadata.nlink()==1,"Hard-linked files are not supported by agent file tools"); }
    }
    require_file_boundary!(metadata.is_file() || metadata.is_dir(),"Special filesystem objects are not supported by agent file tools");
    Ok(())
}

pub trait SandboxRuntime: Send + Sync {
    fn validate_file_access(&self, _path: &str) -> anyhow::Result<()> { Ok(()) }
    fn execution_backend(&self) -> &'static str { "custom" }
    fn read_file(&self, rel_path: &str) -> anyhow::Result<String>;
    fn write_file(&self, rel_path: &str, content: &str) -> anyhow::Result<()>;
    fn file_exists(&self, rel_path: &str) -> bool;
    fn list_files(&self) -> Vec<String>;
    fn execute_command(&self, program: &str, args: &[String]) -> (i32, String, String);
    fn create_snapshot(&self, snapshot_id: &str) -> anyhow::Result<HashMap<String, String>>;
    fn restore_snapshot(&self, snapshot_id: &str) -> anyhow::Result<()>;
    fn root_dir(&self) -> Option<PathBuf> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct LocalIsolatedRuntime {
    root_path: PathBuf,
    snapshots_dir: PathBuf,
}

impl LocalIsolatedRuntime {
    pub fn new<P: AsRef<Path>>(root_dir: P) -> anyhow::Result<Self> {
        let root = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let snapshots = root.join(".ethos_snapshots");
        fs::create_dir_all(&snapshots)?;
        Ok(Self {
            root_path: root,
            snapshots_dir: snapshots,
        })
    }

    fn resolve_path(&self, rel_path: &str) -> anyhow::Result<PathBuf> {
        let cleaned = Path::new(rel_path);
        if cleaned.is_absolute() {
            return Err(FileBoundaryViolation(format!("Absolute paths not allowed in sandbox: {}", rel_path)).into());
        }
        let resolved = self.root_path.join(cleaned);

        // Resolve from the trusted root while rejecting linked path components,
        // including an in-root alias to an otherwise protected file.
        let mut cursor=self.root_path.canonicalize()?;
        for component in cleaned.components() {
            require_file_boundary!(matches!(component,std::path::Component::Normal(_)|std::path::Component::CurDir),"Invalid path: only ordinary relative file paths are supported by agent file tools");
            #[cfg(windows)]
            {
                let name=component.as_os_str().to_string_lossy();
                require_file_boundary!(!name.contains(':'),"Alternate data streams are not supported by agent file tools");
                let base=name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
                let device=matches!(base.as_str(),"CON"|"PRN"|"AUX"|"NUL") ||
                    ["COM","LPT"].iter().any(|prefix|base.strip_prefix(prefix).is_some_and(|n|n.len()==1 && matches!(n.as_bytes()[0],b'1'..=b'9')));
                require_file_boundary!(!device,"Windows device names are not supported by agent file tools");
            }
            cursor.push(component.as_os_str());
            match fs::symlink_metadata(&cursor) {
                Ok(_)=>check_file_identity(&cursor)?,
                Err(error) if error.kind()==std::io::ErrorKind::NotFound=>{},
                Err(error)=>return Err(error.into()),
            }
        }

        let mut current = resolved.as_path();
        let mut to_append = Vec::new();
        let canonical_resolved = loop {
            if let Ok(canon) = fs::canonicalize(current) {
                let mut full = canon;
                for comp in to_append.into_iter().rev() {
                    full.push(comp);
                }
                break full;
            }
            if let Some(parent) = current.parent() {
                if let Some(file_name) = current.file_name() {
                    to_append.push(file_name.to_owned());
                }
                current = parent;
            } else {
                return Err(FileBoundaryViolation(format!("Invalid path: {}", rel_path)).into());
            }
        };

        let canon_root = fs::canonicalize(&self.root_path)?;
        if !canonical_resolved.starts_with(&canon_root) {
            return Err(FileBoundaryViolation(format!("Path escape detected: {}", rel_path)).into());
        }
        #[cfg(windows)]
        {
            let actual=canonical_resolved.strip_prefix(&canon_root)?.to_string_lossy().replace('\\',"/").to_lowercase();
            let requested=cleaned.components().filter_map(|part|match part {
                std::path::Component::Normal(name)=>Some(name.to_string_lossy().into_owned()),_=>None
            }).collect::<Vec<_>>().join("/").to_lowercase();
            require_file_boundary!(actual==requested,"Short-name and normalized filesystem aliases are not supported by agent file tools");
        }

        if canonical_resolved.exists() { check_file_identity(&canonical_resolved)?; }

        Ok(canonical_resolved)
    }

    fn collect_files_recursive(&self, dir: &Path, rel_prefix: &str, files: &mut Vec<String>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path == self.snapshots_dir {
                    continue;
                }
                // Symlink-safe walk: use the DirEntry file type (which does
                // NOT follow links) and skip links entirely. A symlink or
                // junction planted inside the sandbox must not enumerate
                // the host tree, and fs::copy must not follow it into host
                // files during snapshotting.
                let ftype = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if ftype.is_symlink() {
                    continue;
                }
                let file_name = entry.file_name().to_string_lossy().to_string();
                if file_name == ".ethos_provenance.json" || file_name.starts_with(".ethos-provenance-") {
                    continue;
                }
                let rel = if rel_prefix.is_empty() {
                    file_name
                } else {
                    format!("{}/{}", rel_prefix, file_name)
                };

                if ftype.is_dir() {
                    self.collect_files_recursive(&path, &rel, files);
                } else if ftype.is_file() {
                    if check_file_identity(&path).is_ok() { files.push(rel.replace('\\', "/")); }
                }
            }
        }
    }

    fn validate_snapshot_files(&self,dir:&Path)->anyhow::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry=entry?;
            let path=entry.path();
            if path==self.snapshots_dir || path==self.root_path.join(".taintbox_snapshots") { continue; }
            let kind=entry.file_type()?;
            if kind.is_symlink() { continue; } // Existing snapshots do not follow or preserve symlinks.
            check_file_identity(&path)?;
            if kind.is_dir() { self.validate_snapshot_files(&path)?; }
        }
        Ok(())
    }
}

impl SandboxRuntime for LocalIsolatedRuntime {
    fn validate_file_access(&self, path: &str) -> anyhow::Result<()> { self.resolve_path(path).map(|_| ()) }
    fn execution_backend(&self) -> &'static str { "local_unconfined" }
    fn read_file(&self, rel_path: &str) -> anyhow::Result<String> {
        let path = self.resolve_path(rel_path)?;
        if !path.exists() {
            return Err(anyhow::anyhow!("File not found: {}", rel_path));
        }
        let content = fs::read_to_string(path)?;
        Ok(content)
    }

    fn write_file(&self, rel_path: &str, content: &str) -> anyhow::Result<()> {
        let path = self.resolve_path(rel_path)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
        Ok(())
    }

    fn file_exists(&self, rel_path: &str) -> bool {
        self.resolve_path(rel_path)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    fn list_files(&self) -> Vec<String> {
        let mut files = Vec::new();
        self.collect_files_recursive(&self.root_path, "", &mut files);
        files.sort();
        files
    }

    fn execute_command(&self, program: &str, args: &[String]) -> (i32, String, String) {
        let mut cmd = {
            let mut c = Command::new(program);
            c.args(args);
            c
        };
        cmd.current_dir(&self.root_path);
        // Provider credentials belong to the daemon, not to agent commands.
        // Do not implicitly add a shell on Windows or inherit the host home.
        cmd.env_clear();
        for name in ["PATH", "SystemRoot", "WINDIR", "SystemDrive", "COMSPEC", "PATHEXT", "TEMP", "TMP", "LANG", "LC_ALL"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd.env("HOME", &self.root_path).env("USERPROFILE", &self.root_path);

        match cmd.output() {
            Ok(output) => {
                let code = output.status.code().unwrap_or(1);
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                (code, stdout, stderr)
            }
            Err(e) => (1, String::new(), e.to_string()),
        }
    }

    fn create_snapshot(&self, snapshot_id: &str) -> anyhow::Result<HashMap<String, String>> {
        // Do not silently omit a rejected hard link and later call a destructive
        // rewind a complete restoration of the workspace.
        self.validate_snapshot_files(&self.root_path)?;
        let target_dir = self.snapshots_dir.join(snapshot_id);
        if target_dir.exists() {
            fs::remove_dir_all(&target_dir)?;
        }
        fs::create_dir_all(&target_dir)?;

        let mut hashes = HashMap::new();
        for rel in self.list_files() {
            let src = self.resolve_path(&rel)?;
            let bytes = fs::read(&src)?;
            let hash = hex::encode(Sha256::digest(&bytes));
            hashes.insert(rel.clone(), hash);

            let dest = target_dir.join(&rel);
            if let Some(p) = dest.parent() {
                fs::create_dir_all(p)?;
            }
            fs::copy(&src, &dest)?;
        }

        Ok(hashes)
    }

    fn restore_snapshot(&self, snapshot_id: &str) -> anyhow::Result<()> {
        let source_dir = self.snapshots_dir.join(snapshot_id);
        if !source_dir.exists() {
            return Err(anyhow::anyhow!("Snapshot not found: {}", snapshot_id));
        }

        // Destructive rewind safety guard
        let marker = self.root_path.join(".ethos_sandbox");
        let legacy_marker = self.root_path.join(".taintbox_sandbox");
        if !marker.exists() && !legacy_marker.exists() {
            return Err(anyhow::anyhow!("Destructive rewind refused: root path is not a sandbox created by ACIHarness (missing .ethos_sandbox)"));
        }

        // Clean current files (except snapshots directory and markers)
        for entry in fs::read_dir(&self.root_path)?.flatten() {
            let path = entry.path();
            if path == self.snapshots_dir
                || path == marker
                || path == legacy_marker
                || path == self.root_path.join(".taintbox_snapshots")
            {
                continue;
            }
            if path.is_dir() {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }

        // Restore snapshot files
        let mut files = Vec::new();
        self.collect_files_recursive(&source_dir, "", &mut files);
        for rel in files {
            let src = source_dir.join(&rel);
            let dest = self.resolve_path(&rel)?;
            if let Some(p) = dest.parent() {
                fs::create_dir_all(p)?;
            }
            fs::copy(src, dest)?;
        }

        Ok(())
    }

    fn root_dir(&self) -> Option<PathBuf> {
        Some(self.root_path.clone())
    }
}
