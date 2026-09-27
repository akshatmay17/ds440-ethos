// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[derive(Default)]
struct AppState {
    sidecar_process: Arc<Mutex<Option<Child>>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WslDistroInfo {
    name: String,
    state: String,
    version: u32,
    is_default: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlatformInfo {
    os: String,
    arch: String,
    wsl_available: bool,
    daemon_url: String,
}

#[tauri::command]
fn get_platform_info() -> PlatformInfo {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let wsl_available = cfg!(windows) && is_wsl_installed();

    PlatformInfo {
        os,
        arch,
        wsl_available,
        daemon_url: "http://127.0.0.1:8000".to_string(),
    }
}

#[tauri::command]
fn list_wsl_distros() -> Vec<WslDistroInfo> {
    #[cfg(windows)]
    {
        if let Ok(output) = Command::new("wsl.exe")
            .args(["-l", "-v"])
            .output()
        {
            return parse_wsl_list_output(&output.stdout);
        }
    }
    Vec::new()
}

#[tauri::command]
fn convert_path_wsl(path: String, to_wsl: bool) -> String {
    #[cfg(windows)]
    {
        let arg = if to_wsl { "-u" } else { "-w" };
        if let Ok(output) = Command::new("wsl.exe")
            .args(["wslpath", arg, &path])
            .output()
        {
            if output.status.success() {
                if let Ok(s) = String::from_utf8(output.stdout) {
                    return s.trim().to_string();
                }
            }
        }
    }

    // Pure Rust fallback path translation
    if to_wsl {
        // C:\Users\foo -> /mnt/c/Users/foo
        if path.len() >= 2 && path.chars().nth(1) == Some(':') {
            let drive = path.chars().next().unwrap().to_ascii_lowercase();
            let rest = &path[2..].replace('\\', "/");
            return format!("/mnt/{}{}", drive, rest);
        }
    } else {
        // /mnt/c/Users/foo -> C:\Users\foo
        if path.starts_with("/mnt/") && path.len() > 6 {
            let drive = path.chars().nth(5).unwrap().to_ascii_uppercase();
            let rest = &path[6..].replace('/', "\\");
            return format!("{}:\\{}", drive, rest);
        }
    }

    path
}

fn is_wsl_installed() -> bool {
    #[cfg(windows)]
    {
        Command::new("wsl.exe")
            .args(["--status"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn parse_wsl_list_output(raw_bytes: &[u8]) -> Vec<WslDistroInfo> {
    // wsl -l -v outputs UTF-16LE
    let text = if raw_bytes.len() >= 2 && raw_bytes.len() % 2 == 0 {
        let u16_vec: Vec<u16> = raw_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16_lossy(&u16_vec)
    } else {
        String::from_utf8_lossy(raw_bytes).into_owned()
    };

    let mut distros = Vec::new();
    for line in text.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let is_default = trimmed.starts_with('*');
        let clean_line = trimmed.trim_start_matches('*').trim();
        let parts: Vec<&str> = clean_line.split_whitespace().collect();

        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let state = parts[1].to_string();
            let version = parts[2].parse::<u32>().unwrap_or(2);
            distros.push(WslDistroInfo {
                name,
                state,
                version,
                is_default,
            });
        }
    }
    distros
}

fn try_spawn_sidecar() -> Option<Child> {
    let sidecar_candidates = [
        "tbox",
        "taintbox",
        "./tbox",
        "./taintbox",
        "target/release/tbox",
        "target/release/taintbox",
        "target/debug/tbox",
        "target/debug/taintbox",
    ];

    for candidate in &sidecar_candidates {
        if let Ok(child) = Command::new(candidate)
            .args(["daemon", "--port", "8000"])
            .spawn()
        {
            return Some(child);
        }
    }

    None
}

fn main() {
    let app_state = AppState::default();

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_platform_info,
            list_wsl_distros,
            convert_path_wsl,
        ])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            {
                if let Ok(menu) = tauri::menu::Menu::default(app.handle()) {
                    let _ = app.set_menu(menu);
                }
            }

            // Check if daemon is responding at http://127.0.0.1:8000/health
            // If not, try spawning local daemon
            let state = app.state::<AppState>();
            if let Some(child) = try_spawn_sidecar() {
                *state.sidecar_process.lock().unwrap() = Some(child);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                let state = window.state::<AppState>();
                if let Ok(mut lock) = state.sidecar_process.lock() {
                    if let Some(mut child) = lock.take() {
                        let _ = child.kill();
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running TaintBox desktop application");
}
