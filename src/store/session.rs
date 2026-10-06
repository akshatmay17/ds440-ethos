use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::aci::ACIHarness;

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Arc<Mutex<ACIHarness>>>>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_session(&self, _description: &str) -> anyhow::Result<String> {
        let sandbox_id = format!("sbx_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let harness = ACIHarness::new_with_temp_dir()?;

        let mut lock = self.sessions.write().await;
        lock.insert(sandbox_id.clone(), Arc::new(Mutex::new(harness)));
        Ok(sandbox_id)
    }

    pub async fn get_session(&self, sandbox_id: &str) -> Option<Arc<Mutex<ACIHarness>>> {
        let lock = self.sessions.read().await;
        lock.get(sandbox_id).cloned()
    }

    pub async fn list_sessions(&self) -> Vec<String> {
        let lock = self.sessions.read().await;
        let mut keys: Vec<String> = lock.keys().cloned().collect();
        keys.sort();
        keys
    }

    pub async fn terminate_session(&self, sandbox_id: &str) -> bool {
        let mut lock = self.sessions.write().await;
        if let Some(harness) = lock.remove(sandbox_id) {
            // Best-effort cleanup of the sandbox tempdir: contents (which may
            // include fetched untrusted data or user work product) must not
            // linger in %TEMP% after session termination.
            if let Ok(mutex) = harness.try_lock() {
                if let Some(root) = mutex.root_dir() {
                    let _ = std::fs::remove_dir_all(root);
                }
            }
            true
        } else {
            false
        }
    }

    pub async fn clear_all(&self) {
        let mut lock = self.sessions.write().await;
        lock.clear();
    }
}
