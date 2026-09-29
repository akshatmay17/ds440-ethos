use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateNode {
    pub id: String,
    pub parent_id: Option<String>,
    pub branch_name: String,
    pub snapshot_id: String,
    pub description: String,
    pub timestamp: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTree {
    branches: HashMap<String, String>, // branch_name -> head_node_id
    nodes: HashMap<String, StateNode>,
    current_branch: String,
}

impl Default for StateTree {
    fn default() -> Self {
        Self::new()
    }
}

impl StateTree {
    pub fn new() -> Self {
        let mut branches = HashMap::new();
        branches.insert("main".to_string(), String::new());
        Self {
            branches,
            nodes: HashMap::new(),
            current_branch: "main".to_string(),
        }
    }

    pub fn current_branch(&self) -> &str {
        &self.current_branch
    }

    pub fn list_branches(&self) -> Vec<String> {
        let mut b: Vec<String> = self.branches.keys().cloned().collect();
        b.sort();
        b
    }

    pub fn create_branch(&mut self, branch_name: &str) -> anyhow::Result<()> {
        if self.branches.contains_key(branch_name) {
            return Err(anyhow::anyhow!("Branch already exists: {}", branch_name));
        }

        let current_head = self
            .branches
            .get(&self.current_branch)
            .cloned()
            .unwrap_or_default();
        self.branches.insert(branch_name.to_string(), current_head);
        self.current_branch = branch_name.to_string();
        Ok(())
    }

    pub fn switch_branch(&mut self, branch_name: &str) -> anyhow::Result<()> {
        if !self.branches.contains_key(branch_name) {
            return Err(anyhow::anyhow!("Branch not found: {}", branch_name));
        }
        self.current_branch = branch_name.to_string();
        Ok(())
    }

    pub fn commit(&mut self, snapshot_id: &str, description: &str) -> anyhow::Result<StateNode> {
        let parent_id = self.branches.get(&self.current_branch).and_then(|id| {
            if id.is_empty() {
                None
            } else {
                Some(id.clone())
            }
        });

        let node_id = format!("node_{}", Uuid::new_v4().simple());
        let node = StateNode {
            id: node_id.clone(),
            parent_id,
            branch_name: self.current_branch.clone(),
            snapshot_id: snapshot_id.to_string(),
            description: description.to_string(),
            timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
        };

        self.nodes.insert(node_id.clone(), node.clone());
        self.branches.insert(self.current_branch.clone(), node_id);
        Ok(node)
    }

    pub fn get_branch_history(&self, branch_name: &str) -> Vec<StateNode> {
        let mut history = Vec::new();
        let head_id = match self.branches.get(branch_name) {
            Some(id) if !id.is_empty() => id.clone(),
            _ => return history,
        };

        let mut curr = Some(head_id);
        while let Some(id) = curr {
            if let Some(node) = self.nodes.get(&id) {
                history.push(node.clone());
                curr = node.parent_id.clone();
            } else {
                break;
            }
        }

        history.reverse();
        history
    }
}
