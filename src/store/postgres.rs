use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::models::{AuditEvent, SnapshotMetadata};

#[derive(Debug, Clone)]
pub struct SandboxRecord {
    pub id: String,
    pub description: String,
    pub status: String,
    pub policy_profile: String,
    pub root_path: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        let store = Self { pool };
        store.init_schema().await?;
        Ok(store)
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn init_schema(&self) -> anyhow::Result<()> {
        let ddl = include_str!("../../migrations/0001_init.sql");
        sqlx::raw_sql(ddl).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn create_sandbox(
        &self,
        id: &str,
        description: &str,
        root_path: &str,
        policy_profile: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO sandboxes (id, description, status, policy_profile, root_path)
            VALUES ($1, $2, 'active', $3, $4)
            ON CONFLICT (id) DO UPDATE SET updated_at = NOW()
            "#,
        )
        .bind(id)
        .bind(description)
        .bind(policy_profile)
        .bind(root_path)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_sandbox(&self, id: &str) -> anyhow::Result<Option<SandboxRecord>> {
        let row = sqlx::query(
            r#"
            SELECT id, description, status, policy_profile, root_path, created_at
            FROM sandboxes WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            Ok(Some(SandboxRecord {
                id: r.get("id"),
                description: r.get("description"),
                status: r.get("status"),
                policy_profile: r.get("policy_profile"),
                root_path: r.get("root_path"),
                created_at: r.get("created_at"),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_sandbox(&self, id: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM sandboxes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn save_snapshot(
        &self,
        sandbox_id: &str,
        snapshot: &SnapshotMetadata,
    ) -> anyhow::Result<()> {
        let file_hashes_json = serde_json::to_value(&snapshot.file_hashes)?;

        sqlx::query(
            r#"
            INSERT INTO snapshots (snapshot_id, sandbox_id, description, file_hashes, taint_ledger_state)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (snapshot_id) DO UPDATE 
            SET file_hashes = $4, taint_ledger_state = $5
            "#,
        )
        .bind(&snapshot.snapshot_id)
        .bind(sandbox_id)
        .bind(&snapshot.description)
        .bind(file_hashes_json)
        .bind(&snapshot.taint_ledger_state)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_snapshot(
        &self,
        snapshot_id: &str,
    ) -> anyhow::Result<Option<SnapshotMetadata>> {
        let row = sqlx::query(
            r#"
            SELECT snapshot_id, description, file_hashes, taint_ledger_state, EXTRACT(EPOCH FROM created_at) as ts
            FROM snapshots WHERE snapshot_id = $1
            "#,
        )
        .bind(snapshot_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let hashes_val: serde_json::Value = r.get("file_hashes");
            let hashes = serde_json::from_value(hashes_val).unwrap_or_default();
            let ts: f64 = r.get("ts");

            Ok(Some(SnapshotMetadata {
                snapshot_id: r.get("snapshot_id"),
                timestamp: ts,
                description: r.get("description"),
                file_hashes: hashes,
                taint_ledger_state: r.get("taint_ledger_state"),
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn record_audit_event(
        &self,
        sandbox_id: &str,
        event: &AuditEvent,
    ) -> anyhow::Result<()> {
        let uuid = Uuid::parse_str(&event.id).unwrap_or_else(|_| Uuid::new_v4());

        sqlx::query(
            r#"
            INSERT INTO audit_events (id, sandbox_id, event_type, action, caller, details)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(uuid)
        .bind(sandbox_id)
        .bind(&event.event_type)
        .bind(&event.action)
        .bind(&event.caller)
        .bind(&event.details)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn query_audit_events(
        &self,
        sandbox_id: &str,
        event_type: Option<&str>,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        let rows = if let Some(etype) = event_type {
            sqlx::query(
                r#"
                SELECT id::text, event_type, action, caller, details, EXTRACT(EPOCH FROM created_at) as ts
                FROM audit_events 
                WHERE sandbox_id = $1 AND event_type = $2
                ORDER BY created_at ASC
                "#,
            )
            .bind(sandbox_id)
            .bind(etype)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id::text, event_type, action, caller, details, EXTRACT(EPOCH FROM created_at) as ts
                FROM audit_events 
                WHERE sandbox_id = $1
                ORDER BY created_at ASC
                "#,
            )
            .bind(sandbox_id)
            .fetch_all(&self.pool)
            .await?
        };

        let mut events = Vec::new();
        for r in rows {
            events.push(AuditEvent {
                id: r.get("id"),
                timestamp: r.get("ts"),
                event_type: r.get("event_type"),
                action: r.get("action"),
                caller: r.get("caller"),
                details: r.get("details"),
            });
        }

        Ok(events)
    }

    pub async fn query_blocked_attacks(&self) -> anyhow::Result<Vec<AuditEvent>> {
        let rows = sqlx::query(
            r#"
            SELECT id::text, event_type, action, caller, details, EXTRACT(EPOCH FROM created_at) as ts
            FROM audit_events 
            WHERE event_type = 'POLICY_BLOCK'
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::new();
        for r in rows {
            events.push(AuditEvent {
                id: r.get("id"),
                timestamp: r.get("ts"),
                event_type: r.get("event_type"),
                action: r.get("action"),
                caller: r.get("caller"),
                details: r.get("details"),
            });
        }

        Ok(events)
    }
}
