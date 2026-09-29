use crate::models::AuditEvent;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub active_sandboxes: usize,
    pub total_steps: usize,
    pub active_taint_count: usize,
    pub total_declassifications: usize,
    pub wall_trips_prompt_inject: usize,
    pub wall_trips_ouroboros: usize,
    pub wall_trips_hallu_scan: usize,
    pub wall_trips_estop: usize,
    pub benchmark_solve_rate: f64,
    pub benchmark_defense_rate: f64,
    pub uptime_seconds: f64,
}

#[derive(Debug)]
struct MetricsInner {
    start_time: std::time::Instant,
    active_sandboxes: usize,
    total_steps: usize,
    active_taint_count: usize,
    total_declassifications: usize,
    wall_trips_prompt_inject: usize,
    wall_trips_ouroboros: usize,
    wall_trips_hallu_scan: usize,
    wall_trips_estop: usize,
    benchmark_solve_rate: f64,
    benchmark_defense_rate: f64,
    recent_events: Vec<AuditEvent>,
}

#[derive(Debug, Clone)]
pub struct MetricsCollector {
    inner: Arc<RwLock<MetricsInner>>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MetricsInner {
                start_time: std::time::Instant::now(),
                active_sandboxes: 0,
                total_steps: 0,
                active_taint_count: 0,
                total_declassifications: 0,
                wall_trips_prompt_inject: 0,
                wall_trips_ouroboros: 0,
                wall_trips_hallu_scan: 0,
                wall_trips_estop: 0,
                benchmark_solve_rate: 1.0,
                benchmark_defense_rate: 1.0,
                recent_events: Vec::new(),
            })),
        }
    }

    pub fn set_active_sandboxes(&self, count: usize) {
        if let Ok(mut lock) = self.inner.write() {
            lock.active_sandboxes = count;
        }
    }

    pub fn increment_steps(&self, delta: usize) {
        if let Ok(mut lock) = self.inner.write() {
            lock.total_steps += delta;
        }
    }

    pub fn update_taint_count(&self, count: usize) {
        if let Ok(mut lock) = self.inner.write() {
            lock.active_taint_count = count;
        }
    }

    pub fn record_declassification(&self) {
        if let Ok(mut lock) = self.inner.write() {
            lock.total_declassifications += 1;
        }
    }

    pub fn record_wall_trip(&self, wall_name: &str) {
        if let Ok(mut lock) = self.inner.write() {
            match wall_name.to_lowercase().as_str() {
                "promptinject" | "prompt_inject" => lock.wall_trips_prompt_inject += 1,
                "ouroboros" => lock.wall_trips_ouroboros += 1,
                "halluscan" | "hallu_scan" => lock.wall_trips_hallu_scan += 1,
                "estop" | "emergency_stop" => lock.wall_trips_estop += 1,
                _ => lock.wall_trips_prompt_inject += 1,
            }
        }
    }

    pub fn record_audit_event(&self, event: AuditEvent) {
        if let Ok(mut lock) = self.inner.write() {
            lock.recent_events.push(event);
            if lock.recent_events.len() > 100 {
                lock.recent_events.remove(0);
            }
        }
    }

    pub fn get_summary(&self) -> MetricsSummary {
        let lock = self.inner.read().unwrap();
        MetricsSummary {
            active_sandboxes: lock.active_sandboxes,
            total_steps: lock.total_steps,
            active_taint_count: lock.active_taint_count,
            total_declassifications: lock.total_declassifications,
            wall_trips_prompt_inject: lock.wall_trips_prompt_inject,
            wall_trips_ouroboros: lock.wall_trips_ouroboros,
            wall_trips_hallu_scan: lock.wall_trips_hallu_scan,
            wall_trips_estop: lock.wall_trips_estop,
            benchmark_solve_rate: lock.benchmark_solve_rate,
            benchmark_defense_rate: lock.benchmark_defense_rate,
            uptime_seconds: lock.start_time.elapsed().as_secs_f64(),
        }
    }

    pub fn get_recent_events(&self, limit: usize) -> Vec<AuditEvent> {
        let lock = self.inner.read().unwrap();
        let start = if lock.recent_events.len() > limit {
            lock.recent_events.len() - limit
        } else {
            0
        };
        lock.recent_events[start..].to_vec()
    }
}
