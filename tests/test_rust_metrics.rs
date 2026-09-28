use ethos::metrics::MetricsCollector;
use ethos::models::AuditEvent;

#[test]
fn test_metrics_collector_recording_and_summary() {
    let collector = MetricsCollector::new();

    collector.set_active_sandboxes(3);
    collector.increment_steps(12);
    collector.update_taint_count(4);
    collector.record_declassification();
    collector.record_wall_trip("promptinject");
    collector.record_wall_trip("ouroboros");
    collector.record_wall_trip("halluscan");
    collector.record_wall_trip("estop");

    collector.record_audit_event(AuditEvent {
        id: "evt_test_1".to_string(),
        timestamp: 1000.0,
        event_type: "WALL_TRIP".to_string(),
        action: "prompt_inject".to_string(),
        caller: "agent".to_string(),
        details: serde_json::json!({ "reason": "role_confusion" }),
    });

    let summary = collector.get_summary();
    assert_eq!(summary.active_sandboxes, 3);
    assert_eq!(summary.total_steps, 12);
    assert_eq!(summary.active_taint_count, 4);
    assert_eq!(summary.total_declassifications, 1);
    assert_eq!(summary.wall_trips_prompt_inject, 1);
    assert_eq!(summary.wall_trips_ouroboros, 1);
    assert_eq!(summary.wall_trips_hallu_scan, 1);
    assert_eq!(summary.wall_trips_estop, 1);

    let recent = collector.get_recent_events(10);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, "evt_test_1");
}
