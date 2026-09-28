"""Unit tests for the TaintEngine."""

import pytest
from ethos.models import ProvenanceRecord, ProvenanceTag, TrustLevel
from ethos.taint.engine import TaintEngine


def test_record_and_retrieve_provenance():
    engine = TaintEngine()
    record = ProvenanceRecord(
        source_id="config.json",
        tag=ProvenanceTag.SYSTEM,
        trust_level=TrustLevel.TRUSTED,
    )
    engine.record_provenance("config.json", record)

    retrieved = engine.get_provenance("config.json")
    assert retrieved is not None
    assert retrieved.trust_level == TrustLevel.TRUSTED
    assert not engine.is_tainted("config.json")


def test_taint_propagation_inherits_worst_severity():
    engine = TaintEngine()
    clean_rec = ProvenanceRecord(
        source_id="clean.txt",
        tag=ProvenanceTag.USER,
        trust_level=TrustLevel.INTERNAL,
    )
    tainted_rec = ProvenanceRecord(
        source_id="malicious_email.txt",
        tag=ProvenanceTag.UNTRUSTED_WEB,
        trust_level=TrustLevel.UNTRUSTED,
        chain_of_custody=["https://phishing.site/email"],
    )
    engine.record_provenance("clean.txt", clean_rec)
    engine.record_provenance("malicious_email.txt", tainted_rec)

    derived = engine.propagate(["clean.txt", "malicious_email.txt"], "summary.txt")

    assert derived.trust_level == TrustLevel.UNTRUSTED
    assert "malicious_email.txt" in derived.chain_of_custody
    assert engine.is_tainted("summary.txt")


def test_policy_blocks_privileged_action_on_tainted_resource():
    engine = TaintEngine()
    tainted_rec = ProvenanceRecord(
        source_id="payload.sh",
        tag=ProvenanceTag.UNTRUSTED_WEB,
        trust_level=TrustLevel.UNTRUSTED,
    )
    engine.record_provenance("payload.sh", tainted_rec)

    # Privileged action on tainted resource -> blocked
    decision = engine.evaluate_policy("network_egress", ["payload.sh"])
    assert not decision.allowed
    assert decision.rule_id == "RULE-001"

    # Benign unprivileged action -> allowed
    benign_decision = engine.evaluate_policy("read_safe", ["payload.sh"])
    assert benign_decision.allowed


def test_snapshot_export_and_restore():
    engine = TaintEngine()
    rec = ProvenanceRecord(
        source_id="data.bin",
        tag=ProvenanceTag.EXTERNAL_FILE,
        trust_level=TrustLevel.UNTRUSTED,
    )
    engine.record_provenance("data.bin", rec)

    exported = engine.export_state()

    new_engine = TaintEngine()
    assert not new_engine.is_tainted("data.bin")

    new_engine.restore_state(exported)
    assert new_engine.is_tainted("data.bin")
    assert new_engine.get_provenance("data.bin").trust_level == TrustLevel.UNTRUSTED
