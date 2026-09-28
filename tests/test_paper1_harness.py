"""Unit tests for the Paper 1 ACI Capability Study Harness."""

import tempfile
import pytest
from ethos.eval.paper1_harness import (
    BenchmarkTask,
    CapabilityHarnessRunner,
    InterfaceCondition,
)


def test_interface_conditions_exist():
    conditions = list(InterfaceCondition)
    assert len(conditions) == 4
    assert InterfaceCondition.CONDITION_A_RAW_SHELL in conditions
    assert InterfaceCondition.CONDITION_B_TYPED_TOOLS in conditions
    assert InterfaceCondition.CONDITION_C_SNAPSHOT_REWIND in conditions
    assert InterfaceCondition.CONDITION_D_FULL_ACI in conditions


def test_condition_b_disallows_snapshot():
    runner = CapabilityHarnessRunner(condition=InterfaceCondition.CONDITION_B_TYPED_TOOLS)
    harness = runner.get_harness()

    with pytest.raises(PermissionError, match="Snapshot is disabled in Condition B"):
        harness.snapshot("test")


def test_condition_c_allows_snapshot_and_rewind():
    runner = CapabilityHarnessRunner(condition=InterfaceCondition.CONDITION_C_SNAPSHOT_REWIND)
    harness = runner.get_harness()

    harness.write("file.txt", "v1")
    snap = harness.snapshot("v1")

    harness.write("file.txt", "v2")
    assert harness.read("file.txt").output == "v2"

    harness.rewind(snap.snapshot_id)
    assert harness.read("file.txt").output == "v1"


def test_condition_d_surfaces_provenance_in_observation():
    runner = CapabilityHarnessRunner(condition=InterfaceCondition.CONDITION_D_FULL_ACI)
    harness = runner.get_harness()

    harness.fetch("https://external.org/data.txt", save_as="untrusted.txt", mock_content="xyz")
    obs = harness.observe()

    assert obs.active_taint_count == 1
    assert "untrusted.txt" in obs.tainted_resources
    # Condition D observation should include rich provenance context
    assert hasattr(obs, "provenance_context")
    assert "untrusted.txt" in obs.provenance_context
