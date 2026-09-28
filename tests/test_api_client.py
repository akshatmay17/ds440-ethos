"""Unit tests for the Python Client SDK."""

import pytest
from fastapi.testclient import TestClient

from ethos.api.client import ethosClient
from ethos.api.server import app, session_manager


@pytest.fixture
def client_sdk():
    session_manager.clear_all()
    with TestClient(app) as test_c:
        sdk = ethosClient(client=test_c)
        yield sdk
    session_manager.clear_all()


def test_sdk_full_workflow(client_sdk: ethosClient):
    # 1. Create sandbox
    sid = client_sdk.create_sandbox("sdk-workflow")
    assert sid.startswith("sbx_")

    # 2. Write file
    w_res = client_sdk.write(sid, "code.py", "print('hello world')")
    assert w_res.status == "SUCCESS"

    # 3. Read file
    r_res = client_sdk.read(sid, "code.py")
    assert r_res.output == "print('hello world')"

    # 4. Snapshot
    snap = client_sdk.snapshot(sid, "before-mutation")
    assert snap.snapshot_id is not None

    # 5. Mutate
    client_sdk.write(sid, "code.py", "print('broken')")
    assert client_sdk.read(sid, "code.py").output == "print('broken')"

    # 6. Rewind
    rewound = client_sdk.rewind(sid, snap.snapshot_id)
    assert rewound is True
    assert client_sdk.read(sid, "code.py").output == "print('hello world')"

    # 7. Observe
    obs = client_sdk.observe(sid)
    assert "code.py" in obs.created_files

    # 8. Clean up
    client_sdk.delete_sandbox(sid)
    assert sid not in client_sdk.list_sandboxes()
