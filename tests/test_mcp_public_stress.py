"""Transport failures must never become successful security checks."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mcp_public_stress import Peer, clean_env


class McpTransportTests(unittest.TestCase):
    def peer(self, program, timeout=2):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        peer = Peer([sys.executable, "-u", "-c", program], temporary.name, os.environ.copy(), timeout)
        self.addCleanup(peer.close)
        return peer

    def test_json_rpc_error_is_preserved(self):
        peer = self.peer('import json,sys\nfor line in sys.stdin:\n r=json.loads(line);print(json.dumps({"jsonrpc":"2.0","id":r["id"],"error":{"code":-32602,"message":"bad arguments"}}),flush=True)')
        self.assertEqual(peer.call("tools/call", {})["rpc_error"]["code"], -32602)

    def test_non_protocol_stdout_is_a_failure(self):
        peer = self.peer('import sys\nsys.stdin.readline();print("not JSON",flush=True)')
        with self.assertRaises(ValueError):
            peer.call("initialize", {})

    def test_wrong_response_id_does_not_satisfy_request(self):
        peer = self.peer('import sys,time\nsys.stdin.readline();print(\'{"jsonrpc":"2.0","id":999,"result":{}}\',flush=True);time.sleep(2)', timeout=0.1)
        with self.assertRaises(TimeoutError):
            peer.call("initialize", {})

    def test_parent_credentials_are_not_in_server_environment(self):
        with patch.dict(os.environ, {"API_KEY": "fixture-only", "GITHUB_TOKEN": "fixture-only", "NODE_OPTIONS": "fixture-only", "DOCKER_HOST": "fixture-only"}):
            environment = clean_env(Path("temporary-home"))
        for key in ["API_KEY", "GITHUB_TOKEN", "NODE_OPTIONS", "DOCKER_HOST"]:
            self.assertNotIn(key, environment)
        self.assertEqual(environment["HOME"], "temporary-home")


if __name__ == "__main__":
    unittest.main()
