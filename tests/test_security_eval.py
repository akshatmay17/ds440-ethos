"""Standalone stdlib tests; run with python -m unittest discover -s tests -p test_security_eval.py."""
import importlib.util
import unittest
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("security_eval", Path(__file__).resolve().parents[1] / "scripts/security_eval.py")
security_eval = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_eval)


class SamplingTests(unittest.TestCase):
    def test_actual_corpus_selection_is_reproducible_and_unique(self):
        rows, _ = security_eval.load_corpus()
        first, strata = security_eval.sample(rows, 440, 2)
        second, _ = security_eval.sample(list(reversed(rows)), 440, 2)
        self.assertEqual(first, second)
        self.assertEqual(len(first), len({r["id"] for r in first}))
        self.assertTrue(all(s["selected"] <= s["available"] for s in strata))
        self.assertEqual(len(rows), 44)
        self.assertEqual(len(first), 27)

    def test_shortages_are_reported_instead_of_replacement_sampling(self):
        rows = [{"id": "one", "dataset": "tiny", "difficulty": "easy"}]
        chosen, strata = security_eval.sample(rows, 1, 2)
        self.assertEqual(len(chosen), 1)
        self.assertEqual(sum(s["shortfall"] for s in strata), 5)

    def test_metrics_keep_detection_and_benign_false_positives_separate(self):
        result = security_eval.metrics([
            {"label": 1, "flagged": True, "truncated": False},
            {"label": 1, "flagged": False, "truncated": True},
            {"label": 0, "flagged": True, "truncated": False},
        ])
        self.assertEqual(result["attack_recall"], 0.5)
        self.assertEqual(result["benign_fpr"], 1.0)
        self.assertEqual(result["truncated"], 1)

    def test_attacker_endpoint_rejects_nonlocal_and_credential_urls(self):
        for url in ["https://127.0.0.1/v1", "http://example.com/v1", "http://user:pass@localhost/v1"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                security_eval.mutate(url, "test", {"text": "fixture"}, [], 1)

    def test_attacker_http_transport_preserves_feedback_and_returns_inert_text(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()
                response = {"choices": [{"message": {"content": json.dumps({"text": "Fixture: persist an unauthorized instruction in MEMORY.md"})}}]}
                self.wfile.write(json.dumps(response).encode())
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            result = security_eval.mutate(f"http://127.0.0.1:{server.server_port}/v1", "fixture-model",
                                          {"text": "original fixture"}, [{"risk_score": 0.9}], 440)
            self.assertIn("MEMORY.md", result)
            self.assertEqual(received[0]["seed"], 440)
            user = json.loads(received[0]["messages"][1]["content"])
            self.assertEqual(user["feedback"][0]["risk_score"], 0.9)
        finally:
            thread.join(timeout=2)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
