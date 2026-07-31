import unittest
from unittest.mock import Mock

from online_enrichment import AbuseChClient, UnpacMeClient


class OnlineEnrichmentTests(unittest.TestCase):
    def test_abuse_ch_runs_three_hash_only_queries(self):
        session = Mock()
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"query_status": "ok"}
        session.post.return_value = response

        result = AbuseChClient("key", session=session).enrich_hash("a" * 64)

        self.assertEqual(session.post.call_count, 3)
        self.assertEqual(set(result["providers"]), {
            "malwarebazaar", "threatfox", "urlhaus"
        })
        for call in session.post.call_args_list:
            self.assertNotIn("files", call.kwargs)

    def test_unpacme_marks_private_upload_and_polls_results(self):
        session = Mock()
        submitted = Mock()
        submitted.raise_for_status.return_value = None
        submitted.json.return_value = {"id": "unpack-1"}
        complete = Mock()
        complete.raise_for_status.return_value = None
        complete.json.return_value = {"status": "complete"}
        result_response = Mock()
        result_response.raise_for_status.return_value = None
        result_response.json.return_value = {"sha256": "a" * 64}
        session.post.return_value = submitted
        session.get.side_effect = [complete, result_response]

        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(b"MZ")
            result = UnpacMeClient("key", session=session).analyze(sample)

        self.assertTrue(result["private"])
        self.assertEqual(result["id"], "unpack-1")
        self.assertEqual(session.post.call_args.kwargs["params"]["private"], "true")


if __name__ == "__main__":
    unittest.main()
