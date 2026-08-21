import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from virustotal_client import VirusTotalClient, summarize_virustotal


class VirusTotalClientTests(unittest.TestCase):
    def _sample(self, directory):
        sample = Path(directory) / "sample.bin"
        sample.write_bytes(b"suspicious")
        return sample

    def test_hash_lookup_does_not_upload_known_sample(self):
        session = Mock()
        response = Mock(status_code=200)
        response.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 4}}}
        }
        response.raise_for_status.return_value = None
        session.request.return_value = response
        session.headers = {}

        with tempfile.TemporaryDirectory() as directory:
            result = VirusTotalClient("key", session=session).enrich(
                self._sample(directory)
            )

        self.assertEqual(result["status"], "found")
        self.assertFalse(result["uploaded"])
        session.request.assert_called_once()
        self.assertEqual(session.request.call_args.args[0], "GET")

    def test_unknown_sample_is_not_uploaded_without_opt_in(self):
        session = Mock()
        response = Mock(status_code=404)
        session.request.return_value = response
        session.headers = {}

        with tempfile.TemporaryDirectory() as directory:
            result = VirusTotalClient("key", session=session).enrich(
                self._sample(directory)
            )

        self.assertEqual(result["status"], "not_found")
        self.assertFalse(result["uploaded"])
        session.request.assert_called_once()

    def test_upload_requires_separate_disclosure_consent(self):
        session = Mock()
        response = Mock(status_code=404)
        session.request.return_value = response
        session.headers = {}

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "disclosure"):
                VirusTotalClient("key", session=session).enrich(
                    self._sample(directory),
                    upload_missing=True,
                    allow_upload=False,
                )

    def test_opted_in_upload_polls_and_returns_file_report(self):
        session = Mock()
        session.headers = {}
        missing = Mock(status_code=404)
        upload = Mock(status_code=200)
        upload.raise_for_status.return_value = None
        upload.json.return_value = {"data": {"id": "analysis-1"}}
        completed = Mock(status_code=200)
        completed.raise_for_status.return_value = None
        completed.json.return_value = {
            "data": {"attributes": {"status": "completed"}}
        }
        report = Mock(status_code=200)
        report.raise_for_status.return_value = None
        report.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 2}}}
        }
        session.request.side_effect = [missing, upload, completed, report]

        with tempfile.TemporaryDirectory() as directory:
            result = VirusTotalClient(
                "key", session=session, poll_interval=1
            ).enrich(
                self._sample(directory),
                upload_missing=True,
                allow_upload=True,
            )

        self.assertEqual(result["status"], "uploaded")
        self.assertEqual(result["analysis_id"], "analysis-1")
        self.assertTrue(result["uploaded"])
        self.assertEqual(
            [call.args[0] for call in session.request.call_args_list],
            ["GET", "POST", "GET", "GET"],
        )

    def test_summary_is_bounded(self):
        summary = summarize_virustotal({
            "status": "found",
            "sha256": "a" * 64,
            "report": {
                "data": {
                    "attributes": {
                        "names": [str(index) for index in range(100)],
                        "tags": [str(index) for index in range(100)],
                        "crowdsourced_yara_results": [
                            {"rule_name": str(index)} for index in range(100)
                        ],
                    }
                }
            },
        })
        self.assertEqual(len(summary["names"]), 30)
        self.assertEqual(len(summary["tags"]), 50)
        self.assertEqual(len(summary["crowdsourced_yara_results"]), 20)


if __name__ == "__main__":
    unittest.main()
