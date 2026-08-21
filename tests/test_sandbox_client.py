import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from sandbox_client import (
    AnyRunClient,
    JoeSandboxClient,
    MultiSandboxClient,
    TriageClient,
    create_sandbox_client,
    summarize_sandbox_report,
    validate_provider,
    validate_providers,
)


class SandboxClientTests(unittest.TestCase):
    def test_multiple_provider_selection_is_deduplicated(self):
        self.assertEqual(
            validate_providers("cape,anyrun,cape"),
            ["cape", "anyrun"],
        )

    def test_multi_sandbox_retains_success_when_one_provider_fails(self):
        cape = Mock()
        cape.analyze.return_value = (17, {"info": {"score": 2}})
        anyrun = Mock()
        anyrun.analyze.side_effect = RuntimeError("quota exhausted")

        task_ids, report = MultiSandboxClient({
            "cape": cape,
            "anyrun": anyrun,
        }).analyze("sample.exe")

        self.assertEqual(task_ids, {"cape": 17})
        self.assertEqual(report["providers"]["cape"]["status"], "complete")
        self.assertEqual(report["providers"]["anyrun"]["status"], "failed")
        self.assertIn("quota exhausted", report["providers"]["anyrun"]["error"])

    def test_provider_validation_and_remote_consent(self):
        self.assertEqual(validate_provider(" ANYRUN "), "anyrun")
        with self.assertRaisesRegex(ValueError, "Unknown"):
            validate_provider("unknown")
        with self.assertRaisesRegex(ValueError, "remote disclosure"):
            create_sandbox_client(
                "anyrun",
                url="",
                api_key="secret",
                timeout=60,
                poll_interval=1,
                allow_remote=False,
            )

    def test_anyrun_uses_official_sdk_and_normalizes_key(self):
        connector = MagicMock()
        connector.run_file_analysis.return_value = "task-123"
        connector.get_task_status.return_value = iter([{"status": "running"}])
        connector.get_analysis_report.return_value = {"verdict": "malicious"}
        factory = Mock()
        factory.windows.return_value = connector
        connectors_module = types.ModuleType("anyrun.connectors")
        connectors_module.SandboxConnector = factory
        anyrun_module = types.ModuleType("anyrun")

        with patch.dict(
            sys.modules,
            {"anyrun": anyrun_module, "anyrun.connectors": connectors_module},
        ), tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(b"MZ")
            task_id, report = AnyRunClient("abc").analyze(str(sample))

        self.assertEqual(task_id, "task-123")
        self.assertEqual(report["verdict"], "malicious")
        factory.windows.assert_called_once_with("API-Key abc", timeout=600)
        connector.run_file_analysis.assert_called_once_with(filepath=str(sample))

    def test_joe_submission_polling_and_report_download(self):
        joe = Mock()
        joe.submit_sample.return_value = {"submission_id": 41}
        joe.submission_info.return_value = {
            "status": "accepted",
            "analyses": [{"webid": 99}],
        }
        joe.analysis_info.return_value = {"status": "finished"}
        joe.analysis_download.return_value = ("report.json", b'{"score": 8}')
        jbx_module = types.ModuleType("jbxapi")
        jbx_module.JoeSandbox = Mock(return_value=joe)

        with patch.dict(
            sys.modules,
            {"jbxapi": jbx_module},
        ), tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(b"MZ")
            task_id, report = JoeSandboxClient(
                "abc", poll_interval=0
            ).analyze(str(sample))

        self.assertEqual(task_id, "99")
        self.assertEqual(report["score"], 8)
        joe.analysis_download.assert_called_once_with(99, "jsonfixed")

    def test_hosted_summary_is_bounded_and_identifies_provider(self):
        summary = summarize_sandbox_report(
            {"verdict": "malicious", "details": "x" * 130_000},
            "task",
            "anyrun",
        )
        self.assertEqual(summary["backend"], "ANY.RUN")
        self.assertTrue(summary["truncated"])
        self.assertLess(len(summary["report"]), 120_000)

    def test_triage_finds_hash_without_uploading_bytes(self):
        session = Mock()
        search = Mock()
        search.raise_for_status.return_value = None
        search.json.return_value = {"data": [{"id": "sample-1"}]}
        summary_response = Mock()
        summary_response.raise_for_status.return_value = None
        summary_response.json.return_value = {"score": 8}
        session.get.side_effect = [search, summary_response]

        with patch("sandbox_client.requests.Session", return_value=session), \
                tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(b"MZ")
            task_id, report = TriageClient("key").analyze(str(sample))

        self.assertEqual(task_id, "sample-1")
        self.assertEqual(report["source"], "hash_lookup")
        session.post.assert_not_called()

    def test_triage_unknown_hash_requires_explicit_upload(self):
        session = Mock()
        search = Mock()
        search.raise_for_status.return_value = None
        search.json.return_value = {"data": []}
        session.get.return_value = search

        with patch("sandbox_client.requests.Session", return_value=session), \
                tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "novel.exe"
            sample.write_bytes(b"MZ")
            task_id, report = TriageClient("key").analyze(str(sample))

        self.assertEqual(task_id, "not-found")
        self.assertEqual(report["status"], "not_found")
        session.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
