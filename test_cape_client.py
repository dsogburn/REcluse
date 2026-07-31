import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from cape_client import (
    CapeClient,
    cape_analyst_details,
    filter_cape_baseline_noise,
    summarize_cape_report,
    validate_cape_url,
)


class CapeClientTests(unittest.TestCase):
    def test_private_endpoints_are_accepted(self):
        self.assertEqual(
            validate_cape_url("http://127.0.0.1:8090/"),
            "http://127.0.0.1:8090",
        )
        self.assertEqual(
            validate_cape_url("https://10.20.30.40"),
            "https://10.20.30.40",
        )

    def test_public_endpoint_requires_explicit_consent(self):
        with self.assertRaisesRegex(ValueError, "dynamic_allow_remote"):
            validate_cape_url("https://sandbox.example.com")
        self.assertEqual(
            validate_cape_url("https://sandbox.example.com", allow_remote=True),
            "https://sandbox.example.com",
        )

    def test_client_uses_modern_apiv2_routes(self):
        client = CapeClient(
            "http://127.0.0.1:8000",
            timeout=1,
            poll_interval=0,
        )
        submit_response = Mock()
        submit_response.raise_for_status.return_value = None
        submit_response.json.return_value = {"data": {"task_ids": [17]}}
        status_response = Mock()
        status_response.raise_for_status.return_value = None
        status_response.json.return_value = {"error": False, "data": "reported"}
        report_response = Mock()
        report_response.raise_for_status.return_value = None
        report_response.json.return_value = {"info": {"score": 8}}
        client.session.post = Mock(return_value=submit_response)
        client.session.get = Mock(side_effect=[status_response, report_response])

        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(b"MZ")
            task_id, report = client.analyze(str(sample))

        self.assertEqual(task_id, 17)
        self.assertEqual(report["info"]["score"], 8)
        self.assertEqual(
            client.session.post.call_args.args[0],
            "http://127.0.0.1:8000/apiv2/tasks/create/file/",
        )
        self.assertEqual(
            client.session.get.call_args_list[0].args[0],
            "http://127.0.0.1:8000/apiv2/tasks/status/17/",
        )
        self.assertEqual(
            client.session.get.call_args_list[1].args[0],
            "http://127.0.0.1:8000/apiv2/tasks/get/report/17/json/",
        )

    def test_status_falls_back_to_task_view(self):
        client = CapeClient("http://127.0.0.1:8000")
        disabled_response = Mock()
        disabled_response.raise_for_status.return_value = None
        disabled_response.json.return_value = {
            "error": True,
            "error_value": "Task status API is disabled",
        }
        view_response = Mock()
        view_response.raise_for_status.return_value = None
        view_response.json.return_value = {"data": {"status": "running"}}
        client.session.get = Mock(side_effect=[disabled_response, view_response])

        self.assertEqual(client.task_status(23), "running")
        self.assertEqual(
            client.session.get.call_args_list[1].args[0],
            "http://127.0.0.1:8000/apiv2/tasks/view/23/",
        )

    def test_still_analyzing_api_error_is_pending(self):
        client = CapeClient("http://127.0.0.1:8000")
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "error": True,
            "error_value": "Task is still being analyzed",
        }
        client.session.get = Mock(side_effect=[response, response])

        self.assertEqual(client.task_status(24), "processing")

    def test_report_endpoint_race_is_retried(self):
        client = CapeClient(
            "http://127.0.0.1:8000",
            timeout=1,
            poll_interval=0,
        )
        reported = Mock()
        reported.raise_for_status.return_value = None
        reported.json.return_value = {"error": False, "data": "reported"}
        pending_report = Mock()
        pending_report.raise_for_status.return_value = None
        pending_report.json.return_value = {
            "error": True,
            "error_value": "Task is still being analyzed",
        }
        ready_report = Mock()
        ready_report.raise_for_status.return_value = None
        ready_report.json.return_value = {"info": {"score": 1}}
        client.session.get = Mock(side_effect=[
            reported,
            pending_report,
            reported,
            ready_report,
        ])

        self.assertEqual(client.wait_for_report(25)["info"]["score"], 1)

    def test_apiv2_suffix_is_not_duplicated(self):
        client = CapeClient("http://127.0.0.1:8000/apiv2")
        self.assertEqual(client.api_url, "http://127.0.0.1:8000/apiv2")

    def test_api_errors_are_exposed(self):
        client = CapeClient("http://127.0.0.1:8000")
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "error": True,
            "error_value": "File-create API is disabled",
        }
        with self.assertRaisesRegex(RuntimeError, "File-create API is disabled"):
            client._json(response)

    def test_report_summary_extracts_behavioral_evidence(self):
        report = {
            "info": {"score": 9.5},
            "target": {"file": {"sha256": "abc"}},
            "signatures": [{"name": "persistence", "severity": 3}],
            "behavior": {
                "processes": [{
                    "process_id": 42,
                    "parent_id": 1,
                    "process_name": "sample.exe",
                    "command_line": "sample.exe -x",
                }],
                "summary": {
                    "write_keys": ["HKCU\\Software\\Example"],
                    "write_files": ["C:\\Temp\\payload.dll"],
                    "mutexes": ["example-mutex"],
                },
            },
            "network": {
                "domains": [{"domain": "example.test"}],
                "hosts": ["192.0.2.10"],
            },
        }
        summary = summarize_cape_report(report, 7)
        self.assertEqual(summary["task_id"], 7)
        self.assertEqual(summary["score"], 9.5)
        self.assertEqual(summary["processes"][0]["pid"], 42)
        self.assertEqual(summary["registry"], ["HKCU\\Software\\Example"])
        self.assertEqual(summary["domains"][0]["domain"], "example.test")

    def test_baseline_network_noise_is_excluded_but_auditable(self):
        summary = filter_cape_baseline_noise({
            "domains": [
                {"domain": "cdn.onenote.net", "ip": "23.217.42.55"},
                {"domain": "evil.example", "ip": "192.0.2.50"},
            ],
            "dns": [{"request": "cdn.onenote.net"}],
            "hosts": [
                {"ip": "40.90.64.229"},
                {"ip": "192.0.2.50"},
            ],
            "signatures": [{
                "name": "stealth_network",
                "data": [
                    {"ip": "40.90.64.229"},
                    {"domain": "evil.example"},
                ],
            }],
            "analyst_details": {"anomalies": [
                {"signature": "stealth_network", "detail": {"ip": "40.90.64.229"}},
                {"signature": "contains_pe_overlay", "detail": {"size": 10}},
            ]},
        })
        self.assertEqual(summary["domains"], [
            {"domain": "evil.example", "ip": "192.0.2.50"},
        ])
        self.assertEqual(summary["hosts"], [{"ip": "192.0.2.50"}])
        self.assertEqual(
            summary["signatures"][0]["data"],
            [{"domain": "evil.example"}],
        )
        self.assertGreater(summary["baseline_noise"]["filtered"], 0)
        self.assertEqual(
            summary["analyst_details"]["anomalies"][0]["signature"],
            "contains_pe_overlay",
        )

    def test_report_summary_does_not_embed_large_static_target_details(self):
        report = {
            "target": {
                "name": "sample.exe",
                "sha256": "abc",
                "pe": {"strings": ["x" * 200_000]},
            },
            "behavior": {},
            "network": {},
        }
        summary = summarize_cape_report(report, 9)
        encoded = json.dumps(summary)
        self.assertLess(len(encoded), 120_000)
        self.assertEqual(summary["target"]["name"], "sample.exe")
        self.assertNotIn("pe", summary["target"])

    def test_analyst_details_include_addresses_entropy_yara_and_next_steps(self):
        details = cape_analyst_details({
            "target": {"file": {
                "pe": {
                    "imagebase": "0x00400000",
                    "entrypoint": "0x00001000",
                    "sections": [{
                        "name": ".text",
                        "raw_address": "0x00000400",
                        "virtual_address": "0x00001000",
                        "virtual_size": "0x100",
                        "size_of_data": "0x100",
                        "characteristics": "IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE",
                        "entropy": "7.80",
                    }],
                },
                "yara": [{
                    "name": "example_rule",
                    "meta": {"description": "Example", "author": "Analyst"},
                    "strings": ["{ 90 90 }"],
                    "addresses": {"hit": 512},
                }],
            }},
            "signatures": [{
                "name": "pe_writable_executable_section",
                "severity": 2,
                "confidence": 70,
                "data": [{"section": ".text"}],
            }],
        })
        section = details["pe"]["sections"][0]
        self.assertEqual(section["virtual_address"], "0x00401000")
        self.assertTrue(section["high_entropy"])
        self.assertTrue(section["writable"])
        self.assertTrue(section["executable"])
        self.assertEqual(
            details["yara_matches"][0]["matches"][0]["offset_hex"],
            "0x00000200",
        )
        self.assertTrue(details["prioritized_pivots"])
        self.assertTrue(details["recommended_next_steps"])
        self.assertIn("0x00401000", details["recommended_next_steps"][0])
        self.assertFalse(any(
            step.startswith("Validate provenance")
            for step in details["recommended_next_steps"]
        ))

    def test_analyst_next_steps_include_observed_runtime_pivots(self):
        details = cape_analyst_details({
            "target": {"file": {"pe": {
                "imagebase": "0x00400000",
                "entrypoint": "0x00002000",
                "imports": {
                    "KERNEL32.dll": {
                        "dll": "KERNEL32.dll",
                        "imports": [{
                            "name": "VirtualProtect",
                            "address": "0x00405010",
                        }],
                    },
                },
            }}},
            "behavior": {
                "summary": {
                    "write_keys": [
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
                    ],
                    "write_files": ["C:\\Users\\analyst\\AppData\\Local\\stage2.exe"],
                    "mutexes": ["Global\\sample-mutex"],
                },
                "processes": [{
                    "process_id": 202,
                    "parent_id": 101,
                    "process_name": "rundll32.exe",
                    "command_line": "rundll32.exe stage2.dll,Start",
                }],
            },
            "network": {"http": [{
                "method": "GET",
                "url": "https://example.test/payload.bin",
                "status": 200,
            }]},
            "dropped": [{
                "path": "C:\\Users\\analyst\\AppData\\Local\\stage2.exe",
                "sha256": "a" * 64,
                "type": "PE32 executable",
            }],
        })

        steps = "\n".join(details["recommended_next_steps"])
        self.assertIn("VirtualProtect at 0x00405010", steps)
        self.assertIn("CurrentVersion\\Run\\Updater", steps)
        self.assertIn("stage2.exe", steps)
        self.assertIn("https://example.test/payload.bin", steps)
        self.assertIn("rundll32.exe stage2.dll,Start", steps)
        self.assertIn("Global\\sample-mutex", steps)
        self.assertEqual(
            details["runtime_pivots"]["endpoints"][0]["status"], 200
        )


if __name__ == "__main__":
    unittest.main()
