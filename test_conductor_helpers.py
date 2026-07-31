import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from conductor import (
    add_actionable_next_steps,
    compact_archive_context,
    exception_details,
    deterministic_dynamic_report,
    decode_pem_armored_payload,
    get_routing_profile,
    mcp_result_text,
    normalize_final_report,
    prioritize_archive_targets,
    summarize_capa_output,
    summarize_floss_output,
    validate_final_report,
)


class ConductorHelperTests(unittest.TestCase):
    def test_generates_manual_decode_pivots_from_vbscript(self):
        report = add_actionable_next_steps(
            {"recommended_next_steps": []},
            "crtupdate.vbs",
            source_text=(
                'Set x = shell.Exec("certutil -decode one.crt '
                'C:\\Users\\Public\\Documents\\one.vbs")'
            ),
        )
        self.assertIn("one.crt", report["recommended_next_steps"][0])
        self.assertIn("one.vbs", report["recommended_next_steps"][0])

    def test_decodes_pem_armored_vbscript_and_routes_decoded_content(self):
        encoded = (
            "-----BEGIN CERTIFICATE-----\n"
            "RGltIHNoZWxsClNldCBzaGVsbCA9IENyZWF0ZU9iamVjdCgiV1NjcmlwdC5TaGVsbCIpCg==\n"
            "-----END CERTIFICATE-----\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "one.crt"
            source.write_text(encoded)
            decoded = decode_pem_armored_payload(str(source))
            self.assertEqual(decoded["encoding"], "PEM-armored Base64")
            self.assertEqual(decoded["detected_content"], "VBScript")
            output = Path(directory) / "decoded.vbs"
            output.write_bytes(decoded["decoded"])
            self.assertEqual(get_routing_profile(str(output))["name"], "SCRIPT")

    def test_normalizes_known_remnux_evidence_name_aliases(self):
        report = normalize_final_report({
            "evidence": [{
                "tool_call_id": "call_remnux_get_file_info",
                "claim": "PEM data was identified.",
            }],
        }, {"call_remnux_file_info"})
        self.assertEqual(
            report["evidence"][0]["tool_call_id"], "call_remnux_file_info"
        )

    def test_archive_targets_prioritize_orchestrating_scripts(self):
        self.assertEqual(
            prioritize_archive_targets(["payload.crt", "run.vbs", "library.dll"]),
            ["run.vbs", "library.dll", "payload.crt"],
        )

    def test_archive_context_retains_capabilities_and_relationship_pivots(self):
        context = compact_archive_context("run.vbs", {
            "sample": {"sha256": "a" * 64, "analysis_route": "SCRIPT"},
            "analysis": {"status": "complete"},
            "triage": {
                "verdict": "malicious", "confidence": 0.9,
                "summary": "Writes and launches payload.crt",
                "capabilities": ["writes file", "executes second stage"],
                "iocs": {"files": ["payload.crt"]},
                "recommended_next_steps": ["Decode payload.crt"],
            },
        })
        self.assertEqual(context["status"], "complete")
        self.assertIn("executes second stage", context["capabilities"])
        self.assertEqual(context["iocs"]["files"], ["payload.crt"])

    def test_mcp_result_includes_structured_content(self):
        result = SimpleNamespace(
            content=[SimpleNamespace(text="ok count=1")],
            structuredContent={"items": [{"name": "CreateFileW"}]},
        )
        text = mcp_result_text(result)
        self.assertIn("ok count=1", text)
        self.assertIn('"CreateFileW"', text)
        self.assertEqual(json.loads(text[text.index("{"):])["items"][0]["name"], "CreateFileW")

    def test_exception_details_preserves_nested_exception_group(self):
        error = ExceptionGroup("outer", [ValueError("inner detail")])
        details = exception_details(error)
        self.assertIn("ExceptionGroup", details)
        self.assertIn("ValueError: inner detail", details)

    def test_validator_rejects_object_verdict_without_crashing(self):
        errors = validate_final_report(
            {
                "verdict": {"type": "malicious"},
                "confidence": 0.5,
                "summary": "summary",
                "capabilities": [],
                "iocs": {},
                "evidence": [],
            },
            set(),
        )
        self.assertIn("invalid verdict", errors)

    def test_normalizes_common_nested_report_shape(self):
        report = normalize_final_report({
            "verdict": {"status": "suspicious", "confidence": 0.75},
            "summary": {
                "description": "Observed suspicious behavior.",
                "capabilities": ["command execution"],
            },
            "iocs": {},
            "evidence": [{
                "tool_call_id": "call_1",
                "description": "The import is present.",
            }],
        }, {"call_1"})
        self.assertEqual(report["verdict"], "suspicious")
        self.assertEqual(report["confidence"], 0.75)
        self.assertEqual(report["summary"], "Observed suspicious behavior.")
        self.assertEqual(report["capabilities"], ["command execution"])
        self.assertEqual(report["evidence"][0]["claim"], "The import is present.")
        self.assertEqual(validate_final_report(report, {"call_1"}), [])

    def test_normalizer_discards_fabricated_evidence_ids(self):
        report = normalize_final_report({
            "evidence": [
                {"tool_call_id": "call_real", "claim": "Supported"},
                {"tool_call_id": "call_invented", "claim": "Unsupported"},
            ],
        }, {"call_real"})
        self.assertEqual(
            [item["tool_call_id"] for item in report["evidence"]],
            ["call_real"],
        )

    def test_normalizes_small_model_report_operation(self):
        report = normalize_final_report({
            "op": "report",
            "arguments": {
                "summary": "Static strings were reviewed.",
                "evidence": [{
                    "tool_call_id": "/ViewStrings/invented",
                    "confidence": 0.8,
                    "capabilities": ["string analysis"],
                    "iocs": {"strings": ["example"]},
                }],
            },
        }, {"call_preflight_strings"})
        self.assertEqual(report["verdict"], "unknown")
        self.assertEqual(report["confidence"], 0.8)
        self.assertEqual(
            report["evidence"][0]["tool_call_id"],
            "call_preflight_strings",
        )
        self.assertEqual(
            validate_final_report(report, {"call_preflight_strings"}),
            [],
        )

    def test_preserves_opaque_evidence_alias_and_moderates_static_only_cape(self):
        report = normalize_final_report({
            "verdict": {"type": "malicious"},
            "confidence": 0.95,
            "summary": "Unsupported malicious conclusion.",
            "capabilities": ["Packed data"],
            "iocs": {"file_hashes": {"sha256": "abc"}},
            "evidence": [{
                "opaque_tool_call_id": "call_dynamic_sandbox",
                "function_name": "Dynamic Sandbox Report",
            }],
        }, {"call_dynamic_sandbox"}, {
            "signatures": [{"name": "packer_entropy"}],
            "processes": [],
            "domains": [],
            "files_written": [],
        })
        self.assertEqual(report["verdict"], "suspicious")
        self.assertEqual(report["confidence"], 0.7)
        self.assertEqual(
            report["evidence"][0]["tool_call_id"],
            "call_dynamic_sandbox",
        )
        self.assertIn("no process, network", report["summary"])
        self.assertEqual(
            validate_final_report(report, {"call_dynamic_sandbox"}),
            [],
        )

    def test_accepts_exact_id_alias_and_replaces_overstated_claim(self):
        report = normalize_final_report({
            "verdict": "suspicious",
            "confidence": 0.6,
            "summary": "Static anomalies require review.",
            "capabilities": [],
            "iocs": {},
            "evidence": [{
                "id": "call_preflight_strings",
                "description": "Strings prove command-and-control behavior.",
            }],
        }, {"call_preflight_strings"})
        self.assertEqual(
            report["evidence"][0]["tool_call_id"],
            "call_preflight_strings",
        )
        self.assertNotIn("command-and-control", report["evidence"][0]["claim"])
        self.assertEqual(
            validate_final_report(report, {"call_preflight_strings"}),
            [],
        )

    def test_threat_synonym_is_moderated_by_static_only_cape(self):
        report = normalize_final_report({
            "verdict": {"type": "threat"},
            "confidence": 0.95,
            "summary": "Unsupported runtime claim.",
            "capabilities": ["packed"],
            "iocs": {},
            "evidence": [{
                "tool_call_id": "call_dynamic_sandbox",
                "description": "Unsupported runtime claim.",
            }],
        }, {"call_dynamic_sandbox"}, {
            "signatures": [{"name": "packer_entropy"}],
            "processes": [],
        })
        self.assertEqual(report["verdict"], "suspicious")
        self.assertEqual(report["confidence"], 0.7)
        self.assertEqual(
            validate_final_report(report, {"call_dynamic_sandbox"}),
            [],
        )

    def test_dynamic_fallback_preserves_low_signal_findings_without_escalating(self):
        report = deterministic_dynamic_report({
            "target": {"sha256": "abc"},
            "signatures": [{"name": "packer_entropy"}],
            "processes": [],
        })
        self.assertEqual(report["verdict"], "unknown")
        self.assertEqual(report["confidence"], 0.0)
        self.assertEqual(report["iocs"]["file_hashes"]["sha256"], "abc")
        self.assertEqual(report["capabilities"], ["packer_entropy"])
        self.assertEqual(
            validate_final_report(report, {"call_dynamic_sandbox"}),
            [],
        )

    def test_floss_summary_ranks_decoded_indicators(self):
        summary = summarize_floss_output({
            "strings": {
                "static_strings": [{"string": "ordinary label"}],
                "decoded_strings": [{
                    "string": "https://example.test/payload",
                    "address": "0x401000",
                }],
            },
        })
        self.assertEqual(summary["interesting_strings"][0]["type"], "decoded")
        self.assertEqual(summary["interesting_strings"][0]["location"], "0x401000")

    def test_capa_summary_preserves_mapping_and_locations(self):
        summary = summarize_capa_output({
            "rules": {
                "create process": {
                    "meta": {
                        "name": "create process",
                        "namespace": "host-interaction/process",
                        "attack": ["Execution::Command Interpreter [T1059]"],
                    },
                    "matches": [["0x401000", {"success": True}]],
                },
            },
        })
        self.assertEqual(summary["capability_count"], 1)
        self.assertEqual(summary["capabilities"][0]["locations"], ["0x401000"])


if __name__ == "__main__":
    unittest.main()
