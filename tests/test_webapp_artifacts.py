import json
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

import webapp


class _SampleInputParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.attributes = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("id") == "sample-input":
            self.attributes = attributes


class WebArtifactTests(unittest.TestCase):
    def test_partial_package_exit_is_completed_with_warnings(self):
        self.assertEqual(webapp.job_status_from_return_code(0), "completed")
        self.assertEqual(
            webapp.job_status_from_return_code(2), "completed_with_warnings"
        )
        self.assertEqual(webapp.job_status_from_return_code(1), "failed")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.job_id = "viewer-test"
        with webapp.jobs_lock:
            webapp.jobs[self.job_id] = {"report_dir": self.root}

    def tearDown(self):
        with webapp.jobs_lock:
            webapp.jobs.pop(self.job_id, None)
        self.directory.cleanup()

    def test_report_content_is_inline_and_download_is_explicit(self):
        report = self.root / "sample.report.json"
        report.write_text(json.dumps({"triage": {"verdict": "unknown"}}))

        inline = webapp.view_artifact(self.job_id, "sample.report.json")
        self.assertEqual(inline.status_code, 200)
        self.assertEqual(Path(inline.path), report)
        self.assertNotIn("content-disposition", inline.headers)

        viewer = webapp.download_artifact(self.job_id, "sample.report.json")
        self.assertEqual(viewer.status_code, 303)
        self.assertIn("/report.html?", viewer.headers["location"])

        download = webapp.download_artifact(
            self.job_id,
            "sample.report.json",
            download=True,
        )
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers["content-disposition"])

    def test_report_viewer_page_is_served(self):
        source = (webapp.STATIC_DIR / "report.html").read_text()
        script = (webapp.STATIC_DIR / "report.js").read_text()
        self.assertIn("Download report", source)
        self.assertIn('id="report-back"', source)
        self.assertIn('/?job=${encodeURIComponent(jobId)}', script)
        self.assertIn("Sections and entropy", source)
        self.assertIn("Recommended next steps", source)

    def test_help_page_documents_console_api_and_upload_consent(self):
        source = (webapp.STATIC_DIR / "help.html").read_text()
        index = (webapp.STATIC_DIR / "index.html").read_text()
        settings = (webapp.STATIC_DIR / "settings.html").read_text()

        self.assertIn("FastAPI integration", source)
        self.assertIn('href="/api/docs"', source)
        self.assertIn("/api/jobs/{job_id}", source)
        self.assertIn("upload_acknowledgement=acknowledge", source)
        self.assertIn("Hash searches should be the first pivot", source)
        self.assertIn('href="/help.html"', index)
        self.assertIn('href="/help.html"', settings)

    def test_report_archive_page_exposes_required_filters(self):
        source = (webapp.STATIC_DIR / "reports.html").read_text()
        script = (webapp.STATIC_DIR / "reports.js").read_text()
        for filter_id in (
            "filter-filename", "filter-hash", "filter-from", "filter-to",
            "filter-model", "filter-verdict",
        ):
            self.assertIn(f'id="{filter_id}"', source)
        self.assertIn("/api/reports", script)
        self.assertIn('id="archive-details"', source)
        self.assertIn('id="reports-per-page"', source)
        self.assertIn('<option value="15" selected>15</option>', source)
        self.assertIn("openAnalysisDetails", script)
        self.assertIn("return=reports", script)
        self.assertIn("reports.slice(0, limit)", script)

    def test_secondary_pages_use_consistent_analysis_navigation(self):
        expected_icon = '<circle cx="10.5" cy="10.5" r="6.5"/>'
        for page in ("settings.html", "help.html", "reports.html"):
            source = (webapp.STATIC_DIR / page).read_text()
            self.assertIn('aria-label="File Analysis"', source)
            self.assertIn(expected_icon, source)
            self.assertIn("<span>File Analysis</span>", source)

    def test_header_actions_use_consistent_icons(self):
        gear = 'M12 15.5a3.5 3.5 0 1 0 0-7'
        help_circle = '<circle cx="12" cy="12" r="9"/>'
        report_document = 'M6 3h9l3 3v15H6V3Z'
        pages = {
            name: (webapp.STATIC_DIR / name).read_text()
            for name in ("index.html", "settings.html", "help.html", "reports.html")
        }
        for name in ("index.html", "help.html", "reports.html"):
            self.assertIn(gear, pages[name])
        for name in ("index.html", "settings.html", "reports.html"):
            self.assertIn(help_circle, pages[name])
        for name in ("index.html", "settings.html", "help.html"):
            self.assertIn(report_document, pages[name])

    def test_report_catalog_filters_persisted_report_metadata(self):
        job_id = "catalog-test"
        report_dir = self.root / f"web-{job_id}"
        report_dir.mkdir()
        report_path = report_dir / "payload.report.json"
        report_path.write_text(json.dumps({
            "sample": {"member_name": "payload.exe", "sha256": "a" * 64},
            "analysis": {"status": "complete", "model": "ollama/test"},
            "triage": {"verdict": "malicious"},
        }))
        job = {
            "id": job_id, "filename": "upload.zip", "status": "completed",
            "created_at": "2026-07-20T12:00:00+00:00", "finished_at": None,
            "report_dir": report_dir, "parameters": {"model": "fallback"},
            "artifacts": [{"kind": "report", "path": report_path.name}],
        }
        with webapp.jobs_lock:
            webapp.jobs[job_id] = job
        try:
            results = webapp.search_reports(
                filename="PAYLOAD", file_hash="aaaa", date_from="2026-07-20",
                date_to="2026-07-20", model="TEST", verdict="malicious",
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["filename"], "payload.exe")
            self.assertEqual(results[0]["sha256"], "a" * 64)
        finally:
            with webapp.jobs_lock:
                webapp.jobs.pop(job_id, None)

    def test_frontend_views_json_even_when_kind_is_unknown(self):
        source = (webapp.STATIC_DIR / "app.js").read_text()
        self.assertIn("TEXT_ARTIFACT_EXTENSIONS.test(item.path)", source)
        self.assertIn("File Triage Report", source)
        self.assertIn("Analysis Agent Transcript", source)

    def test_collect_artifacts_identifies_decoded_outputs(self):
        decoded = self.root / "one.crt.decoded.xml"
        decoded.write_text("<Project />")
        (self.root / "one.crt.report.json").write_text(json.dumps({
            "sample": {"member_name": "one.crt"},
            "triage": {"verdict": "malicious"},
        }))
        job = {"report_dir": self.root, "artifacts": []}
        webapp.collect_artifacts(job)
        item = next(entry for entry in job["artifacts"] if entry["name"] == decoded.name)
        self.assertEqual(item["kind"], "decoded")
        self.assertEqual(item["member_name"], "one.crt")
        self.assertEqual(item["verdict"], "malicious")

    def test_main_form_exposes_optional_provider_selectors(self):
        source = (webapp.STATIC_DIR / "index.html").read_text()
        script = (webapp.STATIC_DIR / "app.js").read_text()
        for integration in (
            "cape", "anyrun", "joesandbox", "triage", "virustotal",
            "abusech", "unpacme",
        ):
            self.assertIn(f'id="use-{integration}"', source)
        for integration in ("anyrun", "joesandbox", "triage", "virustotal", "unpacme"):
            self.assertIn(f'id="upload-{integration}"', source)
        self.assertIn('Type <strong>acknowledge</strong>', source)
        self.assertIn('data.set("dynamic_providers"', script)
        self.assertIn('data.set("virustotal_enabled"', script)
        self.assertIn("jobs.slice(0, 7)", script)

    def test_dropped_sample_is_not_blocked_by_native_file_validation(self):
        parser = _SampleInputParser()
        parser.feed((webapp.STATIC_DIR / "index.html").read_text())

        self.assertIsNotNone(parser.attributes)
        self.assertNotIn("required", parser.attributes)

    def test_machine_facing_api_is_discoverable(self):
        schema = webapp.app.openapi()

        self.assertEqual(schema["info"]["title"], "REcluse API")
        self.assertIn("/api/health", schema["paths"])
        self.assertIn("/api/jobs", schema["paths"])
        self.assertIn("/api/reports", schema["paths"])
        self.assertIn(
            "/api/jobs/{job_id}/artifact-content/{artifact_path}",
            schema["paths"],
        )

    def test_health_reports_api_version(self):
        self.assertEqual(
            webapp.health(),
            {
                "status": "ok",
                "service": "recluse",
                "version": "1.0.0",
            },
        )

    def test_public_job_does_not_expose_virustotal_key(self):
        job = {
            "id": "vt-test",
            "filename": "sample.bin",
            "status": "queued",
            "created_at": "2026-01-01T00:00:00+00:00",
            "return_code": None,
            "report_dir": self.root,
            "log": [],
            "artifacts": [],
            "parameters": {
                "model": "test",
                "api_key": "",
                "dynamic_token": "",
                "virustotal_api_key": "secret",
            },
        }

        public = webapp.public_job(job)

        self.assertNotIn("virustotal_api_key", public["parameters"])
        self.assertTrue(
            public["parameters"]["virustotal_api_key_configured"]
        )

    def test_legacy_report_directory_is_loaded_after_restart(self):
        job_id = "legacy123456"
        report_dir = self.root / f"web-{job_id}"
        report_dir.mkdir()
        (report_dir / "payload.report.json").write_text(json.dumps({
            "sample": {"member_name": "payload.exe"},
            "analysis": {"status": "complete", "model": "test-model"},
        }))
        (report_dir / "payload.transcript.json").write_text("[]")

        with patch.object(webapp, "DEFAULT_REPORTS_DIR", self.root), patch.object(
            webapp, "JOB_INDEX", self.root / ".index.json"
        ), patch.object(
            webapp,
            "configured_defaults",
            return_value={"reports_dir": str(self.root)},
        ):
            webapp.load_persisted_jobs()

        try:
            restored = webapp.get_job(job_id)
            self.assertEqual(restored["filename"], "payload.exe")
            self.assertEqual(restored["status"], "completed")
            self.assertEqual(len(restored["artifacts"]), 2)
        finally:
            with webapp.jobs_lock:
                webapp.jobs.pop(job_id, None)

    def test_delete_job_removes_managed_report_directory(self):
        job_id = "delete123456"
        report_dir = self.root / f"web-{job_id}"
        report_dir.mkdir()
        job = {
            "id": job_id,
            "filename": "payload.exe",
            "status": "completed",
            "created_at": "2026-01-01T00:00:00+00:00",
            "return_code": 0,
            "report_dir": report_dir,
            "log": [],
            "artifacts": [],
            "parameters": {"model": "test"},
        }
        with webapp.jobs_lock:
            webapp.jobs[job_id] = job

        with patch.object(webapp, "JOB_INDEX", self.root / ".index.json"):
            webapp.delete_job(job_id)

        self.assertFalse(report_dir.exists())
        with webapp.jobs_lock:
            self.assertNotIn(job_id, webapp.jobs)


if __name__ == "__main__":
    unittest.main()
